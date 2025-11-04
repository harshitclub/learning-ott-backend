/**
 * ===========================================================
 *  Main Server Entry (index.ts)
 * ===========================================================
 * - Loads environment variables
 * - Configures Express middlewares
 * - Mounts API routes
 * - Handles errors & 404 routes
 * - Provides health check endpoint
 * - Gracefully shuts down on SIGINT / SIGTERM
 * ===========================================================
 */

import express, { Application, Request, Response } from 'express'
import dotenv from 'dotenv'
dotenv.config()

/* ---------------------------------
 * Third-party middlewares
 * --------------------------------- */
import cors from 'cors'
import helmet from 'helmet'
import cookieParser from 'cookie-parser'
import compression from 'compression'
import hpp from 'hpp'

/* ---------------------------------
 * Custom middlewares & configs
 * --------------------------------- */
import { errorHandler } from './middlewares/errorHandler'
import { morganMiddleware } from './configs/morganMiddleware'
import { logger } from './configs/logger'
import { config } from './configs/config'
import { prisma } from './configs/prisma'
import redisCache from './configs/redisCache'
import adminRoutesV1 from './routes/v1/admin.routes'
import userRoutesV1 from './routes/v1/user.routes'
import healthRoutes from './routes/v1/health.routes'

/* ---------------------------------
 * Initialize Express app
 * --------------------------------- */
const app: Application = express()

/* ---------------------------------
 * Security: small hardening flags
 * --------------------------------- */
// Disable "X-Powered-By" header to prevent tech stack disclosure
app.disable('x-powered-by')

/* ---------------------------------
 * Global Middlewares
 * --------------------------------- */
// HTTP request logging
app.use(morganMiddleware)

// Parse JSON body with size limit
app.use(express.json({ limit: '10kb' }))

// Parse URL-encoded payloads
app.use(express.urlencoded({ extended: true, limit: '10kb' }))

// Parse cookies from requests
app.use(cookieParser())

// Gzip compression for responses
app.use(compression())

// Protect against HTTP Parameter Pollution attacks
app.use(hpp())

// Secure HTTP headers via Helmet
app.use(helmet())

// CORS configuration (temporary: allow all origins in development)
app.use(cors({ origin: '*', credentials: true }))

/* ---------------------------------
 * Health Check Route
 * --------------------------------- */
app.get('/api/v1/system', healthRoutes)

/* ---------------------------------
 * API Routes
 * --------------------------------- */
app.use('/api/v1/users', userRoutesV1)
app.use('/api/v1/admins', adminRoutesV1)

/* ---------------------------------
 * 404 Route Handler
 * --------------------------------- */
/**
 * Handles all unmatched routes and responds with 404.
 */
app.use((req: Request, res: Response) => {
  res.status(404).json({
    status: 'fail',
    message: `Route ${req.originalUrl} not found`
  })
})

/* ---------------------------------
 * Global Error Handler
 * --------------------------------- */
/**
 * Centralized error-handling middleware.
 * Catches errors thrown across the app and formats the response.
 */
app.use(errorHandler)

/* ---------------------------------
 * Start Server
 * --------------------------------- */
const PORT = config.PORT || 3002
const HOST = '0.0.0.0'

const server = app.listen(PORT, HOST, () => {
  logger.info(`Server ${process.pid} running in ${config.ENV} mode`)
  logger.info(`Listening on http://${HOST}:${PORT}`)
})

/* ---------------------------------
 * Graceful Shutdown
 * --------------------------------- */
/**
 * Graceful shutdown for controlled process termination.
 * - Closes HTTP server
 * - Disconnects Prisma client
 * - Closes Redis connection
 * - Forces exit after timeout if needed
 */
const gracefulShutdown = async (signal: string) => {
  try {
    logger.warn(`${signal} received - shutting down gracefully...`)

    server.close(async () => {
      try {
        await prisma.$disconnect()
      } catch (error) {
        logger.error('Prisma disconnect error', error)
      }
      try {
        await redisCache.quit()
      } catch (error) {
        logger.error('Redis quit error', error)
      }
      logger.info('Cleanup complete. Exiting.')
      process.exit(0)
    })

    // Force exit if shutdown takes too long
    setTimeout(() => {
      logger.error(`Forcing Shutdown after timeout`)
      process.exit(0)
    }, 30_000).unref()
  } catch (error) {
    logger.error('Error during shutdown', error)
    process.exit(1)
  }
}

/* ---------------------------------
 * OS Signal Handlers
 * --------------------------------- */
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
process.on('SIGINT', () => gracefulShutdown('SIGINT'))

/* ---------------------------------
 * Crash-Safe Handlers
 * --------------------------------- */
/**
 * Handle unhandled promise rejections and uncaught exceptions.
 * The process is exited intentionally to avoid unknown corrupted states.
 */
process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Rejection at:', reason)
  process.exit(1)
})
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', err)
  process.exit(1)
})

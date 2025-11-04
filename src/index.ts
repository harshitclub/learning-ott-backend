import express, { Application } from 'express'
import dotenv from 'dotenv'
dotenv.config()

import cors from 'cors'
import helmet from 'helmet'
import cookieParser from 'cookie-parser'
import compression from 'compression'
import hpp from 'hpp'

import { errorHandler } from './middlewares/errorHandler'
import { morganMiddleware } from './configs/morganMiddleware'
import { logger } from './configs/logger'
import { config } from './configs/config'
import { prisma } from './configs/prisma'
import redisCache from './configs/redisCache'
import userRoutesV1 from './routes/v1/user.routes'
import adminRoutesV1 from './routes/v1/admin.routes'
import { notFound } from './controllers/v1/system.controllers'
import systemRoutesV1 from './routes/v1/system.routes'

const app: Application = express()

app.disable('x-powered-by')

app.use(morganMiddleware)

app.use(express.json({ limit: '10kb' }))

app.use(express.urlencoded({ extended: true, limit: '10kb' }))

app.use(cookieParser())

app.use(compression())

app.use(hpp())

app.use(helmet())

app.use(cors({ origin: '*', credentials: true }))

app.use('/api/v1/system', systemRoutesV1)

app.use('/api/v1/users', userRoutesV1)
app.use('/api/v1/admins', adminRoutesV1)

app.use(notFound)

app.use(errorHandler)

const PORT = config.PORT || 3002
const HOST = '0.0.0.0'

const server = app.listen(PORT, HOST, () => {
  logger.info(`Server ${process.pid} running in ${config.ENV} mode`)
  logger.info(`Listening on http://${HOST}:${PORT}`)
})

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

    setTimeout(() => {
      logger.error(`Forcing Shutdown after timeout`)
      process.exit(0)
    }, 30_000).unref()
  } catch (error) {
    logger.error('Error during shutdown', error)
    process.exit(1)
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
process.on('SIGINT', () => gracefulShutdown('SIGINT'))

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Rejection at:', reason)
  process.exit(1)
})
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', err)
  process.exit(1)
})

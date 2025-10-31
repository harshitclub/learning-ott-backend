import { Request, Response } from 'express'
import { AppError } from '../utils/appError'
import { logger } from '../configs/logger'

export const errorHandler = (err: AppError, _req: Request, res: Response) => {
  // Default values if error is not AppError
  const statusCode = err.statusCode || 500
  const status = err.status || 'error'

  // Log error with winston
  logger.error(`${statusCode} - ${err.message}`)

  res.status(statusCode).json({
    status,
    message: err.message || 'Something went wrong',

    // Stack only in dev mode (never in production for security)
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  })
}

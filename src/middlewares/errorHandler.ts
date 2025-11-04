import { NextFunction, Request, Response } from 'express'
import { AppError } from '../utils/appError'
import { ApiResponse, ApiError } from '../utils/apiResponse'
import { logger } from '../configs/logger'
import { Messages } from '../configs/messages'

export const errorHandler = (
  err: unknown,
  req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction
) => {
  // Normalize error to AppError
  let appErr: AppError

  if (err instanceof AppError) {
    appErr = err
  } else if (err instanceof Error) {
    // Unexpected/native Error -> wrap as 500 AppError
    appErr = new AppError(err.message || Messages.SERVER_ERROR, 500)
    appErr.isOperational = false
  } else {
    // Non-error thrown value
    appErr = new AppError('An unexpected error occurred', 500)
    appErr.isOperational = false
  }

  const statusCode = appErr.statusCode || 500

  // Only show detailed message in dev or if it's operational
  const message =
    process.env.NODE_ENV === 'development' || appErr.isOperational
      ? appErr.message
      : Messages.FAILED

  // Log structured error details
  logger.error({
    message: appErr.message,
    statusCode,
    isOperational: appErr.isOperational,
    stack: appErr.stack,
    path: req.originalUrl,
    method: req.method,
    requestId: req.headers['x-request-id']
  })

  // Optional: build errors array for client (validation-like)
  const errors: ApiError[] | null = appErr.isOperational
    ? [{ message: appErr.message }]
    : null

  // Use ApiResponse for consistent envelope
  return ApiResponse.error(req, res, statusCode, message, errors)
}

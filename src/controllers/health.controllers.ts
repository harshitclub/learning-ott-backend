import { Request, Response } from 'express'
import { logger } from '../configs/logger'
import { ApiResponse } from '../utils/apiResponse'

export async function checkHealth(req: Request, res: Response) {
  logger.info('Health check endpoint hit')
  const data = {
    status: 'OK',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  }
  return ApiResponse.success<typeof data>(
    req,
    res,
    200,
    'Server is healthy',
    data
  )
}

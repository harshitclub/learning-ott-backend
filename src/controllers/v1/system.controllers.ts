import { Request, Response } from 'express'
import { logger } from '../../configs/logger'
import { ApiResponse } from '../../utils/apiResponse'

export async function notFound(req: Request, res: Response) {
  return ApiResponse.error(
    req,
    res,
    404,
    `Route ${req.originalUrl} not found`,
    [
      {
        field: 'path',
        message: `The requested endpoint '${req.originalUrl}' does not exist on this server.`,
        code: 'ROUTE_NOT_FOUND'
      }
    ]
  )
}

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

export async function getAppInfo(req: Request, res: Response) {
  const data = {
    name: process.env.APP_NAME || 'Mujhe Padhna Hai Backend',
    version: process.env.APP_VERSION || '1.0.0',
    nodeVersion: process.version,
    environment: process.env.NODE_ENV || 'development',
    pid: process.pid,
    uptime: process.uptime()
  }

  return ApiResponse.success<typeof data>(
    req,
    res,
    200,
    'Application information retrieved',
    data
  )
}

export async function getServerTime(req: Request, res: Response) {
  const now = new Date()
  const data = {
    isoTime: now.toISOString(),
    localeTime: now.toLocaleString(),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
  }

  return ApiResponse.success<typeof data>(
    req,
    res,
    200,
    'Server time retrieved',
    data
  )
}

export async function ping(req: Request, res: Response) {
  return ApiResponse.success(req, res, 200, 'pong', { pong: true })
}

export async function getUptime(req: Request, res: Response) {
  const data = {
    uptimeSeconds: process.uptime(),
    uptimeMinutes: (process.uptime() / 60).toFixed(2),
    uptimeHours: (process.uptime() / 3600).toFixed(2)
  }

  return ApiResponse.success<typeof data>(
    req,
    res,
    200,
    'Server uptime retrieved',
    data
  )
}

export async function getMemoryUsage(req: Request, res: Response) {
  const memory = process.memoryUsage()
  const data = {
    rss: `${(memory.rss / 1024 / 1024).toFixed(2)} MB`,
    heapTotal: `${(memory.heapTotal / 1024 / 1024).toFixed(2)} MB`,
    heapUsed: `${(memory.heapUsed / 1024 / 1024).toFixed(2)} MB`,
    external: `${(memory.external / 1024 / 1024).toFixed(2)} MB`
  }

  return ApiResponse.success<typeof data>(
    req,
    res,
    200,
    'Memory usage retrieved',
    data
  )
}

import { Response, Request } from 'express'
import { v4 as uuidv4 } from 'uuid'

export interface ApiMeta {
  timestamp: string
  path: string
  method: string
  version: string
  requestId: string
}

export interface ApiError {
  field?: string
  message: string
  code?: string
}

export class ApiResponse {
  static success<T>(
    req: Request,
    res: Response,
    statusCode: number,
    message: string,
    data?: T
  ) {
    const meta: ApiMeta = {
      timestamp: new Date().toISOString(),
      path: req.originalUrl,
      method: req.method,
      version: req.baseUrl.split('/')[2] || 'v1',
      requestId: req.headers['x-request-id']?.toString() || uuidv4()
    }

    return res.status(statusCode).json({
      success: true,
      message,
      data: data ?? null,
      meta,
      errors: null
    })
  }

  static error(
    req: Request,
    res: Response,
    statusCode: number,
    message: string,
    errors?: ApiError[] | null
  ) {
    const meta: ApiMeta = {
      timestamp: new Date().toISOString(),
      path: req.originalUrl,
      method: req.method,
      version: req.baseUrl.split('/')[2] || 'v1',
      requestId: req.headers['x-request-id']?.toString() || uuidv4()
    }

    return res.status(statusCode).json({
      success: false,
      message,
      data: null,
      meta,
      errors: errors ?? null
    })
  }
}

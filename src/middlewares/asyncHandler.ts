import { NextFunction, Request, Response } from 'express'

/**
 * Wraps an async Express route/controller function and forwards any errors
 * to the global error handler automatically.
 */
export const asyncHandler = <
  Req extends Request = Request,
  Res extends Response = Response
>(
  fn: (req: Req, res: Res, next: NextFunction) => Promise<unknown>
) => {
  return (req: Req, res: Res, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next)
  }
}

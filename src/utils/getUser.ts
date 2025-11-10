import { Request } from 'express'
import { Messages } from '../configs/messages'
import { AppError } from './appError'

export function getUser(req: Request) {
  if (!req.user) {
    throw new AppError(Messages.UNAUTHORIZED, 401)
  }
  return req.user
}

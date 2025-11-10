// utils/jwt.ts
import jwt, {
  JsonWebTokenError,
  NotBeforeError,
  TokenExpiredError
} from 'jsonwebtoken'
import dotenv from 'dotenv'
import { config } from '../../configs/config'
import { logger } from '../../configs/logger'
import { Messages } from '../../configs/messages'
import { AppError } from '../appError'

dotenv.config()

const JWT_ACCESS_SECRET = config.JWT.ACCESS_SECRET

/** ---- access token ---- */
export const generateAccessToken = (payload: object): string => {
  // keep existing expiry (1 hour)
  return jwt.sign(payload, JWT_ACCESS_SECRET, {
    expiresIn: 3600 // seconds (1 hour)
  })
}
export const verifyAccessToken = (token: string) => {
  try {
    return jwt.verify(token, JWT_ACCESS_SECRET)
  } catch (err) {
    if (err instanceof TokenExpiredError) {
      logger.warn('Access token expired')
      throw new AppError(Messages.TOKEN_INVALID ?? 'Access token expired', 401)
    }

    if (err instanceof JsonWebTokenError || err instanceof NotBeforeError) {
      logger.warn('Invalid access token')
      throw new AppError(Messages.TOKEN_INVALID ?? 'Invalid access token', 401)
    }

    logger.error('Access token verification failed unexpectedly')
    throw new AppError(Messages.FAILED, 401)
  }
}

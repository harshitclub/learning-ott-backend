// utils/jwt.ts
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import { config } from '../../configs/config'
import { logger } from '../../configs/logger'

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
    logger.error('Invalid or expired access token')
    throw err
  }
}

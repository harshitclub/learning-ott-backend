// utils/jwt.ts
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import { config } from '../configs/config'
import { logger } from '../configs/logger'
import crypto from 'crypto'

dotenv.config()

const JWT_VERIFICATION_SECRET = config.JWT.VERIFICATION_SECRET
const JWT_ACCESS_SECRET = config.JWT.ACCESS_SECRET
const JWT_REFRESH_SECRET = config.JWT.REFRESH_SECRET

/** ---- verification token (email / reset) ---- */
export const generateVerificationToken = (payload: object): string => {
  return jwt.sign(payload, JWT_VERIFICATION_SECRET, {
    expiresIn: '15m'
  })
}
export const verifyVerificationToken = (token: string) => {
  try {
    return jwt.verify(token, JWT_VERIFICATION_SECRET)
  } catch (err) {
    logger.error('Invalid or expired verification token')
    throw err
  }
}

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

/** ---- refresh token (JWT) with jti support ---- */
export const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60 // 7 days

// Create refresh JWT with a unique jti and return both
export const generateRefreshTokenWithJti = (
  payload: object
): { token: string; jti: string } => {
  // Safe UUID generation across Node versions
  const jti =
    typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : crypto.randomBytes(16).toString('hex')

  const token = jwt.sign(payload, JWT_REFRESH_SECRET, {
    expiresIn: REFRESH_TOKEN_TTL_SECONDS,
    jwtid: jti
  })

  return { token, jti }
}

/**
 * verifyRefreshToken: verifies signature & expiry and returns decoded payload.
 * The decoded object will include `jti` if present.
 */
export const verifyRefreshToken = (token: string) => {
  try {
    return jwt.verify(token, JWT_REFRESH_SECRET) // returns decoded payload including jti
  } catch (err) {
    logger.error('Invalid or expired refresh token')
    throw err
  }
}

/** helper to extract jwtid (jti) without verifying signature (useful in logout) */
export const decodeRefreshToken = (token: string) => {
  try {
    return jwt.decode(token) // caution: does NOT verify signature or expiry
  } catch {
    return null
  }
}

/** helper to create sha256 hex — use this to persist jti hash in DB */
export const sha256Hex = (input: string) => {
  return crypto.createHash('sha256').update(input).digest('hex')
}

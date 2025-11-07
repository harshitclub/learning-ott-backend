import jwt from 'jsonwebtoken'
import crypto from 'crypto'
import { config } from '../../configs/config'
import { logger } from '../../configs/logger'

const JWT_REFRESH_SECRET = config.JWT.REFRESH_SECRET
const REFRESH_TOKEN_TTL_SECONDS = config.COOKIE.REFRESH_TOKEN_TTL_SECONDS

/** ---- refresh token (JWT) with jti support ---- */

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

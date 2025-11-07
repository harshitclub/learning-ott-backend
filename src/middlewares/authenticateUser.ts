import { NextFunction, Request, Response } from 'express'
import { Messages } from '../configs/messages'
import { AppError } from '../utils/appError'
import { verifyAccessToken } from '../utils/tokens/accessToken'
import { prisma } from '../configs/prisma'
import { logger } from '../configs/logger'
import { AccessTokenPayload } from '../types/accessTokenPayload'

declare module 'express-serve-static-core' {
  interface Request {
    user?: AccessTokenPayload
  }
}

/**
 * Authenticate user via Access Token (Authorization: Bearer <token>).
 * - Verifies JWT
 * - Ensures user exists and isn't disabled
 * - Attaches minimal identity to req.user
 */
export async function authenticateUser(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    // 1) Extract and validate Authorization header
    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AppError(Messages.TOKEN_REQUIRED, 401)
    }

    // Split exactly once to tolerate extra spaces
    const token = authHeader.split(' ')[1]
    if (!token) {
      throw new AppError(Messages.TOKEN_INVALID, 401)
    }

    // 2) Verify access token (signature + expiry)
    const decoded = verifyAccessToken(token)
    if (typeof decoded !== 'object' || !decoded.sub) {
      throw new AppError(Messages.TOKEN_INVALID, 401)
    }

    const userId = decoded.sub as string

    // 3) Ensure user still exists and is not disabled (revocation/lock honored)
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        role: true,
        isDisabled: true
      }
    })

    if (!user || user.isDisabled) {
      throw new AppError(Messages.ACCOUNT_LOCKED, 403)
    }

    // 4) Attach identity for downstream handlers
    // Keep email if you plan to query by email index—but also keep immutable id.
    req.user = {
      id: user.id,
      email: user.email,
      role: user.role,
      name: `${user.firstName} ${user.lastName}`
    } as AccessTokenPayload

    return next()
  } catch (error) {
    logger.warn(`Unauthorized access attempt | ip=${req.ip}`)
    return next(error)
  }
}

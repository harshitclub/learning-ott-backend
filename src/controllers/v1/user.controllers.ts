import { Request, Response } from 'express'
import { ApiResponse } from '../../utils/apiResponse'
import {
  loginUserValidator,
  signupUserValidator
} from '../../validators/user.validator'
import { AppError } from '../../utils/appError'
import { prisma } from '../../configs/prisma'
import { comparePassword, hashPassword } from '../../utils/password'
import { logger } from '../../configs/logger'
import { Messages } from '../../configs/messages'
import { maskEmail } from '../../utils/mask'
import redisCache from '../../configs/redisCache'
import {
  generateAccessToken,
  generateRefreshTokenWithJti,
  REFRESH_TOKEN_TTL_SECONDS,
  sha256Hex,
  verifyRefreshToken
} from '../../utils/jwt'
import { JwtPayload } from 'jsonwebtoken'

const REFRESH_COOKIE_NAME = 'mph_refresh_token'
const REFRESH_COOKIE_PATH = '/'
const REFRESH_COOKIE_SAMESITE: 'lax' | 'strict' | 'none' = 'lax'
const REFRESH_TTL_MS = REFRESH_TOKEN_TTL_SECONDS * 1000
const MAX_FAILED_LOGIN = 5

export async function userSignup(req: Request, res: Response) {
  const parsed = await signupUserValidator.safeParseAsync(req.body)
  if (!parsed.success) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const { firstName, lastName, email, password } = parsed.data

  const existingUser = await prisma.user.findUnique({
    where: { email }
  })

  if (existingUser) {
    throw new AppError(Messages.USER_ALREADY_EXISTS, 400)
  }

  const hashedPassword = await hashPassword(password)

  const user = await prisma.user.create({
    data: {
      firstName: firstName,
      lastName: lastName,
      passwordHash: hashedPassword,
      email: email
    },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      emailVerified: true,
      createdAt: true
    }
  })

  const safeUser = {
    id: user.id,
    email: user.email,
    name: `${user.firstName} ${user.lastName}`,
    verified: user.emailVerified
  }

  logger.info(
    `${Messages.USER_CREATED} | userId=${user.id} | email=${maskEmail(user.email)} | ip=${req.ip}`
  )
  return ApiResponse.success(req, res, 201, Messages.USER_CREATED, safeUser)
}
export async function userLogin(req: Request, res: Response) {
  // 1. Validate input
  const parsed = await loginUserValidator.safeParseAsync(req.body)
  if (!parsed.success) {
    throw new AppError(Messages.VALIDATION_FAILED, 400)
  }

  const { email, password } = parsed.data

  // 2. Fetch user (include failedLogins for lockout logic)
  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      firstName: true,
      lastName: true,
      email: true,
      emailVerified: true,
      phone: true,
      isDisabled: true,
      createdAt: true,
      profile: true,
      role: true,
      passwordHash: true,
      failedLogins: true
    }
  })

  if (!user) throw new AppError(Messages.LOGIN_FAILED, 401)
  if (user.isDisabled) throw new AppError(Messages.ACCOUNT_LOCKED, 403)

  // 3. Verify password
  const isPasswordValid = await comparePassword(password, user.passwordHash)

  // 4. If password invalid -> increment failedLogins and possibly lock account
  if (!isPasswordValid) {
    // increment and read the new failedLogins count atomically
    const updated = await prisma.user.update({
      where: { id: user.id },
      data: { failedLogins: { increment: 1 } },
      select: { failedLogins: true }
    })

    // if threshold reached, disable account
    if (updated.failedLogins >= MAX_FAILED_LOGIN) {
      await prisma.user.update({
        where: { id: user.id },
        data: { isDisabled: true }
      })
      // You may want to notify the user/admin here (email, alert) — implement if needed.
      throw new AppError(Messages.ACCOUNT_LOCKED, 403)
    }

    // still under threshold — return generic login failed
    throw new AppError(Messages.LOGIN_FAILED, 401)
  }

  // 5. Password valid -> generate tokens
  const accessToken = generateAccessToken({ sub: user.id })

  // generate refresh JWT (with jti) and compute hash for DB
  const { token: refreshJwt, jti } = generateRefreshTokenWithJti({
    sub: user.id
  })
  const refreshJtiHash = sha256Hex(jti)
  const refreshExpiresAt = new Date(Date.now() + REFRESH_TTL_MS)

  const userAgent = req.get('user-agent') ?? null
  const ip =
    req.ip ?? (req.headers['x-forwarded-for'] as string | undefined) ?? null

  // 6. Persist and revoke old tokens (single-session), reset failedLogins and update lastLoginAt
  await prisma.$transaction([
    // revoke old tokens
    prisma.userRefreshToken.updateMany({
      where: { userId: user.id, revoked: false },
      data: { revoked: true }
    }),
    // create new refresh token row
    prisma.userRefreshToken.create({
      data: {
        userId: user.id,
        tokenHash: refreshJtiHash,
        expiresAt: refreshExpiresAt,
        userAgent,
        ip
      }
    }),
    // update lastLoginAt and reset failedLogins to 0
    prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date(), failedLogins: 0 }
    })
  ])

  // set refresh token cookie (send the JWT to client)
  res.cookie(REFRESH_COOKIE_NAME, refreshJwt, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: REFRESH_COOKIE_SAMESITE,
    path: REFRESH_COOKIE_PATH,
    maxAge: REFRESH_TTL_MS
  })

  const safeUser = {
    id: user.id,
    email: user.email,
    name: `${user.firstName} ${user.lastName}`,
    verified: user.emailVerified,
    role: user.role,
    accessToken // short-lived access token
  }

  return ApiResponse.success(req, res, 200, Messages.LOGIN_SUCCESS, safeUser)
}

export async function refreshHandler(req: Request, res: Response) {
  const rawRefresh = req.cookies?.[REFRESH_COOKIE_NAME]
  if (!rawRefresh) {
    throw new AppError(Messages.REFRESH_TOKEN_MISSING, 401)
  }

  let decodedToken: string | JwtPayload

  try {
    decodedToken = verifyRefreshToken(rawRefresh)
  } catch {
    throw new AppError(Messages.REFRESH_TOKEN_INVALID, 401)
  }

  if (typeof decodedToken !== 'object' || decodedToken === null) {
    throw new AppError(Messages.REFRESH_TOKEN_INVALID, 401)
  }

  const jtiValue = decodedToken.jti
  const subValue = decodedToken.sub

  if (typeof jtiValue !== 'string' || !jtiValue.trim()) {
    throw new AppError(Messages.REFRESH_TOKEN_INVALID, 401)
  }
  if (typeof subValue !== 'string' || !subValue.trim()) {
    throw new AppError(Messages.REFRESH_TOKEN_INVALID, 401)
  }

  const jti = jtiValue
  const userId = subValue
  const tokenHash = sha256Hex(jti)

  const existing = await prisma.userRefreshToken.findUnique({
    where: { tokenHash }
  })

  if (!existing) {
    try {
      await prisma.userRefreshToken.updateMany({
        where: { userId },
        data: { revoked: true }
      })
    } catch {
      // ignore update errors while continuing to fail request
    }
    throw new AppError(Messages.REFRESH_TOKEN_INVALID, 401)
  }

  if (existing.revoked) {
    await prisma.userRefreshToken.updateMany({
      where: { userId: existing.userId },
      data: { revoked: true }
    })
    throw new AppError(Messages.REFRESH_TOKEN_INVALID, 401)
  }

  if (existing.expiresAt <= new Date()) {
    await prisma.userRefreshToken.update({
      where: { id: existing.id },
      data: { revoked: true }
    })
    throw new AppError(Messages.REFRESH_TOKEN_EXPIRED, 401)
  }

  // 7) rotate token: create new refresh JWT and persist new row while revoking old
  const { token: newRefreshJwt, jti: newJti } = generateRefreshTokenWithJti({
    sub: userId
  })
  const newHash = sha256Hex(newJti)
  const newExpiresAt = new Date(Date.now() + REFRESH_TTL_MS)
  const userAgent = req.get('user-agent') ?? null
  const ip =
    req.ip ?? (req.headers['x-forwarded-for'] as string | undefined) ?? null

  await prisma.$transaction([
    prisma.userRefreshToken.update({
      where: { id: existing.id },
      data: { revoked: true, replacedBy: newHash }
    }),
    prisma.userRefreshToken.create({
      data: {
        userId,
        tokenHash: newHash,
        expiresAt: newExpiresAt,
        userAgent,
        ip
      }
    })
  ])

  // 8) issue new access token
  const accessToken = generateAccessToken({ sub: userId })

  // 9) set new refresh cookie
  res.cookie(REFRESH_COOKIE_NAME, newRefreshJwt, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: REFRESH_COOKIE_SAMESITE,
    path: REFRESH_COOKIE_PATH,
    maxAge: REFRESH_TTL_MS
  })

  // 10) respond with new access token
  return ApiResponse.success(
    req,
    res,
    200,
    Messages.TOKEN_REFRESHED ?? 'Token refreshed',
    {
      accessToken
    }
  )
}

export async function userProfile(req: Request, res: Response) {
  const userId = 'default_user'

  const cacheKey = `user:${userId}`
  let isCached = false
  const TTL_SECONDS = 60 * 60

  const cached = await redisCache.get(cacheKey)

  if (cached) {
    isCached = true
    const user = JSON.parse(cached)
    return ApiResponse.success(req, res, 200, 'User Found', { user, isCached })
  }

  const fakeUser = {
    id: userId,
    name: `User ${userId}`,
    email: `${
      String(userId)
        .replace(/[^a-z0-9]/gi, '')
        .toLowerCase() || 'user'
    }@example.com`,
    role: 'customer',
    createdAt: new Date().toISOString(),
    profile: {
      bio: 'This is a fake user generated for Redis test.',
      preferences: {
        newsletter: false
      }
    }
  }

  await redisCache.set(cacheKey, JSON.stringify(fakeUser), 'EX', TTL_SECONDS)

  return ApiResponse.success(req, res, 200, 'User Found', {
    fakeUser,
    isCached
  })
}
export async function userUpdate() {}
export async function userChangePassword() {}

import { Request, Response } from 'express'
import { ApiResponse } from '../../utils/apiResponse'
import { signupUserValidator } from '../../validators/user.validator'
import { AppError } from '../../utils/appError'
import { prisma } from '../../configs/prisma'
import { hashPassword } from '../../utils/password'
import { logger } from '../../configs/logger'
import { Messages } from '../../configs/messages'
import { maskEmail } from '../../utils/mask'

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
export async function userLogin() {}
export async function userProfile() {}
export async function userUpdate() {}
export async function userChangePassword() {}

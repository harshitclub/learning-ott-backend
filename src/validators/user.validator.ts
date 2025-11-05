import { z } from 'zod'
import { ZodErrorMessages } from './ZodErrorMessages'

const passwordRegex =
  /^(?=.*[A-Z])(?=.*[0-9])(?=.*[@$!%*?&])[A-Za-z0-9@$!%*?&]{6,}$/

// User Signup Validator
export const signupUserValidator = z.object({
  firstName: z
    .string()
    .trim()
    .min(2, ZodErrorMessages.FIRST_NAME_MIN)
    .max(50, ZodErrorMessages.FIRST_NAME_MAX),

  lastName: z
    .string()
    .trim()
    .min(2, ZodErrorMessages.LAST_NAME_MIN)
    .max(50, ZodErrorMessages.LAST_NAME_MAX),

  email: z
    .email(ZodErrorMessages.EMAIL_INVALID)
    .max(100, ZodErrorMessages.EMAIL_MAX)
    .toLowerCase()
    .trim(),

  password: z
    .string()
    .regex(passwordRegex, ZodErrorMessages.PASSWORD_COMPLEXITY)
    .nonempty(ZodErrorMessages.PASSWORD_REQUIRED)
})

// User Login Validator
export const loginUserValidator = z.object({
  email: z
    .email(ZodErrorMessages.EMAIL_INVALID)
    .max(100, ZodErrorMessages.EMAIL_MAX)
    .toLowerCase()
    .trim(),

  password: z.string().nonempty(ZodErrorMessages.PASSWORD_REQUIRED)
})

// Forget Password Validator
export const forgetPasswordValidator = z.object({
  email: z
    .email(ZodErrorMessages.EMAIL_INVALID)
    .max(100, ZodErrorMessages.EMAIL_MAX)
    .toLowerCase()
    .trim()
})

// User Change Password Validator
export const changePasswordValidator = z.object({
  currentPassword: z
    .string()
    .regex(passwordRegex, ZodErrorMessages.PASSWORD_COMPLEXITY)
    .nonempty(ZodErrorMessages.PASSWORD_REQUIRED),
  newPassword: z
    .string()
    .regex(passwordRegex, ZodErrorMessages.PASSWORD_COMPLEXITY)
    .nonempty(ZodErrorMessages.PASSWORD_REQUIRED)
})

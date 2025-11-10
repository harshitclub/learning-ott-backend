import z from 'zod'
import { ZodErrorMessages } from './ZodErrorMessages'

export const passwordRegex =
  /^(?=.*[A-Z])(?=.*[0-9])(?=.*[@$!%*?&])[A-Za-z0-9@$!%*?&]{6,}$/

export const CustomValidators = {
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
    .nonempty(ZodErrorMessages.PASSWORD_REQUIRED),
  username: z
    .string()
    .trim()
    .toLowerCase()
    .min(3, ZodErrorMessages.USERNAME_MIN)
    .max(20, ZodErrorMessages.USERNAME_MAX),
  phone: z.string(),
  profile: z.json()
}

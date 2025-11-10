import z from 'zod'
import { ZodErrorMessages } from './ZodErrorMessages'

export const passwordRegex =
  /^(?=.*[A-Z])(?=.*[0-9])(?=.*[@$!%*?&])[A-Za-z0-9@$!%*?&]{6,}$/

export const phoneRegex = /^[0-9]{10,15}$/

export const usernameRegex = /^[a-zA-Z0-9]+$/

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
    .toLowerCase()
    .regex(usernameRegex, ZodErrorMessages.USERNAME_INVALID)
    .min(3, ZodErrorMessages.USERNAME_MIN)
    .max(20, ZodErrorMessages.USERNAME_MAX)
    .trim(),
  phone: z.string().regex(phoneRegex, ZodErrorMessages.PHONE_INVALID),
  profile: z.object({
    bio: z
      .string()
      .min(3, ZodErrorMessages.PROFILE_BIO_MIN)
      .max(300, ZodErrorMessages.PROFILE_BIO_MAX)
      .optional(),
    facebook: z
      .url(ZodErrorMessages.PROFILE_URL_INVALID)
      .max(200, ZodErrorMessages.PROFILE_URL_MAX)
      .optional(),
    linkedin: z
      .url(ZodErrorMessages.PROFILE_URL_INVALID)
      .max(200, ZodErrorMessages.PROFILE_URL_MAX)
      .optional(),
    twitter: z
      .url(ZodErrorMessages.PROFILE_URL_INVALID)
      .max(200, ZodErrorMessages.PROFILE_URL_MAX)
      .optional(),
    instagram: z
      .url(ZodErrorMessages.PROFILE_URL_INVALID)
      .max(200, ZodErrorMessages.PROFILE_URL_MAX)
      .optional(),
    github: z
      .url(ZodErrorMessages.PROFILE_URL_INVALID)
      .max(200, ZodErrorMessages.PROFILE_URL_MAX)
      .optional()
  })
}

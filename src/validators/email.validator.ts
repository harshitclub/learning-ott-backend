import { z } from 'zod'

export const VerifyEmailSchema = z.object({
  to: z.email(),
  appName: z.string(),
  recipientName: z.string(),
  verifyUrl: z.url()
})

export const ResetPasswordEmailSchema = z.object({
  to: z.email(),
  appName: z.string(),
  recipientName: z.string(),
  resetUrl: z.url()
})

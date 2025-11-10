import z from 'zod'
import { CustomValidators } from './custom.validator'

// User Login Validator
export const loginValidator = z.object({
  email: CustomValidators.email,
  password: CustomValidators.password
})

// Forget Password Validator
export const forgetPasswordValidator = z.object({
  email: CustomValidators.email
})

// Change Password Validator
export const changePasswordValidator = z.object({
  currentPassword: CustomValidators.password,
  newPassword: CustomValidators.password
})

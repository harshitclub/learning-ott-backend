import { z } from 'zod'
import { CustomValidators } from './custom.validator'

// User Signup Validator
export const signupUserValidator = z.object({
  firstName: CustomValidators.firstName,
  lastName: CustomValidators.lastName,
  email: CustomValidators.email,
  password: CustomValidators.password
})

// User Update Profile Validator
export const updateUserValidator = z.object({
  firstName: CustomValidators.firstName.optional(),
  lastName: CustomValidators.lastName.optional(),
  username: CustomValidators.username.optional(),
  phone: CustomValidators.phone.optional(),
  profile: CustomValidators.profile.optional()
})

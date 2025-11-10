export enum ZodErrorMessages {
  // Name
  FIRST_NAME_MIN = 'First name must be at least 2 characters long',
  FIRST_NAME_MAX = 'First name is too long',
  LAST_NAME_MIN = 'Last name must be at least 2 characters long',
  LAST_NAME_MAX = 'Last name is too long',

  // Username
  USERNAME_MIN = 'Username must be at least 4 characters long',
  USERNAME_MAX = 'Username too long',

  // Email
  EMAIL_INVALID = 'Invalid email format',
  EMAIL_MAX = 'Email is too long',

  // Phone
  PHONE_MIN = 'Phone number must be at least 10 digits',
  PHONE_MAX = 'Phone number cannot exceed 15 digits',

  // Password
  PASSWORD_REQUIRED = 'Password is required',
  PASSWORD_MIN = 'Password must be at least 6 characters',
  PASSWORD_COMPLEXITY = 'Password must be at least 6 characters long, include 1 uppercase letter, 1 number, and 1 special character (@$!%*?&)'
}

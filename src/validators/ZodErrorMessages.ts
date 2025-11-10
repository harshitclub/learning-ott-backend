export enum ZodErrorMessages {
  // Name
  FIRST_NAME_MIN = 'First name must be at least 2 characters long',
  FIRST_NAME_MAX = 'First name is too long',
  LAST_NAME_MIN = 'Last name must be at least 2 characters long',
  LAST_NAME_MAX = 'Last name is too long',

  // Username
  USERNAME_MIN = 'Username must be at least 4 characters long',
  USERNAME_MAX = 'Username too long',
  USERNAME_INVALID = 'Username can only contain letters and numbers.',

  // Email
  EMAIL_INVALID = 'Invalid email format',
  EMAIL_MAX = 'Email is too long',

  // Phone
  PHONE_INVALID = 'Phone number must be 10 to 15 digits.',

  // Password
  PASSWORD_REQUIRED = 'Password is required',
  PASSWORD_MIN = 'Password must be at least 6 characters',
  PASSWORD_COMPLEXITY = 'Password must be at least 6 characters long, include 1 uppercase letter, 1 number, and 1 special character (@$!%*?&)',

  // Profile
  PROFILE_BIO_MIN = 'Bio must be at least 3 characters.',
  PROFILE_BIO_MAX = 'Bio cannot be longer than 300 characters.',
  PROFILE_URL_MAX = 'URL too long.',
  PROFILE_URL_INVALID = 'Link must be a valid URL.'
}

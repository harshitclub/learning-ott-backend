export const Messages = {
  // General / System
  SUCCESS: 'Operation completed successfully',
  FAILED: 'An error occurred. Please try again later',
  SERVER_ERROR: 'Internal server error',
  BAD_REQUEST: 'Bad request',
  VALIDATION_FAILED: 'Validation failed',
  NOT_FOUND: 'Requested resource not found',
  ROUTE_NOT_FOUND: 'Endpoint not found',
  UNAUTHORIZED: 'Authentication required',
  FORBIDDEN: 'Access denied',
  TOO_MANY_REQUESTS: 'Too many requests. Please try again later',
  UNDER_MAINTENANCE: 'Service is temporarily unavailable for maintenance',
  FEATURE_UNAVAILABLE: 'This feature is currently unavailable',

  // Auth & Tokens
  LOGIN_SUCCESS: 'Login successful',
  LOGIN_FAILED: 'Invalid credentials',
  LOGOUT_SUCCESS: 'Logged out successfully',
  TOKEN_INVALID: 'Invalid or expired token',
  TOKEN_REQUIRED: 'Authorization token required',
  TOKEN_REFRESHED: 'Access token refreshed',
  TOKEN_REVOKED: 'Session revoked',
  SESSION_NOT_FOUND: 'Session not found',
  ACCESS_DENIED: 'You do not have permission to perform this action',
  REFRESH_TOKEN_MISSING: 'Refresh token missing',
  REFRESH_TOKEN_INVALID: 'Invalid or expired refresh token',
  REFRESH_TOKEN_EXPIRED: 'Refresh token expired',
  MISSING_VERIFICATION_TOKEN: 'Missing verification token',
  INVALID_LINK: 'Invalid or expired link',
  VERIFIED: 'Email verified',

  // User & Account
  USER_CREATED: 'Account created successfully',
  USER_UPDATED: 'Account updated successfully',
  USER_DELETED: 'Account deleted successfully',
  USER_NOT_FOUND: 'User not found',
  USER_ALREADY_EXISTS: 'Unable to create account with provided email',
  EMAIL_VERIFIED: 'Email verified successfully',
  EMAIL_NOT_VERIFIED: 'Email not verified',
  VERIFICATION_EMAIL_SENT: 'Verification email has been sent',
  VERIFICATION_TOKEN_EXPIRED: 'Verification token has expired',
  VERIFICATION_TOKEN_INVALID: 'Verification token is invalid or already used',
  PASSWORD_CHANGED: 'Password changed successfully',
  PASSWORD_RESET_REQUESTED:
    'If an account exists, a password reset link has been sent',
  PASSWORD_RESET_SUCCESS: 'Password has been reset successfully',
  PASSWORD_RESET_FAILED: 'Unable to reset password',
  PASSWORD_WEAK: 'Password does not meet complexity requirements',

  // Security / Abuse
  ACCOUNT_LOCKED: 'Account temporarily locked due to multiple failed attempts',
  CAPTCHA_REQUIRED: 'Please complete the CAPTCHA challenge',
  RATE_LIMITED: 'Rate limit exceeded. Try again later',
  SUSPICIOUS_ACTIVITY:
    'Suspicious activity detected. Please verify your account',

  // Email / Notifications
  EMAIL_SENT: 'Email sent successfully',
  EMAIL_FAILED: 'Failed to send email',

  // Database / Integration
  DB_CONNECTION_ERROR: 'Unable to connect to database',
  DB_OPERATION_FAILED: 'Database operation failed',
  EXTERNAL_SERVICE_ERROR: 'External service error. Please try again later',

  // Files / Uploads
  FILE_UPLOAD_SUCCESS: 'File uploaded successfully',
  FILE_UPLOAD_FAILED: 'File upload failed',
  FILE_TOO_LARGE: 'Uploaded file is too large',
  FILE_TYPE_NOT_ALLOWED: 'Uploaded file type is not allowed',

  // Admin / Management
  ADMIN_CREATED: 'Administrator account created',
  ADMIN_UPDATED: 'Administrator updated',
  ADMIN_DELETED: 'Administrator deleted',

  // Misc
  INVALID_REQUEST: 'Invalid request format',
  CONFIG_ERROR: 'Service configuration error',
  HEALTH_OK: 'OK'
}

// Optional: machine-friendly error codes (useful for frontend localization & logic)
export const MessageCodes = {
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  USER_EXISTS: 'USER_ALREADY_EXISTS',
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  VERIFICATION_EXPIRED: 'VERIFICATION_TOKEN_EXPIRED',
  PASSWORD_WEAK: 'PASSWORD_WEAK',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  RATE_LIMITED: 'RATE_LIMITED',
  TOKEN_INVALID: 'TOKEN_INVALID',
  SERVER_ERROR: 'SERVER_ERROR'
}

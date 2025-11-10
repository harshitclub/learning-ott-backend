export const Messages = {
  // ───── General ─────
  SUCCESS: 'Operation completed successfully',
  FAILED: 'Something went wrong. Please try again.',
  SERVER_ERROR: 'Internal server error',
  BAD_REQUEST: 'Bad request',
  VALIDATION_FAILED: 'Validation failed',
  NOT_FOUND: 'Resource not found',
  ROUTE_NOT_FOUND: 'Endpoint not found',
  UNAUTHORIZED: 'Authentication required',
  FORBIDDEN: 'Access denied',
  TOO_MANY_REQUESTS: 'Too many requests. Try again later',
  UNDER_MAINTENANCE: 'Service temporarily unavailable',
  FEATURE_UNAVAILABLE: 'This feature is currently unavailable',

  // ───── Auth ─────
  LOGIN_SUCCESS: 'Logged in successfully',
  LOGIN_FAILED: 'Invalid login credentials',
  LOGOUT_SUCCESS: 'Logged out successfully',
  TOKEN_INVALID: 'Invalid or expired token',
  TOKEN_REQUIRED: 'Authorization token required',
  TOKEN_REFRESHED: 'Token refreshed successfully',
  ACCESS_DENIED: 'You do not have permission to perform this action',

  // ───── Verification ─────
  EMAIL_VERIFIED: 'Email verified successfully',
  EMAIL_NOT_VERIFIED: 'Email is not verified',
  VERIFICATION_EMAIL_SENT: 'Verification email sent',
  VERIFICATION_TOKEN_INVALID: 'Invalid or expired verification link',
  VERIFICATION_TOKEN_EXPIRED: 'Verification token has expired',
  MISSING_VERIFICATION_TOKEN: 'Verification token not found',

  // ───── User Profile ─────
  USER_NOT_FOUND: 'User not found',
  USER_CREATED: 'Account created successfully',
  USER_UPDATED: 'Account updated successfully',
  USER_DELETED: 'Account deleted successfully',
  USER_ALREADY_EXISTS: 'User with this email already exists',
  NO_VALID_FIELD: 'No valid fields provided for update',
  PROFILE_FETCHED: 'Profile retrieved successfully',
  PASSWORD_CHANGED: 'Password changed successfully',

  // ───── Password Reset ─────
  PASSWORD_RESET_REQUESTED: 'If an account exists, a reset link has been sent',
  PASSWORD_RESET_SUCCESS: 'Password has been reset successfully',
  PASSWORD_RESET_FAILED: 'Failed to reset password',
  PASSWORD_WEAK: 'Password does not meet security requirements',

  // ───── Security / Abuse ─────
  ACCOUNT_LOCKED: 'Account temporarily locked due to multiple failed attempts',
  SUSPICIOUS_ACTIVITY:
    'Suspicious activity detected. Additional verification required',

  // ───── Email / Notifications ─────
  EMAIL_SENT: 'Email sent successfully',
  EMAIL_FAILED: 'Failed to send email',

  // ───── Database ─────
  DB_CONNECTION_ERROR: 'Could not connect to database',
  DB_OPERATION_FAILED: 'Database operation failed',

  // ───── File Uploads ─────
  FILE_UPLOAD_SUCCESS: 'File uploaded successfully',
  FILE_UPLOAD_FAILED: 'File upload failed',
  FILE_TOO_LARGE: 'File size exceeds allowed limit',
  FILE_TYPE_NOT_ALLOWED: 'File type not allowed',

  // ───── Admin (NEW + CLEAN) ─────
  ADMIN_CREATED: 'Admin account created successfully',
  ADMIN_UPDATED: 'Admin details updated successfully',
  ADMIN_DELETED: 'Admin account deleted successfully',
  ADMIN_NOT_FOUND: 'Admin not found',
  ADMIN_ACTION_FORBIDDEN: 'Only administrators can perform this action',

  // ───── System / Misc ─────
  INVALID_REQUEST: 'Invalid request format',
  CONFIG_ERROR: 'Configuration error',
  HEALTH_OK: 'OK'
}

// Optional: machine-friendly error codes (useful for frontend localization & logic)
export const MessageCodes = {
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  NOT_FOUND: 'NOT_FOUND',
  USER_EXISTS: 'USER_EXISTS',
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  VERIFICATION_EXPIRED: 'VERIFICATION_EXPIRED',
  PASSWORD_WEAK: 'PASSWORD_WEAK',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  RATE_LIMITED: 'RATE_LIMITED',
  TOKEN_INVALID: 'TOKEN_INVALID',
  SERVER_ERROR: 'SERVER_ERROR'
}

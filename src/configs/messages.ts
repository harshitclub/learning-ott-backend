export const Messages = {
  // General
  SUCCESS: 'Operation completed successfully',
  FAILED: 'Something went wrong',
  VALIDATION_FAILED: 'Validation failed',
  NOT_FOUND: 'Resource not found',
  UNAUTHORIZED: 'Unauthorized access',
  FORBIDDEN: 'You do not have permission to perform this action',
  SERVER_ERROR: 'Internal server error',
  BAD_REQUEST: 'Bad request',
  TOO_MANY_REQUESTS: 'Too many requests, please try again later',

  // User-related
  USER_CREATED: 'User registered successfully',
  USER_UPDATED: 'User profile updated successfully',
  USER_DELETED: 'User deleted successfully',
  USER_NOT_FOUND: 'User not found',
  USER_ALREADY_EXISTS: 'User with this email already exists',
  EMAIL_ALREADY_IN_USE: 'Email already in use',
  USER_DISABLED: 'User account is disabled',
  PASSWORD_CHANGED: 'Password changed successfully',

  // Auth-related
  LOGIN_SUCCESS: 'Login successful',
  LOGIN_FAILED: 'Invalid credentials',
  LOGOUT_SUCCESS: 'Logout successful',
  TOKEN_REFRESHED: 'Access token refreshed successfully',
  TOKEN_INVALID: 'Invalid or expired token',
  TOKEN_REQUIRED: 'Authorization token required',
  ACCESS_DENIED: 'Access denied',
  EMAIL_VERIFIED: 'Email verified successfully',
  EMAIL_NOT_VERIFIED: 'Email not verified',
  VERIFICATION_EMAIL_SENT: 'Verification email sent',
  PASSWORD_RESET_REQUESTED: 'Password reset link sent successfully',
  PASSWORD_RESET_SUCCESS: 'Password reset successful',
  PASSWORD_RESET_FAILED: 'Password reset failed',

  // System
  SERVER_HEALTHY: 'Server is healthy',
  SYSTEM_STATUS_OK: 'System status OK',
  ROUTE_NOT_FOUND: 'Route not found',
  CONFIG_ERROR: 'Configuration error detected',

  // Database
  DB_CONNECTION_SUCCESS: 'Database connection successful',
  DB_CONNECTION_ERROR: 'Database connection failed',
  DB_OPERATION_FAILED: 'Database operation failed',

  // Email
  EMAIL_SENT: 'Email sent successfully',
  EMAIL_FAILED: 'Failed to send email',

  // Misc
  FEATURE_UNAVAILABLE: 'This feature is not available yet',
  UNDER_MAINTENANCE: 'Service is under maintenance',
  INVALID_REQUEST: 'Invalid request format'
}

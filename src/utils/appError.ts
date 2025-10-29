export class AppError extends Error {
  statusCode: number;
  status: string;
  isOperational: boolean;

  constructor(message: string, statusCode: number) {
    super(message);

    this.statusCode = statusCode;

    // "fail" for 4xx errors, "error" for 5xx errors
    this.status = `${statusCode}`.startsWith("4") ? "fail" : "error";
    this.isOperational = true;

    // Captures stack trace but exclude this contructor
    Error.captureStackTrace(this, this.constructor);
  }
}

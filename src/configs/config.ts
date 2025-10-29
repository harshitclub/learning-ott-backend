import dotenv from "dotenv";
dotenv.config();

const ENV = process.env.NODE_ENV || "development";

export const config = {
  ENV,
  FRONTEND_URL: process.env.FRONTEND_URL || "http://localhost:3000",
  PORT: Number(process.env.PORT) || 5000,
  LOG_LEVEL: process.env.LOG_LEVEL || "info",

  DATABASE_URL: process.env.DATABASE_URL!,

  BCRYPT_SALT_ROUNDS: Number(process.env.BCRYPT_SALT_ROUNDS) || 10,

  REDIS: {
    CACHE_URL: process.env.REDIS_CACHE_URL!,
    BULL_URL: process.env.REDIS_BULL_URL!,
  },

  WORKERS: {
    EMAIL_CONCURRENCY: Number(process.env.EMAIL_WORKER_CONCURRENCY) || 5,
  },

  JWT: {
    VERIFICATION_SECRET: process.env.JWT_VERIFICATION_SECRET!,
    ACCESS_SECRET: process.env.JWT_ACCESS_SECRET!,
    REFRESH_SECRET: process.env.JWT_REFRESH_SECRET!,
  },

  SMTP: {
    HOST: process.env.SMTP_HOST!,
    PORT: Number(process.env.SMTP_PORT) || 465,
    USER: process.env.SMTP_USER!,
    PASS: process.env.SMTP_PASS!,
    MAIL_FROM: process.env.MAIL_FROM || "No Reply <noreply@example.com>",
  },
};

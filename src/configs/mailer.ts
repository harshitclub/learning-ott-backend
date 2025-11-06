import nodemailer from 'nodemailer'
import { logger } from './logger'
import { config } from './config'

// SMTP TRANSPORT
export const transporter = nodemailer.createTransport({
  host: config.SMTP.HOST,
  port: config.SMTP.PORT,
  secure: config.SMTP.PORT === 465,
  auth: {
    user: config.SMTP.USER,
    pass: config.SMTP.PASS
  },
  pool: true, // enable connection pooling
  maxConnections: 5, // maintain up to 5 open connections
  maxMessages: 100, // send up to 100 emails per connection
  rateDelta: 1000, // window for rate limit
  rateLimit: 10, // max 10 messages per second (safe default)
  tls: {
    rejectUnauthorized: false // prevents TLS issues with some providers
  }
})

// Verify SMTP connection
transporter
  .verify()
  .then(() => logger.info('SMTP server ready to send emails'))
  .catch((err) => logger.error('SMTP connection error:', err.message))

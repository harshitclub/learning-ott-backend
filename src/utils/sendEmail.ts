import type { SentMessageInfo } from 'nodemailer'
import { transporter } from '../configs/mailer'
import { logger } from '../configs/logger'
import { config } from '../configs/config'
import { htmlToText } from 'html-to-text'

export interface SendEmailOptions {
  to: string
  subject: string
  html: string
  text?: string
}

export interface SendEmailResult {
  messageId: string
  accepted: string[]
  rejected: string[]
  envelope: SentMessageInfo['envelope']
}

export const sendEmail = async ({
  to,
  subject,
  html,
  text
}: SendEmailOptions): Promise<SendEmailResult> => {
  try {
    const info = await transporter.sendMail({
      from: config.SMTP.MAIL_FROM,
      to,
      subject,
      html,
      text: text ?? htmlToText(html)
    })

    logger.info(`Email sent to ${to}`, { messageId: info.messageId })
    return {
      messageId: info.messageId,
      accepted: (info.accepted as string[]) ?? [],
      rejected: (info.rejected as string[]) ?? [],
      envelope: info.envelope
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    logger.error(`Email send failed to ${to}: ${message}`)
    throw err
  }
}

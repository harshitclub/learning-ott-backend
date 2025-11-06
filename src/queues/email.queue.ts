import { Queue, JobsOptions } from 'bullmq'
import crypto from 'crypto'
import { redisBull } from '../configs/redisBull'

export type EmailJobName = 'verificationEmail' | 'resetPasswordEmail'

export interface EmailJobData {
  to: string
  subject: string
  html: string
}

export const emailQueue = new Queue<EmailJobData, unknown, EmailJobName>(
  'emailQueue',
  {
    connection: redisBull,
    defaultJobOptions: {
      attempts: 3,
      backoff: { type: 'exponential', delay: 5000 },
      removeOnComplete: { age: 3600 },
      removeOnFail: false
    }
  }
)

function buildJobId(name: EmailJobName, data: EmailJobData) {
  const hash = crypto
    .createHash('sha256')
    .update(JSON.stringify({ name, data }))
    .digest('hex')
    .slice(0, 16)
  return `${name}:${hash}`
}

export async function enqueueEmail(
  name: EmailJobName,
  data: EmailJobData,
  opts?: JobsOptions & { jobId?: string }
) {
  // caller can pass a custom jobId; otherwise we generate a deterministic one
  const jobId = opts?.jobId ?? buildJobId(name, data)
  return emailQueue.add(name, data, { ...opts, jobId })
}

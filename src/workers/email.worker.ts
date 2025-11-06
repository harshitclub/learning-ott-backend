import { Worker, Job } from 'bullmq'
import { logger } from '../configs/logger'
import { redisBull } from '../configs/redisBull'
import { config } from '../configs/config'
import { sendEmail } from '../utils/sendEmail'

type EmailJobName = 'verificationEmail' | 'resetPasswordEmail'

interface EmailPayload {
  to: string
  subject: string
  html: string
}

const processor = async (
  job: Job<EmailPayload, unknown, EmailJobName>
): Promise<void> => {
  logger.info(`Processing job: ${job.name}`, { jobId: job.id })

  switch (job.name) {
    case 'verificationEmail':
    case 'resetPasswordEmail':
      await sendEmail(job.data)
      break
    default:
      logger.warn('Unknown job type', { jobName: job.name })
  }
}

const emailWorker = new Worker<EmailPayload, unknown, EmailJobName>(
  'emailQueue',
  processor,
  {
    connection: redisBull,
    concurrency: Number(config.WORKERS.EMAIL_CONCURRENCY) || 5
  }
)

emailWorker.on('active', (job) => {
  logger.info('Job active', { jobId: job.id, name: job.name })
})

emailWorker.on('failed', (job, err) => {
  logger.error(`Job ${job?.id} failed`, {
    name: job?.name,
    error: err?.message
  })
})

emailWorker.on('completed', (job) => {
  logger.info(`Job completed: ${job.id}`)
})

emailWorker.on('error', (err) => {
  logger.error('Worker error', { error: err?.message })
})

emailWorker.on('drained', () => {
  logger.info('Queue drained (no waiting jobs)')
})

process.on('SIGINT', async () => {
  logger.info('SIGINT: shutting down worker gracefully...')
  await emailWorker.close()
  await redisBull.quit()
  logger.info('Worker cleanup done. Exiting.')
  process.exit(0)
})

export default emailWorker

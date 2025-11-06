import Redis from 'ioredis'
import { config } from './config'
import { logger } from './logger'

export const redisBull = new Redis(config.REDIS.BULL_URL, {
  maxRetriesPerRequest: null,
  enableReadyCheck: false
})

redisBull.on('connect', () => {
  logger.info('Redis (BullMQ) connected:', config.REDIS.BULL_URL)
})

redisBull.on('error', (err) => {
  logger.error('Redis (BullMQ) error:', err.message)
})

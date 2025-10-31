import { PrismaClient } from '../../generated/prisma'
import { logger } from './logger'

const globalForPrisma = globalThis as unknown as {
  prisma?: PrismaClient
}

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log:
      process.env.NODE_ENV === 'development'
        ? ['query', 'error', 'warn']
        : ['error']
  })

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma

logger.info(`Prisma Client initialized for ${process.env.NODE_ENV} mode.`)

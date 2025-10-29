import { PrismaClient } from "../../generated/prisma";
import { logger } from "./logger";

let prisma: PrismaClient;

if (process.env.NODE_ENV === "production") {
  prisma = new PrismaClient();
  logger.info("Prisma Client initialized for production.");
} else {
  if (!(global as any).prisma) {
    (global as any).prisma = new PrismaClient();
    logger.info("Prisma Client initialized for development.");
  }
  prisma = (global as any).prisma;
}

export { prisma };

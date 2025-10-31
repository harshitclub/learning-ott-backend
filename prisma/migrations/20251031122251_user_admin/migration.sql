-- CreateEnum
CREATE TYPE "Role" AS ENUM ('USER', 'ADMIN');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "emailVerified" BOOLEAN NOT NULL DEFAULT false,
    "passwordHash" TEXT NOT NULL,
    "firstName" TEXT NOT NULL,
    "lastName" TEXT NOT NULL,
    "username" TEXT,
    "phone" TEXT,
    "isDisabled" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "profile" JSONB,
    "role" "Role" NOT NULL DEFAULT 'USER',
    "lastLoginAt" TIMESTAMP(3),
    "failedLogins" INTEGER NOT NULL DEFAULT 0,
    "passwordChangedAt" TIMESTAMP(3),
    "metadata" JSONB,
    "emailVerificationTokenHash" TEXT,
    "emailVerificationExpiresAt" TIMESTAMP(3),
    "emailVerificationUsed" BOOLEAN NOT NULL DEFAULT false,
    "passwordResetTokenHash" TEXT,
    "passwordResetExpiresAt" TIMESTAMP(3),
    "passwordResetUsed" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Admin" (
    "id" TEXT NOT NULL,
    "firstName" TEXT NOT NULL,
    "lastName" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "emailVerified" BOOLEAN NOT NULL DEFAULT false,
    "passwordHash" TEXT NOT NULL,
    "username" TEXT,
    "phone" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'ADMIN',
    "isSuperAdmin" BOOLEAN NOT NULL DEFAULT false,
    "notes" TEXT,
    "lastLoginAt" TIMESTAMP(3),
    "metadata" JSONB,
    "emailVerificationTokenHash" TEXT,
    "emailVerificationExpiresAt" TIMESTAMP(3),
    "emailVerificationUsed" BOOLEAN NOT NULL DEFAULT false,
    "passwordResetTokenHash" TEXT,
    "passwordResetExpiresAt" TIMESTAMP(3),
    "passwordResetUsed" BOOLEAN NOT NULL DEFAULT false,

    CONSTRAINT "Admin_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");

-- CreateIndex
CREATE INDEX "User_email_idx" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_createdAt_idx" ON "User"("createdAt");

-- CreateIndex
CREATE INDEX "User_emailVerificationExpiresAt_idx" ON "User"("emailVerificationExpiresAt");

-- CreateIndex
CREATE INDEX "User_passwordResetExpiresAt_idx" ON "User"("passwordResetExpiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "Admin_email_key" ON "Admin"("email");

-- CreateIndex
CREATE UNIQUE INDEX "Admin_username_key" ON "Admin"("username");

-- CreateIndex
CREATE INDEX "Admin_email_idx" ON "Admin"("email");

-- CreateIndex
CREATE INDEX "Admin_createdAt_idx" ON "Admin"("createdAt");

-- CreateIndex
CREATE INDEX "Admin_emailVerificationExpiresAt_idx" ON "Admin"("emailVerificationExpiresAt");

-- CreateIndex
CREATE INDEX "Admin_passwordResetExpiresAt_idx" ON "Admin"("passwordResetExpiresAt");

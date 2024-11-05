-- CreateEnum
CREATE TYPE "VulnerabilityServerity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');

-- CreateTable
CREATE TABLE "VulnerabilityPatterns" (
    "id" TEXT NOT NULL,
    "vulnerabilityId" TEXT NOT NULL,
    "vulnerabilityName" TEXT NOT NULL,
    "patterns" JSONB NOT NULL,
    "severity" "VulnerabilityServerity" NOT NULL,
    "swc_code" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "VulnerabilityPatterns_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "VulnerabilityPatterns_vulnerabilityId_key" ON "VulnerabilityPatterns"("vulnerabilityId");

-- CreateIndex
CREATE UNIQUE INDEX "VulnerabilityPatterns_vulnerabilityName_key" ON "VulnerabilityPatterns"("vulnerabilityName");

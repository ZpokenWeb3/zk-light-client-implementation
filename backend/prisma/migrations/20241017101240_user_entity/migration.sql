-- CreateTable
CREATE TABLE "BlockProof" (
    "hash" TEXT NOT NULL PRIMARY KEY DEFAULT '',
    "epochId" TEXT NOT NULL,
    "height" INTEGER NOT NULL,
    "timestamp" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "previousEpochStartHash" TEXT NOT NULL,
    "previousEpochEndHash" TEXT NOT NULL,
    "dateCreate" TEXT NOT NULL
);

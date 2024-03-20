-- CreateTable
CREATE TABLE "BlockProof" (
    "hash" TEXT NOT NULL PRIMARY KEY DEFAULT '',
    "epochId" TEXT NOT NULL,
    "height" INTEGER NOT NULL,
    "timestamp" BIGINT NOT NULL DEFAULT 0,
    "status" TEXT NOT NULL,
    "hexInput" TEXT NOT NULL,
    "previousEpochHash" TEXT NOT NULL,
    "nextBlockHash" TEXT NOT NULL,
    "dateCreate" BIGINT NOT NULL
);

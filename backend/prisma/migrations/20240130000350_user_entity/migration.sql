-- RedefineTables
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_BlockProof" (
    "hash" TEXT NOT NULL PRIMARY KEY DEFAULT '',
    "epochId" TEXT NOT NULL,
    "height" INTEGER NOT NULL,
    "timestamp" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "hexInput" TEXT NOT NULL,
    "previousEpochHash" TEXT NOT NULL,
    "nextBlockHash" TEXT NOT NULL,
    "dateCreate" TEXT NOT NULL
);
INSERT INTO "new_BlockProof" ("dateCreate", "epochId", "hash", "height", "hexInput", "nextBlockHash", "previousEpochHash", "status", "timestamp") SELECT "dateCreate", "epochId", "hash", "height", "hexInput", "nextBlockHash", "previousEpochHash", "status", "timestamp" FROM "BlockProof";
DROP TABLE "BlockProof";
ALTER TABLE "new_BlockProof" RENAME TO "BlockProof";
PRAGMA foreign_key_check;
PRAGMA foreign_keys=ON;

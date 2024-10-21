export interface RandomBlockProvingTask {
    currentBlockHash: string;
    previousEpochStartHash: string;
    previousEpochEndHash: string;
}

export interface RandomBlockProvingResult {
    currentBlockHash: string;
    journal: string,
    proof: string,
    status: string;
}

export interface EpochBlockProvingTask {
    currentEpochHash: string;
    prevEpochStartHash: string;
    prevEpochEndHash: string;
    prevEpochMinus1EndHash: string;
    prevEpochMinus2EndHash: string;
}

export interface EpochBlockProvingResult {
    currentBlockHash: string;
    previousBlockHash: string;
    currentBlockHeight: number;
    status: string;
}

export interface ProvingResult {
    current_hash: string;
    status: string;
}

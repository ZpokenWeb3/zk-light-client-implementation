export interface ProvingTask {
    previous_epoch_hash: string,
    current_hash: string,
    next_hash: string
}

export interface ProvingResult {
    current_hash: string,
    status: string
}
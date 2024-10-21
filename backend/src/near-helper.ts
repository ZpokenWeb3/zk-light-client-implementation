import {decode} from 'bs58';
import {EpochBlockProvingTask, RandomBlockProvingTask} from './types';
import {getEpochHashesByHeight} from "./eth-helper";



export const nearRpc = process.env.NEAR_RPC || 'https://rpc.mainnet.near.org';
export const nearArchivalRpc = process.env.NEAR_ARCHIVAL_RPC || 'https://archival-rpc.mainnet.near.org';

export const BLOCKS_IN_EPOCH = 43200;

export const fetchBlockByHashFromNear = async (rpc: string, hash: string) => {
    const response = await fetch(rpc, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            jsonrpc: '2.0',
            id: 'dontcare',
            method: 'block',
            params: {block_id: hash},
        }),
    });
    return JSON.parse(await response.clone().text());
};

export const selectCorrectNode = async (hash?: string, height?: number) => {
    try {
        if (!hash && !height) {
            throw new Error('Either hash or height must be provided');
        }
        const blockId = hash ? hash : height;
        const currentBlockText = await fetch(nearRpc, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                    jsonrpc: '2.0',
                    id: 'dontcare',
                    method: 'block',
                    params: {block_id: blockId}
                }
            ),
        }).then(response => {
            if (!response.ok) {
                throw BlockError.InternalError(`Failed request with status ${response.status}`);
            }

            return response.text();
        });

        const currentBlockResponse = JSON.parse(currentBlockText);

        if (currentBlockResponse.error && currentBlockResponse.error.cause.name === 'UNKNOWN_BLOCK') {
            const archivalResponseText = await fetch(nearArchivalRpc, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                        jsonrpc: '2.0',
                        id: 'dontcare',
                        method: 'block',
                        params: {block_id: blockId}
                    }
                ),
            }).then(response => {
                if (!response.ok) {
                    throw BlockError.InternalError(`Failed request with status ${response.status}`);
                }

                return response.text();
            });

            const archivalResponse = JSON.parse(archivalResponseText);
            if (archivalResponse.error && archivalResponse.error.cause.name === 'UNKNOWN_BLOCK') {
                throw BlockError.UnknownBlock(blockId);
            } else if (archivalResponse.error && archivalResponse.error.cause.name === 'NOT_SYNCED_YET') {
                throw BlockError.NotSyncedYet();
            }
            console.log('Switching to archival RPC');
            return nearArchivalRpc;
        } else if (currentBlockResponse.error && currentBlockResponse.error.cause.name === 'NOT_SYNCED_YET') {
            throw BlockError.NotSyncedYet();
        }

        const latestBlockText = await fetch(nearArchivalRpc, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                jsonrpc: '2.0',
                id: 'dontcare',
                method: 'block',
                params: {finality: "optimistic"},
            }),
        }).then(response => {
            if (!response.ok) {
                throw BlockError.InternalError(`Failed request with status ${response.status}`);
            }
            return response.text();
        });

        const latestBlockResponse = JSON.parse(latestBlockText);

        if (currentBlockResponse.result.header.height < latestBlockResponse.result.header.height - BLOCKS_IN_EPOCH * 3) {
            console.log('Switching to archival RPC');
            return nearArchivalRpc;
        } else {
            return nearRpc;
        }

    } catch (error) {
        if (error instanceof BlockError) {
            throw error;
        } else {
            console.log(error)
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-expect-error
            throw BlockError.UnexpectedError(error.message || 'Unknown error occurred');
        }
    }
};

export const fetchBlockByHeightFromNear = async (rpc: any, height: number) => {
    const response = await fetch(rpc, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            jsonrpc: '2.0',
            id: 'dontcare',
            method: 'block',
            params: {block_id: height},
        }),
    });
    return JSON.parse(await response.clone().text());
};

// eslint-disable-next-line
export const getRandomProvingTask = async (rpc: any, block: any): Promise<RandomBlockProvingTask> => {
    const epochId = block.result.header.epoch_id;
    const epoch_id_i_2_block_last = await fetchBlockByHashFromNear(rpc, epochId);
    const savedHeight = epoch_id_i_2_block_last.result.header.height + 1;
    const {previousHashSaved, currentHashSaved} = await getEpochHashesByHeight(savedHeight);
    return {
        currentBlockHash: block.result.header.hash,
        previousEpochStartHash: currentHashSaved,
        previousEpochEndHash: previousHashSaved,
    };
};

// eslint-disable-next-line
export const getEpochProvingTask = async (rpc: any, currentHeight: any): Promise<EpochBlockProvingTask> => {
    let lastBlockHeight = currentHeight + BLOCKS_IN_EPOCH - 1;
    let firstBlockHeight = currentHeight + BLOCKS_IN_EPOCH;

    const {previousHashSaved, currentHashSaved} = await getEpochHashesByHeight(currentHeight);

    const lkbBlock = await fetchBlockByHashFromNear(rpc, currentHashSaved);
    let epoch_id_i_1_block_last = lkbBlock;
    let epoch_id_i_block_0 = lkbBlock;

    // eslint-disable-next-line no-constant-condition
    while (true) {
        epoch_id_i_1_block_last = await fetchBlockByHeightFromNear(rpc, lastBlockHeight);
        epoch_id_i_block_0 = await fetchBlockByHeightFromNear(rpc, firstBlockHeight);
        if (epoch_id_i_1_block_last.error || epoch_id_i_block_0.error) {
            lastBlockHeight += 1;
            firstBlockHeight += 1;

            //Check whether block is produced or not, await
            if (firstBlockHeight - currentHeight + BLOCKS_IN_EPOCH >= 20) {
                throw Error("Block isn't produced, await...")
            }

            continue
        }

        if (
            lkbBlock.result.header.epoch_id === epoch_id_i_1_block_last.result.header.epoch_id &&
            epoch_id_i_1_block_last.result.header.hash === epoch_id_i_block_0.result.header.next_epoch_id &&
            epoch_id_i_1_block_last.result.header.hash === epoch_id_i_block_0.result.header.prev_hash
        ) {
            console.log("Heights: ", lastBlockHeight, firstBlockHeight);
            break;
        }

        lastBlockHeight += 1;
        firstBlockHeight += 1;
    }

    const epoch_id_i_2_block_last = await fetchBlockByHashFromNear(rpc, previousHashSaved);
    const epoch_id_i_3_hash_last = epoch_id_i_2_block_last.result.header.next_epoch_id;

    return {
        currentEpochHash: epoch_id_i_block_0.result.header.hash,
        prevEpochStartHash: currentHashSaved,
        prevEpochEndHash: epoch_id_i_1_block_last.result.header.hash,
        prevEpochMinus1EndHash: previousHashSaved,
        prevEpochMinus2EndHash: epoch_id_i_3_hash_last,
    };
};

export const base58toHex = (hash: string): string => {
    const buffer = decode(hash);
    return Buffer.from(buffer).toString('hex');
};


class BlockError extends Error {
    static ParseError = (message: string) => new BlockError(`Parse error: ${message}`);
    static InternalError = (message: string) => new BlockError(`Internal error: ${message}`);
    static UnexpectedError = (message: string) => new BlockError(`Unexpected error: ${message}`);
    static UnknownBlock = (message: string | number | undefined) => new BlockError(`Unknown block error: ${message}`);
    static NotSyncedYet = () => new BlockError('Node is not synced yet');
}


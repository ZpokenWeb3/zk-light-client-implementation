import axios from 'axios';
import {getEpochProvingTask, selectCorrectNode} from "../near-helper";
import {serverUrl} from "../server";
import {EpochBlockProvingResult} from "../types";
import {getLatestCheckpointFromContract, saveEpochHashesAndSetCheckpoint} from "../eth-helper";

export const epochProcessor = async () => {
    let lastKnownHeight = await getLatestCheckpointFromContract();
    // eslint-disable-next-line no-constant-condition
    while (true) {
        try {
            console.log('Fetched Latest Height Checkpoint:', lastKnownHeight);
            const rpc = await selectCorrectNode(undefined, lastKnownHeight);
            const task = await getEpochProvingTask(rpc, lastKnownHeight);
            console.log("Send task to epoch service:", task);
            const response = await axios.post(`${serverUrl}/epoch/proof`, JSON.stringify(task), {
                headers: {
                    'Content-Type': 'application/json',
                },
            });
            const data = response.data as EpochBlockProvingResult;
            if (data.status == "OK") {
                await saveEpochHashesAndSetCheckpoint(data.previousBlockHash, data.currentBlockHash, data.currentBlockHeight);
                console.log(`Processed height ${lastKnownHeight}:`, data.previousBlockHash, data.currentBlockHash);
                lastKnownHeight = await getLatestCheckpointFromContract();
            } else {
                throw Error(`Failed to process height: ${lastKnownHeight}, status: ${data.status}`);
            }
        } catch (e) {
            console.error(`Failed to generate epoch proof for height ${lastKnownHeight}:`, e);
            await new Promise(f => setTimeout(f, 5000));
        }
    }
};

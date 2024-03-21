import { decode } from 'bs58';
import { ProvingTask } from './types';

export const fetchBlockByHashFromNear = async (hash: string) => {
  const response = await fetch(
    'https://compatible-light-crater.near-mainnet.quiknode.pro/332447effce5b1cec9f320e24bc52cfa62882e1a/',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'dontcare',
        method: 'block',
        params: { block_id: hash },
      }),
    },
  );
  return JSON.parse(await response.clone().text());
};

export const fetchBlockByHeightFromNear = async (height: number) => {
  const response = await fetch(
    'https://compatible-light-crater.near-mainnet.quiknode.pro/332447effce5b1cec9f320e24bc52cfa62882e1a/',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'dontcare',
        method: 'block',
        params: { block_id: height },
      }),
    },
  );
  return JSON.parse(await response.clone().text());
};

// eslint-disable-next-line
export const getProvingTask = async (block: any): Promise<ProvingTask> => {
  const prevEpochBlockHeight = block.result.header.height - 43200;
  const previousEpochBlock = await fetchBlockByHeightFromNear(prevEpochBlockHeight);

  const nextBlockHeight = block.result.header.height + 1;
  const nextBlock = await fetchBlockByHeightFromNear(nextBlockHeight);

  return {
    current_hash: block.result.header.hash,
    previous_epoch_hash: previousEpochBlock.result.header.hash,
    next_hash: nextBlock.result.header.hash,
  };
};

export const base58toHex = (hash: string): string => {
  const buffer = decode(hash);
  return Buffer.from(buffer).toString('hex');
};

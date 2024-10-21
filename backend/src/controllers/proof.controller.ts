import express, {Request, Response} from 'express';
import {prisma} from '../server';
import {sendProvingTaskToQueue} from '../nats/nats-processor';
import {fetchBlockByHashFromNear, getRandomProvingTask, selectCorrectNode} from '../near-helper';
import path from 'path';


const generateProof = async (req: Request, res: Response) => {
  try {
    const { hash } = req.body;

    const blockProof = await prisma.blockProof.findUnique({
      where: {
        hash: hash,
      },
    });

    if (blockProof && blockProof.status != 'ERROR') res.status(200).json(blockProof);
    else {
      const rpc = await selectCorrectNode(hash);

      const block = await fetchBlockByHashFromNear(rpc, hash);

      const provingTask = await getRandomProvingTask(rpc, block);

      console.log('Send proving task to nats', provingTask);

      await sendProvingTaskToQueue(provingTask);

      const proof = await prisma.blockProof.create({
        data: {
          hash: provingTask.currentBlockHash,
          height: block.result.header.height,
          previousEpochStartHash: provingTask.previousEpochStartHash,
          previousEpochEndHash: provingTask.previousEpochEndHash,
          epochId: block.result.header.epoch_id,
          timestamp: block.result.header.timestamp.toString(),
          dateCreate: Date.now().toString(),
          status: 'IN-PROCESSING',
        },
      });
      res.status(200).json(proof);
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e });
  }
};

const getProofStatus = async (req: Request, res: Response) => {
  console.log('Proof status request', req);
  try {
    const hash = req.query.hash as string;
    const blockProof = await prisma.blockProof.findUnique({
      where: {
        hash: hash,
      },
    });
    res.status(200).json(blockProof);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e });
  }
};

const getProof = async () => {
  console.log(__dirname);
  console.log(path);
  express.static(path.join(__dirname, '/app/proofs'));
};

const health = async (_: Request, res: Response) => {
  res.status(200).json({});
};

export default {
  generateProof,
  getProofStatus,
  getProof,
  health,
};

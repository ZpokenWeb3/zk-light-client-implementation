import express, { Request, Response } from 'express';
import { prisma } from '../server';
import { sendProvingTaskToQueue } from '../nats/nats-processor';
import { base58toHex, fetchBlockByHashFromNear, getProvingTask } from '../near-helper';
import path from 'path';

const generateProof = async (req: Request, res: Response) => {
  console.log('Generate proof request', req);
  try {
    const { hash } = req.body;

    // const blockProof = await prisma.blockProof.findUnique({
    //     where: {
    //         hash: hash,
    //     },
    // });
    // if (blockProof)
    //     res.status(200).json(blockProof);
    // else {
    const block = await fetchBlockByHashFromNear(hash);

    const provingTask = await getProvingTask(block);

    await sendProvingTaskToQueue(provingTask);

    const hexInput =
      base58toHex(provingTask.previous_epoch_hash) + base58toHex(provingTask.current_hash);

    const proof = await prisma.blockProof.create({
      data: {
        hash: block.result.header.hash,
        height: block.result.header.height,
        previousEpochHash: provingTask.previous_epoch_hash,
        nextBlockHash: provingTask.next_hash,
        epochId: block.result.header.epoch_id,
        timestamp: block.result.header.timestamp.toString(),
        dateCreate: Date.now().toString(),
        hexInput: hexInput,
        status: 'IN-PROCESSING',
      },
    });
    res.status(200).json(proof);
    // }
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

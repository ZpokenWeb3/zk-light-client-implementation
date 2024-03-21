import { connect, NatsConnection } from 'nats';
import { prisma } from '../server';
import { ProvingResult, ProvingTask } from '../types';
import { goApiRequest } from '../go-helper';
import { executeContractCall } from '../eth-helper';

const natsurl = process.env.NATS_URL as string;

export const sendProvingTaskToQueue = async (task: ProvingTask): Promise<void> => {
  console.log('Send proving task to nats', task);
  const nc = await connect({ servers: natsurl });
  nc.publish('PROVING_TASKS', JSON.stringify(task));
};

export const resultProcessor = async () => {
  let nc: NatsConnection;

  try {
    nc = await connect({ servers: natsurl });
  } catch (e) {
    console.error('error connects nats, try reconnect');
    await new Promise(f => setTimeout(f, 5000));
    nc = await connect({ servers: natsurl });
  }

  const sub = nc.subscribe('PROVING_RESULTS');

  await (async () => {
    for await (const msg of sub) {
      console.log(`${msg.string()} on subject ${msg.subject}`);

      const result = JSON.parse(msg.string()) as ProvingResult;

      if (result.status === 'OK') {
        await prisma.blockProof.update({
          where: {
            hash: result.current_hash,
          },
          data: {
            status: 'DONE',
          },
        });

        const blockProof = await prisma.blockProof.findUnique({
          where: {
            hash: result.current_hash,
          },
        });

        if (blockProof) {
          const response = await goApiRequest(blockProof.hexInput);
          await executeContractCall(response.inputs, response.proof);
        }
      } else {
        await prisma.blockProof.update({
          where: {
            hash: result.current_hash,
          },
          data: {
            status: 'ERROR',
          },
        });
      }
    }
  })();
};

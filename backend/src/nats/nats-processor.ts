import {connect, NatsConnection} from 'nats';
import {RandomBlockProvingResult, RandomBlockProvingTask} from '../types';
import {prisma} from "../server";
import {executeProofSaving} from "../eth-helper";

const natsurl = process.env.NATS_URL as string;

const provingResultSubject = "RANDOM_PROVING_RESULT";


export const sendProvingTaskToQueue = async (task: RandomBlockProvingTask): Promise<void> => {
    console.log('Send proving task to nats', task);
    const nc = await connect({servers: natsurl});
    const jsc = nc.jetstream();
    await jsc.publish("PROVE_RANDOM", JSON.stringify(task));
};


export const natsProcessor = async () => {
    let nc: NatsConnection;

    try {
        console.log(natsurl);
        nc = await connect({servers: natsurl});
    } catch (e) {
        console.error('error connects nats, try reconnect');
        await new Promise(f => setTimeout(f, 5000));
        nc = await connect({servers: natsurl});
    }

    const sub = nc.subscribe(provingResultSubject);

    await (async () => {
        for await (const msg of sub) {
            console.log(`${msg.string()} on subject ${msg.subject}`);
            const response = JSON.parse(msg.string()) as RandomBlockProvingResult;
            if (response.status === 'OK') {
                const blockProof = await prisma.blockProof.findUnique({
                    where: {
                        hash: response.currentBlockHash,
                    },
                });

                try {
                    if (blockProof) {
                        console.log("Execute contract call");
                        await executeProofSaving(response.journal, response.proof);

                        console.log('Update DB');
                        await prisma.blockProof.update({
                            where: {
                                hash: response.currentBlockHash,
                            },
                            data: {
                                status: 'DONE',
                            },
                        });
                    }
                } catch (error) {
                    await prisma.blockProof.update({
                        where: {
                            hash: response.currentBlockHash,
                        },
                        data: {
                            status: 'ERROR',
                        },
                    });
                    console.error("Error executing proof saving or updating database:", error);
                }

            } else {
                console.log("STATUS ERROR");
                await prisma.blockProof.update({
                    where: {
                        hash: response.currentBlockHash,
                    },
                    data: {
                        status: 'ERROR',
                    },
                });
            }
        }
    })();
};

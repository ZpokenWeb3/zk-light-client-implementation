import express, {Request, Response} from 'express';
import {PrismaClient} from '@prisma/client';
import ProofRouter from './routes/proof.route';
import {natsProcessor} from './nats/nats-processor';
import axios from "axios";
import {epochProcessor} from "./epoch/epoch-processor";

export const prisma = new PrismaClient();

export const app = express();
const port = 9024;

export const serverUrl: string = process.env.SERVER_URL || 'http://127.0.0.1:1337';

async function main() {
    require('log-timestamp');

    app.use(express.json());

    // Register API routes
    app.use('/', ProofRouter);

    // Catch unregistered routes
    app.all('*', (req: Request, res: Response) => {
        res.status(404).json({error: `Route ${req.originalUrl} not found`});
    });

    app.listen(port, () => {
        console.log(`Server is listening on port ${port}`);
    });
}

main()
    .then(async () => {
        await prisma.$connect();
    })
    .catch(async e => {
        console.error(e);
        await prisma.$disconnect();
        process.exit(1);
    })
    .then(async () => {
        const response = await axios.get(`${serverUrl}/health`);
        if (response.status === 200) {
            console.log('Health check successful');
        }
    })
    .catch(async e => {
        console.error('Failed to connect to epoch proving server', e);
        await prisma.$disconnect();
        process.exit(1);
    })
    .then(async () => {
        await Promise.all([
            natsProcessor(),
            epochProcessor(),
        ]);
    })
    .catch(async e => {
        console.error(e);
        await prisma.$disconnect();
        process.exit(1);
    });

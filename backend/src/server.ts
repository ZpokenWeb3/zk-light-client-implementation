import express, {Request, Response} from "express";
import {PrismaClient} from "@prisma/client";
import ProofRouter from "./routes/proof.route";
import {resultProcessor} from "./nats/nats-processor";

export const prisma = new PrismaClient();

export const app = express();
const port = 9024;
async function main() {
    app.use(express.json());

    // Register API routes
    app.use("/", ProofRouter);

    // Catch unregistered routes
    app.all("*", (req: Request, res: Response) => {
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
    .catch(async (e) => {
        console.error(e);
        await prisma.$disconnect();
        process.exit(1);
    })
    .then(async () => {
        await resultProcessor();
    }).catch(async (e) => {
        console.error(e);
        await prisma.$disconnect();
        process.exit(1);
    }
);



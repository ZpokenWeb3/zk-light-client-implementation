import * as dotenv from 'dotenv';
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-foundry";
import * as fs from "node:fs";
import {HardhatUserConfig} from "hardhat/config";

dotenv.config();

function getRemappings() {
    return fs
        .readFileSync("remappings.txt", "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => line.trim().split("="));
}

const config: HardhatUserConfig = {
    solidity: {
        compilers: [
            {
                version: '0.8.20',
                settings: {
                    optimizer: {
                        enabled: true,
                        runs: 200,
                    }
                },
            },
        ],
    },
    networks: {
        hardhat: {
            allowUnlimitedContractSize: true,
        },
        localhost: {
            url: 'http://127.0.0.1:8545',
            accounts: process.env.PRIVATE_KEY !== undefined ? [process.env.PRIVATE_KEY] : [],
        },
        goerli: {
            url: 'https://gateway.tenderly.co/public/goerli',
            accounts: process.env.PRIVATE_KEY !== undefined ? [process.env.PRIVATE_KEY] : [],
        },
        sepolia: {
            url: 'https://ethereum-sepolia-rpc.publicnode.com',
            accounts: process.env.PRIVATE_KEY !== undefined ? [process.env.PRIVATE_KEY] : [],
        },
    },
    paths: {
        sources: 'src/',
        cache: './cache',
    },
    // This fully resolves paths for imports in the ./lib directory for Hardhat
    preprocess: {
        eachLine: (hre: any) => ({
            transform: (line: string) => {
                hre;
                if (line.match(/^\s*import /i)) {
                    getRemappings().forEach(([find, replace]) => {
                        if (line.match(find)) {
                            line = line.replace(find, replace);
                        }
                    });
                }
                return line;
            },
        }),
    },
};

export default config;

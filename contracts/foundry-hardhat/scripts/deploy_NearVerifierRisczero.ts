import {ethers} from "hardhat";
import fs from "node:fs";

const solidityFile = 'src/ImageID.sol';
const solidityCode = fs.readFileSync(solidityFile, 'utf-8');

const regex = /bytes32 public constant NEAR_RISC0_ID = bytes32\((0x[a-fA-F0-9]+)\);/;
const match = solidityCode.match(regex);


async function main() {
    const verifierAddress = process.env.VERIFIER;

    if (match && match[1]) {
        const NearBlockVerification = await ethers.getContractFactory("NearVerifierRiscZero");
        const nearBlockVerification = await NearBlockVerification.deploy();
        await nearBlockVerification.deployed();
        const imageID = match[1];
        await nearBlockVerification.initialize(
            verifierAddress,
            130391511,
            "0x73f57091dc6fcf2b1b1d625159a62124cf9ad3d5e7bd68ff34a1f6f006181ce9",
            "0xbebfe9266137934094d71f93f6d534ec2378ecca95a0010437a6e3e5816b94fb",
            imageID
        );

        console.log("NearVerifierRiscZero deployed to:", nearBlockVerification.address);
    }  else {
        console.error("Image ID not found in the Solidity file. Build Risc Zero project or change path to ImageID.sol");
    }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
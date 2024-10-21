import {ethers} from "hardhat";

require('dotenv').config();


async function main() {
    const RiscZeroGroth16VerifierFactory = await ethers.getContractFactory("RiscZeroGroth16Verifier");
    const CONTROL_ROOT = "0x8b6dcf11d463ac455361b41fb3ed053febb817491bdea00fdb340e45013b852e";
    const BN254_CONTROL_ID = "0x05a022e1db38457fb510bc347b30eb8f8cf3eda95587653d0eac19e1f10d164e";
    const verifier = await RiscZeroGroth16VerifierFactory.deploy(CONTROL_ROOT, BN254_CONTROL_ID);
    await verifier.deployed();

    console.log("RiscZeroGroth16Verifier deployed to:", verifier.address);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
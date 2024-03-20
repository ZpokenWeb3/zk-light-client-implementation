import { ethers } from "hardhat";
import * as crypto from 'crypto';
require('dotenv').config();

const fs = require('fs');
const delay = ms => new Promise(res => setTimeout(res, ms));

function secondHash(array: number[]): string {
    let numbers: number[] = array.slice(2, 4).map(value => BigInt(value));
    let hexString: string = numbers.map(value => value.toString(16)).join('');
    return '0x' + hexString;
}

async function main() {
  let path = process.env.PROOF_PATH;

  let fileData = fs.readFileSync(path, 'utf-8');
  let dataParsed = JSON.parse(fileData);
  let inputs = dataParsed.inputs;
  let proof = dataParsed.proof;

  const verifierAddress = process.env.VERIFIER;
  const verifierFactory = await ethers.getContractFactory("Verifier");  
  let verifier = await verifierFactory.attach(verifierAddress);

  const nearBlockVerificationAddress = process.env.NEAR_BLOCK_VERIFIATION;
  const nearBlockVerificationFactory = await ethers.getContractFactory("NearBlockVerification");  
  let nearBlockVerification = await nearBlockVerificationFactory.attach(nearBlockVerificationAddress);

  let compressedProof = await verifier.compressProof(proof);
  await nearBlockVerification.verifyAndSaveCompressedProof(inputs, compressedProof);

  await delay(1000);

  let hash = secondHash(inputs);
  console.log("hash: ", hash);
  let result = await nearBlockVerification.isProofedHash(hash);
  console.log("nearBlockVerification.isProofedHash: ", result);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

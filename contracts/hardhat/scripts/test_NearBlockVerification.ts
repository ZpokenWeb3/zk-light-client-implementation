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
  let path = process.env.PROOF_PATH; // 'test/proof_with_witness.json'
//   console.log("path:", path);

  let fileData = fs.readFileSync(path, 'utf-8');
  let dataParsed = JSON.parse(fileData);
  let inputs = dataParsed.inputs;
  let proof = dataParsed.proof;

//   console.log("inputs: ", inputs);
//   console.log("proof:", proof);

  const verifierAddress = process.env.VERIFIER;
  const verifierFactory = await ethers.getContractFactory("Verifier");  
  let verifier = await verifierFactory.attach(verifierAddress);

  const nearBlockVerificationAddress = process.env.NEAR_BLOCK_VERIFIATION;
  const nearBlockVerificationFactory = await ethers.getContractFactory("NearBlockVerification");  
  let nearBlockVerification = await nearBlockVerificationFactory.attach(nearBlockVerificationAddress);

  await nearBlockVerification.verifyAndSaveProof(inputs, proof);

  await delay(20000);

  let result = await nearBlockVerification.isProofed(inputs.slice(2, 4));
  console.log("nearBlockVerification.isProofed: ", result);

  let hash = secondHash(inputs);
  console.log("hash: ", hash);
  result = await nearBlockVerification.isProofedHash(hash);
  console.log("nearBlockVerification.isProofedHash: ", result);

  let compressedProof = await verifier.compressProof(proof);
  await nearBlockVerification.verifyAndSaveCompressedProof(inputs, compressedProof);

  await delay(20000);

  console.log("Successfully completed!!");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

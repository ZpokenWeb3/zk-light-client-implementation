import { ethers } from "hardhat";
import * as crypto from 'crypto';
require('dotenv').config();

const fs = require('fs');

async function main() {
  const verifierAddress = process.env.VERIFIER;
//   console.log("verifierAddress:", verifierAddress);

  let path = process.env.PROOF_PATH; // 'test/proof_with_witness.json'
//   console.log("path:", path);

  let fileData = fs.readFileSync(path, 'utf-8');
  let dataParsed = JSON.parse(fileData);
  let inputs = dataParsed.inputs;
  let proof = dataParsed.proof;

//   console.log("inputs: ", inputs);
//   console.log("proof:", proof);

  const verifierFactory = await ethers.getContractFactory("Verifier");  
  let verifier = await verifierFactory.attach(verifierAddress);

  await verifier.verifyProof(proof, inputs);

  let compressedProof = await verifier.compressProof(proof)
  await verifier.verifyCompressedProof(compressedProof, inputs);

  console.log("Successfully completed!!");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

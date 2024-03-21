import { ethers } from "hardhat";
import * as crypto from 'crypto';
require('dotenv').config();

const delay = ms => new Promise(res => setTimeout(res, ms));

async function main() {
  const Verifier = await ethers.getContractFactory("Verifier");
  const newVerifier = await Verifier.deploy();
  await newVerifier.deployed();

  console.log("Verifier deployed to:", newVerifier.address);

  const nearBlockVerificationAddress = process.env.NEAR_BLOCK_VERIFIATION;
  const nearBlockVerificationFactory = await ethers.getContractFactory("NearBlockVerification");  
  let nearBlockVerification = await nearBlockVerificationFactory.attach(nearBlockVerificationAddress);

  await nearBlockVerification.setVerifier(newVerifier.address);

  await delay(3000);

  let result = await nearBlockVerification.getVerifier();
  console.log("nearBlockVerification.getVerifier(): ", result);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

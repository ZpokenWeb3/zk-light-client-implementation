import { ethers } from "hardhat";
import * as crypto from 'crypto';
require('dotenv').config();

const delay = ms => new Promise(res => setTimeout(res, ms));

async function main() {
  const nearBlockVerificationAddress = process.env.NEAR_BLOCK_VERIFIATION;
  const nearBlockVerificationFactory = await ethers.getContractFactory("NearBlockVerification");  
  let nearBlockVerification = await nearBlockVerificationFactory.attach(nearBlockVerificationAddress);

  if (await nearBlockVerification.paused()) {
    await nearBlockVerification.unpause();
    await delay(3000);
  }

  let result = await nearBlockVerification.paused();
  console.log("nearBlockVerification.paused(): ", result);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

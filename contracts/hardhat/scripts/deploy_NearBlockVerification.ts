import { ethers } from "hardhat";
require('dotenv').config();

async function main() {
  const verifierAddress = process.env.VERIFIER;

  const NearBlockVerification = await ethers.getContractFactory("NearBlockVerification");
  const nearBlockVerification = await NearBlockVerification.deploy();
  await nearBlockVerification.deployed();
  await nearBlockVerification.initialize(verifierAddress);

  console.log("NearBlockVerification deployed to:", nearBlockVerification.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

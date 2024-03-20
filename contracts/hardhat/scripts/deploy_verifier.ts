import { ethers } from "hardhat";
require('dotenv').config();

async function main() {
  const Verifier = await ethers.getContractFactory("Verifier");
  const verifier = await Verifier.deploy();

  await verifier.deployed();

  console.log("Verifier deployed to:", verifier.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

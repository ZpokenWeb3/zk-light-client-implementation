# Near light client implementation with ZKVM

## Prerequisites
Ensure you have the following tools installed:
* Node.js (with Yarn)
* Docker
* Rust
* Hardhat


## Quick Start

Make sure [rustup] is installed. The
[`rust-toolchain.toml`][rust-toolchain] file will be used by `cargo` to
automatically install the correct version.

To build all methods and execute the method within the zkVM, run the following
command:

```bash
cargo build --release 
```
**Start the Hardhat Node or use Ethereum chains**

To start local node:
```
yarn hardhat node
```
**Start nats server**

Run the NATS server using Docker with the following command:
```
docker run --name nats --network nats --rm -p 4222:4222 -p 8222:8222 nats --http_port 8222 --js
```
**Build the Risc0 Project**
   
Before deploying, make sure to build the Risc0 project. Then, if needed, deploy the RiscZeroGroth16Verifier and NearBlockVerifier.

**Export your private key**

Set your private key in the environment variable:
```
export PRIVATE_KEY=<your_private_key_here>
```
**Deploy the Verifiers**

Run the deployment script for the RiscZeroGroth16Verifier:
```
npx hardhat run --network localhost scripts/deploy_RiscZeroGroth16Verifier.ts
```
You should see an output similar to:
```
Compiled 39 Solidity files successfully (evm target: paris).
RiscZeroGroth16Verifier deployed to: 0x73511669fd4dE447feD18BB79bAFeAC93aB7F31f
```
Set the deployed verifier address in the environment variable:
```
export VERIFIER=0x73511669fd4dE447feD18BB79bAFeAC93aB7F31f
```
Run the deployment script for the NearVerifierRisc0:
```
npx hardhat run --network localhost scripts/deploy_NearVerifierRisczero.ts
```
Set the NEAR_BLOCK_VERIFIER_CONTRACT environment variable (update with your contract address):

```
export NEAR_BLOCK_VERIFIER_CONTRACT=<your_near_block_verifier_contract_address>
```

**Start the Proving Services**

Start the proving server for Epoch proving with the following command:
```
RUST_LOG=info cargo run --release --bin proving_server --features cuda
```
Run the proving service for Random blocks with the following command:
```
RUST_LOG=info cargo run --release --bin random_service --features cuda
```

**Start Backend server for handling connection with contract**
To start the application, run:
```
yarn start
```

**Await Proving Epochs.** 

Generating a number of epochal proofs requires approximately 10 minutes for every 3 epochs.
The starting height for deployed contract is 130391511, you can see in deployment scripts.

**Send proving request to prove random Block**

To send a block for proof generation, use the following curl command:
```
curl -X POST http://127.0.0.1:9024/generate-proof \
     -H "Content-Type: application/json" \
     -d '{
           "hash": "21KvQHi3aTTDk8vXjbRJ8HuPkiyVTywfgARjbMu5aUV4"
         }'
```
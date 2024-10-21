# Getting Started

## Table of contents
<!--ts-->

* [Hardware requirments](#hardware-requirments)
* [HTTP API Service](#http-api-service)
    * [Endpoints](#endpoints)
    * [Implementation Details](#implementation-details)
* [Deploy](#deploy)
    * [Local deploy](#local-deploy)
    * [Cluster deploy](#cluster-deploy)
<!--te-->

## Hardware requirments

|Component|RAM | Disk space | Description|
|--|--|--|--|
| Nats | 20Mb | 20 Mb | Used as a queue for fair block processing order when multiple concurrent proof requests are received. And it is also used to distribute tasks between Signature Prover services.
| HTTP Service | 200 Mb | 1.6 Gb | Service for creating block proof requests, tracking the proof process status and getting proof results via HTTP API.
| Gnark Wrapper Service | 32 Gb | 45 Gb | Provides a simple API for wrapping plonky2 proofs in GNARK.
| Block Prover Service | 8 Gb | 150 Mb | Service for generating Plonky2 proofs for Near blockchain blocks.
| Signature Prover Service | 18 Gb | 90 Mb | Service for generating proofs of the validator's signatures.

## HTTP API Service

### Implementation Details

-   The service uses `Express.js` for handling HTTP requests and responses.
-   The POST `/generate-proof` endpoint processes the block hash, fetches the corresponding block, generates a proving task, and sends it to the proving task queue.
-   The GET `/proof-status` endpoint queries the status of the proof generation process based on the provided block hash.
-   The service interacts with NEAR RPC to fetch block information and with a NATS-based queue system to handle proof generation tasks asynchronously.
-   The use of Prisma ORM facilitates database interactions, particularly for tracking the status of a proof.

### Endpoints

__POST /generate-proof__

This endpoint initiates the proof generation process for a given block hash.

- **URL:** `/generate-proof`
- **Method:** `POST`
- **Body Parameters:**
  - `hash`: The hash of the block for which the proof needs to be generated.
- **Success Response:**
  - **Code:** 200 OK
  - **Content:** Returns a JSON object containing the proof details, including the status of the proof generation process.
- **Error Response:**
  - **Code:** 500 Internal Server Error
  - **Content:** Returns an error message indicating the failure of the proof generation process.
- **Sample Call:**
  ```bash
  curl --location 'https://api-zk-block-prover.zpoken.dev/generate-proof' \
  --header 'Content-Type: application/json' \
  --data '{
      "hash": "GFmJo59ijD2RaYWhFuwUXq1JNk2iRrNzojJPcTBwdUbF"
  }'
  ```

__GET /proof-status__

This endpoint retrieves the status of a previously requested proof generation task.

-   **URL:** `/proof-status`
-   **Method:** `GET`
-   **URL Parameters:**
    -   `hash`: The hash of the block for which the proof status is being queried.
-   **Success Response:**
    -   **Code:** 200 OK
    -   **Content:** Returns a JSON object containing the status of the requested proof.
-   **Error Response:**
    -   **Code:** 500 Internal Server Error
    -   **Content:** Returns an error message indicating the failure to retrieve the proof status.
- **Sample Call:**
  ```bash
  curl --location 'http://localhost:9024/proof-status?hash=584idunzJeg9s33CFCipnPYM7H2cUkAz1xvwyemzaXNF'
  ```

### Local Deploy
#### Docker compose

 1. Clone repo:
 ```bash
git clone https://github.com/wormhole-foundation/example-zk-light-clients.git
```
 2. Change directory:
 ```bash
 cd ./example-zk-light-clients/near/
 ```
 3. Pull docker images:
 ```bash
 docker compose pull
 ```
 4. Set url to nats server & your Ethereum private key for `http_service`:
 ```bash
 export NATS_URL=nats://127.0.0.1:4222
 export PRIVATE_KEY=9c6293889cac472edd54fc057cc47999a1d9c9c42a009731908a2a821a3ec5da
 ```
5. Set verifier contract address and rpc urls for near and sepolia testnet
```bash
export NEAR_BLOCK_VERIFIER_CONTRACT=0xce5845372e615Cbb46EFCc76c21051932BD8A717
export SEPOLIA_RPC=https://rpc2.sepolia.org
export NEAR_RPC=https://rpc.mainnet.near.org
```
6. Run applications:
 ```bash
 docker compose up -d
 ```

### Cluster deploy
#### Docker swarm

1. Clone repo:
 ```bash
git clone https://github.com/wormhole-foundation/example-zk-light-clients.git
```
 2. Change directory:
 ```bash
 cd ./example-zk-light-clients/near/
 ```
 3. Init docker swarm:
 ```bash
docker swarm init --advertise-addr <management_node_ip>
 ```
 4. Join other nodes to docker swarm using command in output of previous step:
 ```bash
 docker swarm join --token <token> <management_node_ip>:2377
 ```
 5. Change the value of the `replicas` parameter in `docker-stack.yml` for `sign_prover` service to 2 replicas per worker node not considering the management node.
 6. Set url to nats server & your Etherium private key for `http_service`:
 ```bash
 export NATS_URL=nats://127.0.0.1:4222
 export PRIVATE_KEY=9c6293889cac472edd54fc057cc47999a1d9c9c42a009731908a2a821a3ec5da
 ```
 7. Set verifier contract address and rpc urls for near and sepolia testnet
```bash
export NEAR_BLOCK_VERIFIER_CONTRACT=0xce5845372e615Cbb46EFCc76c21051932BD8A717
export SEPOLIA_RPC=https://rpc2.sepolia.org
export NEAR_RPC=https://rpc.mainnet.near.org
```
 8. Deploy stack
 ```bash
docker stack deploy --compose-file docker-stack.yml zk-lite-client
 ```

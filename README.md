# Example Trustless NEAR Light Client Implementation

## Overview

An implementation of a trustless NEAR light client (LC) in plonky2(https://github.com/0xPolygonZero/plonky2). Proves the finality of a block based on the existing final block of the previous epoch.

### Block Integrity and Finality Proof

1. **Operating Fields**: The NEAR zk-light-client operates on several critical fields within the blockchain ecosystem. These fields include the validators, the `next_bp_hash` (next block producers' hash), and the block hash itself.

2. **Formation of `next_bp_hash`**: The `next_bp_hash` is a crucial component in this process. It is derived from the set of validators responsible for producing the next block. This hash serves as a cryptographic representation of the validators' identity and their role in the upcoming block production.

3. **Calculation of the block hash**: The block hash is then calculated based on the data of the current block. This data includes the `next_bp_hash`. By incorporating the `next_bp_hash` into the block hash calculation, there is a direct cryptographic link between the validators of the next block and the current block's integrity.

4. **Core Idea**: The core idea is to establish a traceable and verifiable chain of custody for block creation. By proving that the `next_bp_hash` (derived from the validators) is a part of the current block's data, which in turn is used to calculate the block's hash, a secure chain is formed. This chain ensures that each block is not only a product of its immediate data but also carries a cryptographic signature of its contextual environment, i.e., the validators for the next block.Therefore, verifying a block's authenticity involves confirming that the set of validators is valid (thus legitimizing the `next_bp_hash`) and ensuring that the block hash is correctly derived from the data, including this `next_bp_hash`.

```
defined set of validators ======> defined next_bp_hash ======> defined block hash
```

<!-- ![Illustrative scheme](/schemes/Illustrative_scheme.png) -->

<figure>
  <img src="/schemes/Illustrative_scheme.png" alt="Architecture Diagram">
  <figcaption>Figure: Illustrative Scheme for Block Proving.</figcaption>
</figure>

### Input parameters for proof generation
1. Block for which the proof is generated `(epoch N)` [Example](https://github.com/ZpokenWeb3/zk-light-client-implementation/blob/main/script/data/block-A6Gcz5uXxyTrigefyr48AXwag6gB7D6txzPSR3jBqqg2/block_header.json)

2. Block of the previous epoch `(epoch N-1)` [Example](https://github.com/ZpokenWeb3/zk-light-client-implementation/blob/main/script/data/block-A6Gcz5uXxyTrigefyr48AXwag6gB7D6txzPSR3jBqqg2/block_header.json)

3. List of block producers for `epoch N ` [Example](https://github.com/ZpokenWeb3/zk-light-client-implementation/blob/main/script/data/block-A6Gcz5uXxyTrigefyr48AXwag6gB7D6txzPSR3jBqqg2/validators_ordered.json)


## Near State Proofs

- Proof of Inclusion for the NEAR Blockchain involves identifying a specific data slot in a smart contract and verifying its contents.
- Upon any data mutation, a Merkle tree is constructed using code from the NEAR core, ensuring the data's integrity.
- This process confirms the accuracy of the data in the slot and checks that the corresponding Merkle root is recorded in the blockchain.
- The result of this verification is typically formatted to display key information like the data's key, value, state root, and associated block hash.
- This ensures the data's validity and its presence in a specific blockchain state.

> [!TIP]
> Read the example here [NEAR_STATE_PROOFS.md](/near_state_proofs/NEAR_STATE_PROOFS.md)

Developed by [Zpoken Cryptography Team](https://zpoken.io/)

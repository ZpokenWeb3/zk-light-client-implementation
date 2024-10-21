# NEAR Light Client Implementation

Developed by [Zpoken Cryptography Team](https://zpoken.io/)

## Overview

An implementation of a trustless NEAR Light Client (LC) aims to prove computational integrity (CI) of a chosen block, ensuring its full finality (BFT finality). The idea is to first prove the finality (BFT finality) of a chosen block by proving the finality of successive blocks. Then, if a block is final, prove the computational integrity of its data. 

According to the [protocol](https://nomicon.io/ChainSpec/Consensus#finality-condition), the scheme needs at least three blocks with successive heights to achieve finality of the leading block in this triple. In other words, it needs blocks: `Block_0` (block to be proven, BFT finality), `Block_i+1` (Doomslug finality), `Block_i+2`.

The scheme takes five blocks, instead: 
- `Block_i` (block to be proven, BFT finality);
- `Block_i+1` (BFT finality);
- `Block_i+2` (BFT finality);
- `Block_i+3` (Doomslug finality);
- `Block_i+4`. 

The scheme proves block finality of `Block_i+2`, if the heights of `Block_i+2`, `Block_i+3` and `Block_i+4` are consecutive. `Block_i` automatically becomes final, and its signatures can be safely extracted from `Block_i+1`. Then the CI of the required `Block_i` can then be proven.

Additionally, we provide two more blocks: 
- `Block_n-1`, i.e. the last block of the epoch *i-2*, to prove `epoch_id`;
- `Block_0`, i.e. the first block of the epoch *i-1*, to prove the correspondence of the used list of validators for the current epoch with the field `next_bp_hash` if the `Block_0`. 

### Block Integrity and Finality Proof

1. **Operational fields**: NEAR zk-light-client operates on several critical fields in the blockchain ecosystem. These fields include the list of validators, `next_bp_hash` (the hash of the next block producers) from epoch *i-1*, the hash of the last block from epoch *i-2* to confirm `epoch_id`, and a set of hashes and heights of five consecutive blocks including the required `Block_i` to prove.

2. **Formation of `next_bp_hash`**: The `next_bp_hash` is a crucial component in this process. It is derived from the set of validators responsible for producing the next block. This hash serves as a cryptographic representation of the validators' identity and their role in the upcoming block production.

3. **Calculation of the block hash**: The block hash is calculated based on the data of the current block. This data includes the `next_bp_hash`. By incorporating the `next_bp_hash` into the block hash calculation, there is a direct cryptographic link between the validators of the next block and the current block's integrity.

4. **Core Idea**: The core idea is to establish a traceable and verifiable chain of custody for block creation. By proving that the `next_bp_hash` (derived from the validators) is a part of the current block's data, which in turn is used to calculate the block's hash, a secure chain is formed. This chain ensures that each block is not only a product of its immediate data but also carries a cryptographic signature of its contextual environment, i.e. the validators for the next block.Therefore, verifying a block's authenticity involves confirming that the set of validators is valid (thus legitimizing the `next_bp_hash`) and ensuring that the block hash is correctly derived from the data, including this `next_bp_hash`.

> [!TIP]
> Scheme description: [Scheme_overview.md](/near/near_bft_finality/Scheme_overview.md)

### Input parameters for proof generation
1. A set of five consecutive blocks including the required `Block_i` to prove epoch *i* [Example](/near/script/data/block-A6Gcz5uXxyTrigefyr48AXwag6gB7D6txzPSR3jBqqg2/block_header.json)

2. *Epoch blocks* `Block_n-1` from epoch *i-2* and `Block_0` from epoch *i-1*. [Example](/near/script/data/block-A6Gcz5uXxyTrigefyr48AXwag6gB7D6txzPSR3jBqqg2/block_header.json)

3. List of block producers for  epoch *i* [Example](/near/script/data/block-A6Gcz5uXxyTrigefyr48AXwag6gB7D6txzPSR3jBqqg2/validators_ordered.json)

## Near State Proofs

- Proof of Inclusion for the NEAR Blockchain involves identifying a specific data slot in a smart contract and verifying its contents.
- Upon any data mutation, a Merkle tree is constructed using code from the NEAR core, ensuring the data's integrity.
- This process confirms the accuracy of the data in the slot and checks that the corresponding Merkle root is recorded in the blockchain.
- The result of this verification is typically formatted to display key information like the data's key, value, state root, and associated block hash.
- This ensures the data's validity and its presence in a specific blockchain state.

> [!TIP]
> Read the example here [NEAR_STATE_PROOFS.md](/near/near_state_proofs/NEAR_STATE_PROOFS.md)
> Getting started [Getting-started.md](/near/near_bft_finality/Getting-started.md)
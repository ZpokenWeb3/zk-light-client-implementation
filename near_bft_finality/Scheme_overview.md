An implementation of a trustless NEAR Light Client (LC) aims to prove computational integrity (CI) of a chosen block, ensuring its full finality (BFT finality). 

*The implementation is based on the [Plonky2](https://github.com/0xPolygonZero/plonky2/tree/main) framework developed by Polygon Zero, [ed25519](https://github.com/polymerdao/plonky2-ed25519) scheme developed by PolymerDAO and [SHA-256](https://github.com/JumpCrypto/plonky2-crypto/tree/main/src) implemented by Jump Crypto.*

The idea is to first prove the finality (BFT finality) of a chosen block by proving the finality of successive blocks. Then, if a block is final, prove the computational integrity of its data. According to the [protocol](https://nomicon.io/ChainSpec/Consensus#finality-condition), the scheme needs at least three blocks: `Block_0`, `Block_i+1`, `Block_i+2`, with successive heights to achieve finality of the leading block in this triple.

The scheme takes five blocks, instead: `Block_i` (block to be proven, BFT finality), `Block_i+1` (BFT finality), `Block_i+2` (BFT finality), `Block_i+3` (Doomslug finality), `Block_i+4`. The scheme ensures block finality of `Block_i+2`, if heights of `Block_i+2`, `Block_i+3` and `Block_i+4` are consecutive. `Block_i` automatically becomes final, and its signatures can be safely extracted from `Block_i+1`. Then the computational integrity of the required `Block_i` can then be proven. 

![Chain of blocks that is used to prove BFT and CI of Block_i](/near/schemes/1_Chain_CI_of_Block_i.png)
*Fig. 1 – Chain of blocks that is used to prove BFT and CI of `Block_i`*

*Finality.* Once `Block_i+2` has achieved finality, it could not be reverted. However, there could be forks from this block as it is shown in the picture above. The feature *finality* does not claim that this block is always going to be final, but it guarantees that it will be included in any fork. It is possible that  `Block_i+3` & `Block_i+4` will be reverted with another fork, for instance, `Block_i+3’` & `Block_i+4’`, but the height of `Block_i+3’` will be less then the height of the initial `Block_i+3`. Otherwise, that would mean that >⅔ block producers endorsed skip (due to `Block_i+3’` being valid), and >⅔ block producers voted for Skip(`Block_i+2`, `Block_i+3’`) due to `Block_i+3’` being valid, but that means >⅓ validators did [conflicting skip and endorsement](https://nomicon.io/ChainSpec/Consensus).

Thus, the proof of consecutive heights from `Block_i+2`, `Block_i+3` and `Block_i+4` ensures that `Block_i+2` is final and can be used to extract signatures from it to prove BFT of `Block_i+1` & `Block_i`.

Additionally, we take two more blocks: 
- `Block_n-1`, i.e. the last block of the epoch *i-2*, to prove `epoch_id`;
- `Block_0`, i.e. the first block of the epoch *i-1*, to prove the correspondence of the used list of validators for the current epoch with the field `next_bp_hash` if the `Block_0`. 

Unlike `Block_i`, `Block_i+1`, `Block_i+2`, etc., whose block bodies and hashes are loaded from RCP, the block bodies of `Block_n-1` and `Block_0` are loaded from RPC, but their hashes are stored in the smart-contract to ensure the validity of the provided hashes. In this case, `Block_n-1` and `Block_0` have to be proved and verified in advance so that their hashes can be stored and used later. Since proving the integrity of a block's hash first requires proving the finality of that block, the finality scheme described below applies to both proving a randomly selected block and proving *epoch blocks*, i.e. `Block_n-1` and `Block_0`.

![Used data in proving scheme](/near/schemes/2_Used_data_in_proving_scheme.png)
*Fig. 2 – Used data in proving scheme*

We make two chains: *epoch blocks* and *ordinary blocks*.

*Epoch blocks* represent the first block from epoch *i* and the last block from epoch *i-1*. This case validates hashes for *trusted points*, that are stored in smart-contract and could be further used while proving `epoch_id` & `next_bp_hash` fields. Since these blocks are also loaded from RCP, their BFT finality also needs to be proven. In this case, proving algorithm takes:
- `Block_n-1` from epoch *i-1*,  `Block_0`, `Block_1`, `Block_2`, `Block_3`, `Block_4` from epoch *i*;
- `Block_0` (epoch *i-1*) to extract `next_bp_hash` for `Block_0`;
- `Block_n-1` (epoch *i-2*) to prove `epoch_id` for `Block_0` and `next_bp_hash` for `Block_n-1`;
- `Block_n-1` (epoch *i-3*) to prove `epoch_id` for `Block_n-1`. 
It proves BFT finality and computational integrity of `Block_n-1`, `Block_0` and store their hashes in smart-contract.

*Ordinary blocks* represent a randomly selected `Block_i` and four more blocks to ensure BFT finality of the chosen block. The proving algorithm takes:
- `Block_i`, `Block_i+1`, `Block_i+2`, `Block_i+3`, `Block_i+4` from epoch *i*;
- `Block_n-1` (epoch *i-2*) and its hash from smart-contract to prove `epoch_id`;
- `Block_0` (epoch *i-1*) and its hash from smart-contract to extract `next_bp_hash`.
And it proves computational integrity of `Block_i`.

To make the system work we set four hashes as valid in smart-contract without proving them: `Block_n-1` (epoch *0*), `Block_0` & `Block_n-1` (epoch *1*), `Block_0` (epoch *2*). These hashes are so-called *genesis hashes*. We assume them to be trusted by all participants in the network. Then, it possible to prove randomly selected blocks starting from epoch *2* and prove *epoch blocks* starting from epochs *⅔*, i.e. `Block_n-1` (epoch *2*) and `Block_0` (epoch *3*).

![Trusred points & proofs](/near/schemes/3_Trusted_proofs.png)
*Fig. 3 – Trusred points & proofs*

> [!TIP]
> BFT: [BFT.md](/near/near_bft_finality/BFT.md)

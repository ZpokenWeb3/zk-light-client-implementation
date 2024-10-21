The idea is to first prove the finality (BFT finality) of a chosen block by proving the finality of successive blocks. The scheme takes five consecutive blocks: `Block_i` (block to be proven, BFT finality), `Block_i+1` (BFT finality), `Block_i+2` (BFT finality), `Block_i+3` (Doomslug finality), `Block_i+4`, and two *epoch blocks*: `Block_n-1` and `Block_0`. The scheme ensures block finality of `Block_i+2`, if heights of `Block_i+2`, `Block_i+3` and `Block_i+4` are consecutive. `Block_i` automatically becomes final, and its signatures can be safely extracted from `Block_i+1`. Then the computational integrity of the required `Block_i` can then be proven. 

*Proof_Block_n-1_Epoch_i-2.* We prove the hash of the block using block data from rpc & hash from smart-contract to ensure the validity of the provided hash. We set this hash as public inputs (PI) to prove later the correspondence of the hash and the `epoch_id` field. 

The output is `Proof_Block_n-1_Epoch_i-2` with the `hash` of this block as its PI. 

*Proof_Block_0_Epoch_i-1.* We prove the hash of the previous epoch block using block data from rpc & hash from smart-contract to ensure the validity of the hash provided. We set `hash` & `next_bp_hash` as PI to prove later the correspondence of the hashed list of validators to the hash in the field `next_bp_hash`. 

The output is `Proof_Block_0_Epoch_i-1` with the `hash` of this block & `next_bp_hash` as its PI. 

*Proof_Block_i+4 (Epoch_i).* To prove that the block `Block_i+4` exists we prove its hash with and set its `hash`, `epoch_id`, `height`, `prev_hash` as public inputs. 

The output is `Proof_Block_i+4` with PI. 

*Proof_Block_i+3 (Epoch_i).* To prove that the block `Block_i+3` exists we prove its hash with and set its `hash`, `epoch_id`, `height`, `prev_hash` as public inputs. 

The output is `Proof_Block_i+3` with PI. 

*Proof_Block_i+2 (Epoch_i).* To prove that the block `Block_i+2` exists we prove its hash with and set its `hash`, `epoch_id`, `height`, `prev_hash`, `last_ds_final_block` & `last_final_block` as public inputs. 

After this step the scheme proves consecutive heights of `Block_i+4`, `Block_i+3` & `Block_i+2` and aggregates this proof with the proof for the header of `Block_i+2`.

The output is `Proof_Block_i+2` with PI: `hash`, `epoch_id`, `height`, `prev_hash`, `last_ds_final_block` & `last_final_block`. 

*Proof_Block_i+1 (Epoch_i).* To prove that the block `Block_i+1` exists we prove its hash with and set its `hash`, `epoch_id`, `height`, `prev_hash`, `last_ds_final_block` & `last_final_block` as public inputs. 

The scheme then creates proofs for the `Block_i` and `Block_i+1` headers (or `Block_n-1`, `Block_0`, `Block_1` in the case of epoch block proofs) to check whether the heights of these blocks are consecutive. If so, there will be proofs for the `last_ds_final_block` and `last_final_block` fields during the BFT proving process for the required blocks.

*Proof_Block_i (Epoch_i).* To prove BFT finality of the randomly selected block `Block_i` we follow the next steps:
- Prove all signatures of the block `Block_i`, i.e. its endorsements, that are stored in block `Block_i+1` with ED25519.
- Prove valid keys (existence of valid keys filtered while proving signatures) & stakes (the sum of stakes that correspond to “valid keys” >=2/3 of the sum of all stakes in the list of validators).
- Verification of `Proof_Block_n-1_Epoch_i-2`.
- Prove the correspondence (that arrays of data are equal) of the `hash` of the `Block_n-1` extracted from PI of `Proof_Block_n-1_Epoch_i-2` with `epoch_id` of the current block.
- Verification of `Proof_Block_0_Epoch_i-1`.
- Prove bp hash, i.e. the correspondence of hashed list of validators to the hash in the field `next_bp_hash` in the previous epoch block that is extracted from PI of `Proof_Block_0_Epoch_i-1` (SHA256).
- Verification of `Proof_Block_i+1`.
- Prove the correspondence of `last_ds_final_block` extracted from `Proof_Block_i+1` with the hash of the current block, if the heights are consecutive.
- Verification of `Proof_Block_i+2`.
- Prove the correspondence of `last_final_block` extracted from `Proof_Block_i+2` with the hash of the current block, if the heights are consecutive.
- Verification of the proof for the `Block_i` header.  

The output is `Proof_Block_i` with the its `hash`, the `hash` of `Block_n-1_Epoch_i-2` and the `hash` of `Block_0_Epoch_i-1` as PI. 

![BFT and CI proof](/near/schemes/4_BFT_and_CI_proof.png)
*Fig. 1 — BFT and CI proof*

The scheme generates the same proofs when proving *epoch blocks*. 

![Proofs for epoch blocks](/near/schemes/5_Proofs_for_epoch_blocks.png)
*Fig. 2 — Proofs for epoch block*

> [!TIP]
> Proofs for block data: [Block_data_proofs.md](/near/near_bft_finality/Block_data_proofs.md)

Proving scheme
==============

The scheme proves an arbitrary block using data of the previous epoch block, current block and next one. The current block contains all data that has to be proven: hash, signatures of the validators, who signed the previous block (approvals), chunk data, gas etc. The next block contains the signatures of the validators, who signed the current block. The public keys to these signatures are stored in a validator list that is provided to the scheme separately. Each block also stores a hash of the validator list called next bp hash. A next bp hash for a certain block is in the previous epoch block.

![Near signature verification](/schemes/1_link_blocks_to_prove_signatures.png)
Fig. 1 – Near signature verification

So, to check all the signatures for the current block we need three blocks: the current one to choose the data that was signed, the next one to provide the signatures and the block of the previous epoch to get public keys.

![Near block structure](/schemes/2_block_data.png)
Fig. 2 – Near block structure

The scheme checks all data in a block: hash of the block, signatures, sum of stakes (>= ⅔), next bp hash (next bp hash = hash(validator list)), generates proof for each of the steps and aggregate all proofs into one.

![Proving block entities](/schemes/3_prove_entities.png)
Fig. 3 – Proving block entities

Since all blocks in Near rely on the blocks from the previous epoch, it is necessary to prove computational integrity of the initial block, that we call “genesis”. It is not a genesis of a blockchain, it is just a starting point of the proving process, so it has to be valid and accepted by a community as reliable data. This initial block has only one entity to prove, i.e. hash of the block, signatures cannot be verified because there is neither a list of validators nor a hash from the list of validators. For all next blocks the proving scheme contains verification of all entities.

The scheme also verifies the proof of the previous epoch block, on which the current one relies on, and aggregates it with the resulting proof of the current block to chain all proofs together.

![Scheme of linked proofs](/schemes/4_scheme_of_linked_proofs.png)
Fig. 4 – Scheme of linked proofs

Since every next block proof relies on the epoch proof of the hash, we additionally store proof of hashing to just call it while proving current block data, instead of proving two blocks.

![Linked proofs](/schemes/5_linked_proofs.png)
Fig. 5 – Linked proofs

Proving hash
============

The scheme of proving hash of the block implements [SHA256](https://en.wikipedia.org/wiki/SHA-2). Its input data is a message and a digest, the validity of which has to be verified. The scheme generates a digest based on a provided message and compares it to the given digest. A digest is set to public inputs of a proof.

We also set the next bp hash from the current block to public inputs of the current proof to provide it to validator list verification in the proving process of blocks of the next epoch. This ensures that the next bp hash is delivered securely, “from a trusted source”, since the proof was created based on reliable data and can also be verified.

This proof is stored separately and provided later to the proving process of the next blocks for verification and its public inputs (next bp hash) are provided to verify validators list. It is also aggregated with other proofs for the current block to generate the final proof.

![Scheme of proving block hash](/schemes/6_prove_hash.png)
Fig. 6 – Scheme of proving block hash

Proving signatures
==================

The scheme of proving hash implements [EdDSA](https://en.wikipedia.org/wiki/EdDSA) over the 255-bit curve [Curve25519](https://en.wikipedia.org/wiki/Curve25519). It takes a message, signatures and public keys as input. A message is chosen for each block by the following rule: if the next block exists, the validators sign a hash of the previous one with the height of the current one, otherwise a missed height with the height of the current block. Public keys are provided from the validators list. Signatures are provided from the next block.

The scheme generates proofs for each signature separately and aggregates them later one by one. Since the proving process is made for one message for the whole block, we generate the circuit once and then reuse it for all signatures to make different proofs.

This step also filters all keys and creates a list of valid keys, for which there are verified signatures. This list is hashed and its digest is set to public inputs of the resulting proof. This is done to ensure that the list of filtered keys is valid while proving its existence in the whole validators list in the next step.

![Scheme of proving signatures](/schemes/7_prove_signatures.png)
Fig. 7 – Scheme of proving signatures

Proving keys & ⅔ stakes
=======================

This scheme proves the existence of filtered keys on the previous step in the whole validators list, computes a sum of stakes for these valid keys and checks whether this sum is >= ⅔ of the sum of all stakes of the validator list. Since a list of valid keys is provided as a vector and cannot be considered as trusted data we also check its hash with the one which is stored in the proof of aggregated signatures (which is considered to be valid). This step generates proof for keys & stakes and proof for hash of list of keys. Then the scheme aggregates them into one and sets a list of keys and a sum of stakes as public inputs.

![Scheme of proving keys & stakes](/schemes/8_prove_keys_23stakes.png)
Fig. 8 – Scheme of proving keys & stakes

Proving next bp hash
====================

The scheme of proving the next bp hash implements SHA-256 and checks if a hash of the validator list matches the next bp hash stored in the public inputs of a proof of the previous epoch block. The public inputs of this proof is a verified next bp hash.

Aggregation
===========

The last step is to aggregate all proofs for the current block into one with a hash for the current block & a previous epoch block hash set as public inputs.

![Scheme of proofs aggregation](/schemes/9_aggregation.png)
Fig. 9 – Scheme of proofs aggregation
Proving block header hash
============

The scheme of proving hash of the block implements [SHA256](https://en.wikipedia.org/wiki/SHA-2). Its input data is a message and a digest, the validity of which has to be verified. The scheme generates a digest based on a provided message and compares it to the given one. A digest is set to public inputs of a proof. There are some other fiels like `prev_hash`, `last_ds_final_block` etc. that could be set to public inputs.

Proving signatures
==================

The scheme of proving hash implements [EdDSA](https://en.wikipedia.org/wiki/EdDSA) over the 255-bit curve [Curve25519](https://en.wikipedia.org/wiki/Curve25519). It takes a message, signatures and public keys as input. A message is chosen for each block by the following rule: if the next block exists, the validators sign a hash of the previous block with the height of the current one, otherwise a missed height with the height of the current block. Public keys are provided from the validators list. Signatures are provided from the next block.

The scheme generates proofs for each signature separately and aggregates them later one by one. Since the proving process is made for one message for the whole block, we generate the circuit once and then reuse it for all signatures to make different proofs.

This step also filters all keys and creates a list of valid keys, for which there are verified signatures. This list is hashed and its digest is set to public inputs of the resulting proof. This is done to ensure that the list of filtered keys is valid while proving its existence in the whole validators list in the next step.

![Scheme of proving signatures](/near/schemes/6_Scheme_of_proving_signatures.png)
*Figure – Scheme of proving signatures*

Proving keys & ⅔ stakes
=======================

This scheme proves the existence of filtered keys on the previous step in the validators list, computes a sum of stakes for these valid keys and checks whether this sum is >= ⅔ of the sum of all stakes of the validator list. Since a list of valid keys is provided as a vector and cannot be considered as trusted data we also check its hash with the one which is stored in the proof of aggregated signatures (which is considered to be valid). This step generates proof for keys & stakes and proof for hash of list of keys. Then the scheme aggregates them into one and sets a list of keys and a sum of stakes as public inputs.

Proving hash of the next epoch block producers set
====================

The scheme of proving hash of the next epoch block producers set implements SHA-256 and checks if a hash of the list of validators matches the field `next_bp_hash`, that is stores in public inputs of a proof of the previous epoch block. The public inputs of this proof is a verified `next_bp_hash`.

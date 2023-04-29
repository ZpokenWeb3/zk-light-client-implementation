## **Core Concept**

The first block of an epoch should be accompanied with the recursive zk-SNARK proof of knowledge of correct private inputs for the composite statement below.

Public inputs:

- Hc — SHA-256 hash of the block;
- Hg — SHA-256 hash of the genesis block.

Private inputs:

- Bc — The block;
- Bp — The first block of the previous epoch;
- Hp — SHA-256 hash of the first block of the previous epoch;
- Pp — The proof accompanying the first block of the previous epoch.

Statement:

- Hp equals the hash of Bp;
- Hp equals Hg **OR** Pp is valid for public inputs (Hp, Hg);
- Hc equals the hash of Bc;
- Bc.epoch equals Bp.nextEpoch;
- **Sum**i=1..n(Verify(v[i].pubKey, Bc, Bc.signatures[i]) ⋅ v[i].stake) exceeds ⅔ of **Sum**i=1..n(v[i].stake), where **v** is Bp.nextValidators, **n** is Bp.nextValidators.length, **Verify** performs EdDSA signature verification for a block and returns 1 (correct) or 0 (incorrect).

To generate a proof for the first block of the i-th epoch we should take only this block, the first block of the (i-1)-th epoch, the proof accompanying it and the hash of the genesis block.

To validate a proof for the first block of the i-th epoch we have to compute its hash (denoted as Hi), obtain of the genesis block hash (designated as Hg) and verify the proof, which accompanies the block, for public inputs (Hi, Hg).

The pre-hashing algorithm, which is applied to a block before the direct EdDSA verification, has been implemented in the NEAR lightweight client as a part of the **validate_light_client_block** function and can be found here:[https://github.com/near/nearcore/blob/dce2a47f255fdea591a0c1ea24c0a683f659fb7a/pytest/lib/lightclient.py](https://github.com/near/nearcore/blob/dce2a47f255fdea591a0c1ea24c0a683f659fb7a/pytest/lib/lightclient.py)

The direct EdDSA verification for the NEAR lightweight client is performed using the PyNaCl, which “is a Python binding to libsodium, which is a fork of the Networking and Cryptography library”. In libsodium the EdDSA scheme is built over the **Ed25519** curve and the **SHA-512** hash function. The corresponding source code can be found here: [https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_sign/ed25519/ref10/open.c](https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_sign/ed25519/ref10/open.c)

For better understanding of the EdDSA scheme the following article is recommended: [https://medium.com/asecuritysite-when-bob-met-alice/whats-the-difference-between-ecdsa-and-eddsa-e3a16ee0c966](https://medium.com/asecuritysite-when-bob-met-alice/whats-the-difference-between-ecdsa-and-eddsa-e3a16ee0c966)

The circuit for generating the aforesaid proofs requires the following cryptographic primitives:

- SHA-256 calculator;
- EdDSA verifier using the Ed25519 curve and the SHA-512 hash function;
- Verifier of the proofs generated for the considered circuits.

These cryptographic primitives are SNARK-unfriendly, i.e. are not initially represented as a sequence of computations over the circuit's native field. Therefore, the time and space complexities for the resulting prover should be estimated before implementation.

## This is implementation for Near state based on proving headers of epoch blocks

## **Prerecusites**

This project requires using the nightly Rust toolchain, which can be used by default in this way:
```
rustup default nightly
```
## **Decription**

In our current scheme we create a chain of blocks: epoch and ordinary.

We use the epoch block structure from the NEAR protocol.

In the current implementation we recursively prove the computational integrity of only epoch blocks. These proofs contain only proofs for the hash of epoch blocks.

This is a simplified version of the proving system, where we will additionally prove signatures (of the block producer & validators) for epoch blocks and the whole set of proofs (hash, producer ‘s & validators’ signatures) for ordinary blocks.

## **How to run**
```
cargo run --release --package plonky2_recursion
```

## **Results**
### Time for the first 10 blocks recursion proofs
Block number |build, s	| prove, s |	verify, s
---|---|---|---
1|	2.5633|	4.6440|	0.0070
2|	2.0640|	5.1424|	0.0076
3|	2.4430|	4.8360|	0.0071
4|	2.0789|	4.3056|	0.0076
5|	2.1833|	4.4122|	0.0069
6|	2.1611|	4.4126|	0.0071
7|	2.1334|	4.1623|	0.0071
8|	2.1054|	4.2416|	0.0070
9|	2.1219|	4.1295|	0.0072
avg|	2.2060|	4.4762|	0.0072

### Total time for recursion proofs
Block quantity |build + prove +	verify, s (h : m : s)
---|---:
1|	6 (00:00:06)
10|	68 (00:01:08)
1000|	687 (00:11:27)
10000|	6934 (01:55:34)
42000 (epoch)|	70223 (19:30:23)

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

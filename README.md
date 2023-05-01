## This is implementation of Near Protocol zk light client based on proving headers of epoch blocks

## **Decription**

In our current scheme we create a chain of epoch blocks.

We use the epoch block structure from the NEAR protocol.

In the current implementation we recursively prove the computational integrity of only epoch blocks. These proofs contain only proofs for the hash of epoch blocks.

The figure below shows the proving scheme, which contains:
- Bi are the epoch blocks;
- H(Bi) are the of the epoch blocks to be proved;
- C.S.P is the proving algorithm, where C is a computational scheme Ci(Xi, Wi), (i = 0...n-1) of the verification algorithm V (hash verification), S are the public settings (Spi, Svi) = S(Ci(Xi, Wi)), (i = 1...n), where Spi are public prover settings, Svi are public verifier settings, Xi and Wi are private inputs and witnesses respectively, P is a generator of a proof of computational integrity;
- ∏i is a proof, which is verified for each block and provided for the proof generation of the next block in a chain to make a recursively verified chain of proofs.

![proving epoch blocks](https://github.com/ZpokenWeb3/zk-light-client-implementation/blob/main/schemes/prove_epoch_blocks.png)

This is a simplified version of the proving system, where we will additionally prove signatures (of the block producer & validators) for epoch blocks and the whole set of proofs (hash, producer ‘s & validators’ signatures) for ordinary blocks.

## **Prerecusites**

This project requires using the nightly Rust toolchain, which can be used by default in this way:
```
rustup default nightly
```
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

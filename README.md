## Implementation of Near Protocol ZK light client based on proving headers of epoch blocks

## **Description**

In our current scheme, we create a chain of epoch blocks.

We use the epoch block structure from the NEAR protocol.

In the current implementation, we recursively prove the computational integrity of only epoch blocks. These proofs contain only proofs for the hash of epoch blocks.

The figure below shows the proving scheme, which contains:
- Bi are the epoch blocks;
- H(Bi) are the of the epoch blocks to be proved;
- C.S.P is the proving algorithm, where C is a computational scheme Ci(Xi, Wi), (i = 0...n-1) of the verification algorithm V (hash verification), S are the public settings (Spi, Svi) = S(Ci(Xi, Wi)), (i = 1...n), where Spi are public prover settings, Svi are public verifier settings, Xi and Wi are private inputs and witnesses respectively, P is a generator of a proof of computational integrity;
- ∏i is a proof, which is verified for each block and provided for the proof generation of the next block in a chain to make a recursively verified chain of proofs.

![proving epoch blocks](https://github.com/ZpokenWeb3/zk-light-client-implementation/blob/main/schemes/prove_epoch_blocks.png)

This is a simplified version of the proving system, where we will additionally prove signatures (of the block producer & validators) for epoch blocks and the whole set of proofs (hash, producer ‘s & validators’ signatures) for ordinary blocks.

## **Prerequisites**

This project requires using the nightly Rust toolchain, which can be used by default in this way:
```
rustup default nightly
```
## **How to run**
```
cd prover
cargo run --release
```

## **Results**

### Time for the 100 epoch blocks
After run, you will see output similar to the next one:
```
[INFO  plonky2::util::timing] 89.6174s to Build proofs parallel
[INFO  plonky2::util::timing] 115.5254s to Compose parallel
```
So, the total time to compute on our machine (32 threads) was 205 seconds (3:25).

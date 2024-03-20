# SHA-256 on Plonky2

The implementation of SHA-256 using U32Target from Plonky2 to speed up the proving process.

## Features

SHA-256:
- Hash Arbitrary Length Data
- Hash Two to One (For use with Merkle Proofs)
- Merkle Proof Gadget
- Delta Merkle Proof Gadget

## Run the library tests

```
cargo test --release -- --nocapture
```


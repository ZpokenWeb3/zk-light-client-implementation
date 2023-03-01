# plonky2-sha512

This repository contains [SNARK](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof) circuits of a
cryptographic hash function [SHA-512](https://en.wikipedia.org/wiki/SHA-2) implemented
with [Plonky2](https://github.com/mir-protocol/plonky2).

Run benchmarks

```console
RUSTFLAGS=-Ctarget-cpu=native cargo run --release --package plonky2_sha512 --bin plonky2_sha512
```

Benchmark on a Macbook Pro (M1), preimage message size = 128 (block count = 2)

```console
Constructing inner proof with 29855 gates
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 29946
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 32768
[DEBUG plonky2::plonk::circuit_builder] Building circuit took 1.7478968s
[DEBUG plonky2::util::timing] 1.9542s to prove
[DEBUG plonky2::util::timing] 0.0053s to verify
```

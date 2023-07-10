# plonky2-ed25519

This repository contains [SNARK](https://en.wikipedia.org/wiki/Non-interactive_zero-knowledge_proof) verification
circuits of a
digital signature scheme [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) implemented
with [Plonky2](https://github.com/mir-protocol/plonky2).

Run benchmarks

```console
RUSTFLAGS=-Ctarget-cpu=native cargo run --package plonky2_ed25519 --bin plonky2_ed25519 --release
```

Benchmark on a Macbook Pro (M1)

```console
Constructing inner proof with 171519 gates
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 178959
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 262144
[INFO  plonky2::util::timing] 30.6725s to prove
[INFO  plonky2::util::timing] 0.0071s to verify
[INFO  plonky2_ed25519] Proof length: 204040 bytes
[INFO  plonky2_ed25519] 0.0086s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 188558 bytes
Constructing inner proof with 171519 gates
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 178959
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 262144
[INFO  plonky2::util::timing] 30.8669s to prove
[INFO  plonky2::util::timing] 0.0070s to verify
[INFO  plonky2_ed25519] Proof length: 204040 bytes
[INFO  plonky2_ed25519] 0.0085s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 187197 bytes
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 12086
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 16384
[INFO  plonky2::util::timing] 1.0721s to prove
[INFO  plonky2_ed25519] Proof length: 146348 bytes
[INFO  plonky2_ed25519] 0.0057s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 135653 bytes
[INFO  plonky2_ed25519] Single recursion proof degree 16384 = 2^14
[INFO  plonky2::plonk::circuit_builder] Degree before blinding & padding: 4364
[INFO  plonky2::plonk::circuit_builder] Degree after blinding & padding: 8192
[INFO  plonky2::util::timing] 0.5072s to prove
[INFO  plonky2_ed25519] Proof length: 132816 bytes
[INFO  plonky2_ed25519] 0.0051s to compress proof
[INFO  plonky2_ed25519] Compressed proof length: 120237 bytes
[INFO  plonky2_ed25519] Double recursion proof degree 8192 = 2^13
```
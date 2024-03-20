# Gnark Plonky2 Verifier
[gnark](https://github.com/Consensys/gnark) is a fast zk-SNARK library that offers a high-level API to design circuits.

This is an implementation of a [Plonky2](https://github.com/mir-protocol/plonky2) verifier in Gnark (supports Groth16 and PLONK) for Near verification.

## Requirements

- [Go (1.19+)](https://go.dev/doc/install)

## Deploy

To compile prover, verifier keys and Solidity verifier contract
```
USE_BIT_DECOMPOSITION_RANGE_CHECK=true go run compile_build.go
```

To test proving 
```
go run test_proof.go
```

To run web-api with prover
```
USE_BIT_DECOMPOSITION_RANGE_CHECK=true go run compile_build.go
go run run_api.go
```


## Вenchmarking
**Hardware**: AMD Ryzen 9 7950X 16-Core Processor, 64 GB DDR5-5200

| Proof System | Compile | Proving  | Verification | Proof size |
|--------------|---------|----------|--------------|------------|
| Groth16      | 17 min  | 30 sec   | 0.0011       | 256 bytes  |
| Plonk        | 17 min  | 2.30 min | 0.0020       | 928 bytes  |

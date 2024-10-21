# Gnark Plonky2 Verifier
[gnark](https://github.com/Consensys/gnark) is a fast zk-SNARK library that offers a high-level API to design circuits.

This is an implementation of a [Plonky2](https://github.com/mir-protocol/plonky2) verifier in Gnark (supports Groth16 and PLONK) for Near verification.

## Requirements

- [Go (1.19+)](https://go.dev/doc/install)

## Deploy

To compile prover, verifier keys and Solidity verifier contract
```
USE_BIT_DECOMPOSITION_RANGE_CHECK=true go run main.go compile --dir testdata/test_circuit
```

To test prover (compiled setup needed)
```
go test -race -vet=off ./...
```

To test prover using Dockerfile with compiled setup
```
docker build -t gnark-prover-test -f docker/Dockerfile_test_prover .
docker run gnark-prover-test
```

To run web-api with prover
```
USE_BIT_DECOMPOSITION_RANGE_CHECK=true go run main.go web-api --dir testdata/test_circuit
```


## Вenchmarking
**Hardware**: AMD Ryzen 9 7950X 16-Core Processor, 64 GB DDR5-5200

| Proof System | Compile | Proving  | Verification | Proof size |
|--------------|---------|----------|--------------|------------|
| Groth16      | 17 min  | 30 sec   | 0.0011 sec   | 256 bytes  |
| Plonk        | 17 min  | 2.30 min | 0.0020 sec   | 928 bytes  |

# Crypto Gadgets for Plonky2

A collection of efficient gadgets for Plonky2.

As we're building larger and larger circuits with Plonky2, we want to share some of our work and optimizations, packaged in a single and simple to use library.

## Complete Example

See the [`hello-world` example](examples/hello-world/) to get started and build your own circuit.

Or run:
```
cd examples/hello-world
cargo test --release -- --nocapture
```
(don't forget the `--release`!)

For more examples you can run the library tests:
```
cargo test --release -- --nocapture
```

## Features

Hash functions:
- [x] Sha256
- [x] Keccak256

Integer arithmetic:
- [x] Uint32 arithmetic ops (add, mul, ...)
- [x] Uint32 bitwise ops (and, xor, ...)
- [x] BigUint arithmetic ops (add, sub, mul, div/rem, ...)
- [x] BigUint optimized mul, sqr

Finite field arithmetic:
- [ ] Prime fields
- [ ] Extension fields
- [ ] Extension towers

Elliptic curve cryptography:
- [ ] ECDSA (secp256k1)
- [ ] EDDSA (ed25519)
- [ ] BLS (bls12-381)

## Contribute

We welcome contribution, whether in form of bug fixed, documentation, new gadgets, new functionality.

Just open an issue to discuss what you'd like to contribute and then submit a PR.

**Disclaimer. This alpha software has been open sourced. All software and code are provided “as is,” without any warranty of any kind, and should be used at your own risk.**

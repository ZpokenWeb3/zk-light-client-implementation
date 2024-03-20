## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

-   **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
-   **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
-   **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
-   **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Add OpenZeppelin lib

```shell
$ forge install OpenZeppelin/openzeppelin-contracts-upgradeable --no-commit
```

### Test

```shell
$ forge test

Ran 11 tests for test/NearBlockVerification.t.sol:NearBlockVerificationTest
[PASS] testCompressedProofVerifiedAndSavedEvent() (gas: 309549)
[PASS] testHandleIncorrectProof() (gas: 8797746687696168461)
[PASS] testIsProofedHashWhenInputHashIsProofed() (gas: 278736)
[PASS] testIsProofedHashWhenInputHashNotProofed() (gas: 15405)
[PASS] testIsProofedWhenInputIsNotProofed() (gas: 28540)
[PASS] testIsProofedWhenInputIsProofed() (gas: 277735)
[PASS] testProofVerifiedAndSavedEvent() (gas: 280726)
[PASS] testSetVerifier() (gas: 1098410)
[PASS] testSuccessfulVerifyAndSaveCompressedProof() (gas: 302966)
[PASS] testSuccessfulVerifyAndSaveProof() (gas: 272086)
[PASS] testToHash() (gas: 23504)
Suite result: ok. 11 passed; 0 failed; 0 skipped; finished in 24.07ms (76.77ms CPU time)

Ran 3 tests for test/Verifier.t.sol:VerifierTest
[PASS] testIncorrectProof() (gas: 8937393460516737801)
[PASS] testSuccessfulVerifyCompressedProof() (gas: 269612)
[PASS] testSuccessfulVerifyProof() (gas: 239681)
Suite result: ok. 3 passed; 0 failed; 0 skipped; finished in 24.81ms (38.94ms CPU time)

Ran 2 test suites in 26.88ms (48.88ms CPU time): 14 tests passed, 0 failed, 0 skipped (14 total tests)

```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```

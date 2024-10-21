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

### Deploy Verifier contract

```shell
Add to the .env file:
MAINNET_RPC_URL=<your_mainnet_rpc_url>
PRIVATE_KEY=<your_private_key>

$ source .env
$ forge script script/VerifierDeployment.s.sol:VerifierDeploymentScript --fork-url $MAINNET_RPC_URL --private-key $PRIVATE_KEY --broadcast

[⠒] Compiling...
No files changed, compilation skipped
Script ran successfully.

== Logs ==
  Verifier deployed to: 0xC7f2Cf4845C6db0e1a1e91ED41Bcd0FcC1b0E141
```

### Deploy NearBlockVerification contract

```shell
Add to the .env file:
MAINNET_RPC_URL=<your_mainnet_rpc_url>
PRIVATE_KEY=<your_private_key>
VERIFIER=<verifier_contract_address>

$ source .env
$ forge script script/NearBlockVerificationDeployment.s.sol:NearBlockVerificationDeploymentScript --fork-url $MAINNET_RPC_URL --private-key $PRIVATE_KEY --broadcast

[⠒] Compiling...
No files changed, compilation skipped
Script ran successfully.

== Logs ==
  NearBlockVerification deployed to: 0xC7f2Cf4845C6db0e1a1e91ED41Bcd0FcC1b0E141
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

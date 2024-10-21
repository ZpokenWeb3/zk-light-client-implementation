** Install

```shell
nvm install v18
yarn
npx hardhat help
```

** Unit tests

```shell
npx hardhat test

or

REPORT_GAS=true npx hardhat test
...


** Deploy into goerli testnet

```shell
npx hardhat run --network goerli scripts/deploy_verifier.ts
Verifier deployed to: 0xe4a1B222D308896d09deFA29f89cAb596fBAbbDf

npx hardhat run --network goerli scripts/deploy_NearBlockVerification.ts
NearBlockVerification deployed to: 0x63F526335DB8458c76914BdBD88F0A97E1B6b157
```

** Deploy into sepolia testnet

```shell
npx hardhat run --network sepolia scripts/deploy_verifier.ts
Verifier deployed to: 0x20954439eB64259D2E62d4215d57Ef46086Bd87a

npx hardhat run --network sepolia scripts/deploy_NearBlockVerification.ts
NearBlockVerification deployed to: 0xce5845372e615Cbb46EFCc76c21051932BD8A717
```

** Tests in goerli testnet

```shell
export PROOF_PATH=test/proof_with_16_inputs_01.json && npx hardhat run --network goerli scripts/test_verifierWith16Inputs.ts
export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network goerli scripts/test_verifier.ts
export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network goerli scripts/test_NearBlockVerification.ts
```

** Tests in sepolia testnet

```shell
export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network sepolia scripts/test_verifier.ts
Successfully completed!!

export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network sepolia scripts/test_NearBlockVerification.ts
nearBlockVerification.isProofed:  true
hash:  0xbc3b7ad2c4a1269c8bbc161ee8d9fd3bdd4ee11af49aede8eb8a920e9e344647
nearBlockVerification.isProofedHash:  true
Successfully completed!!
```

** Verification in goerli testnet

```shell
export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network goerli scripts/verification.ts
hash:  0xbc3b7ad2c4a1269c8bbc161ee8d9fd3bdd4ee11af49aede8eb8a920e9e344647
nearBlockVerification.isProofedHash:  true
```

** Verification in sepolia testnet

```shell
export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network sepolia scripts/verification.ts
hash:  0xbc3b7ad2c4a1269c8bbc161ee8d9fd3bdd4ee11af49aede8eb8a920e9e344647
nearBlockVerification.isProofedHash:  true
```

** Update Verifier contract in sepolia testnet

```shell
npx hardhat run --network sepolia scripts/update_verifier.ts
Verifier deployed to: 0x45b3d9C7810ab509c6fe0F394820dB49b2B36160
nearBlockVerification.getVerifier():  0x45b3d9C7810ab509c6fe0F394820dB49b2B36160
```

** Pause NearBlockVerification contract

```shell
npx hardhat run --network sepolia scripts/pause_NearBlockVerification.ts
nearBlockVerification.paused():  true
```

** Unpause NearBlockVerification contract

```shell
npx hardhat run --network sepolia scripts/unpause_NearBlockVerification.ts
nearBlockVerification.paused():  false
```

** Install

```shell
nvm install v16
yarn
npx hardhat help
```

** Unit tests

```shell
npx hardhat test
REPORT_GAS=true npx hardhat test

  Verifier
    ✔ should successfully execute the verifyProof request
    ✔ should successfully execute the verifyCompressedProof request
    ✔ should handle incorrect proof
    NearBlockVerification
      ✔ should successfully execute the verifyAndSaveProof request
      ✔ should handle incorrect proof
      ✔ should successfully execute the verifyAndSaveCompressedProof request
      ✔ should return false for isProofed when input is not proofed
      ✔ should return true for isProofed when input is proofed
      ✔ should correctly convert array to hash
      ✔ should return false for isProofedHash when inputHash is not proofed
      ✔ should return true for isProofedHash when inputHash is proofed
      ✔ should set verifier correctly
      ✔ should emit ProofVerifiedAndSaved event
      ✔ should emit CompressedProofVerifiedAndSaved event

  VerifierWith16Inputs
    ✔ should successfully execute the verifyProof request
    ✔ should successfully execute the verifyCompressedProof request
    NearBlockVerificationWith16Inputs
      ✔ should successfully execute the verifyAndSaveProof request
      ✔ should successfully execute the verifyAndSaveCompressedProof request
      ✔ should return false for isProofed when input is not proofed
      ✔ should return true for isProofed when input is proofed
      ✔ should correctly convert array to hash
      ✔ should return false for isProofedHash when inputHash is not proofed
      ✔ should return true for isProofedHash when inputHash is proofed
      ✔ should set verifier correctly
    NearBlockVerificationWith16InputsIA
      ✔ should successfully execute the verifyAndSaveProof request
      ✔ should successfully execute the verifyAndSaveCompressedProof request
      ✔ should return false for isProofed when input is not proofed
      ✔ should return true for isProofed when input is proofed
      ✔ should correctly convert array to hash
      ✔ should return false for isProofedHash when inputHash is not proofed
      ✔ should return true for isProofedHash when inputHash is proofed
      ✔ should set verifier correctly

·------------------------------------------------------------------------|---------------------------|-------------|-----------------------------·
|                          Solc version: 0.8.16                          ·  Optimizer enabled: true  ·  Runs: 200  ·  Block limit: 30000000 gas  │
·········································································|···························|·············|······························
|  Methods                                                                                                                                       │
········································|································|·············|·············|·············|···············|··············
|  Contract                             ·  Method                        ·  Min        ·  Max        ·  Avg        ·  # calls      ·  usd (avg)  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerification                ·  setVerifier                   ·          -  ·          -  ·      28919  ·            1  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerification                ·  verifyAndSaveCompressedProof  ·          -  ·          -  ·     275941  ·            3  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerification                ·  verifyAndSaveProof            ·          -  ·          -  ·     267051  ·            5  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16Inputs    ·  setVerifier                   ·          -  ·          -  ·      28975  ·            1  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16Inputs    ·  verifyAndSaveCompressedProof  ·          -  ·          -  ·     358914  ·            1  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16Inputs    ·  verifyAndSaveProof            ·          -  ·          -  ·     350046  ·            3  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16InputsIA  ·  setVerifier                   ·          -  ·          -  ·      28908  ·            1  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16InputsIA  ·  verifyAndSaveCompressedProof  ·          -  ·          -  ·     356619  ·            1  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16InputsIA  ·  verifyAndSaveProof            ·          -  ·          -  ·     347751  ·            3  ·          -  │
········································|································|·············|·············|·············|···············|··············
|  Deployments                                                           ·                                         ·  % of limit   ·             │
·········································································|·············|·············|·············|···············|··············
|  NearBlockVerification                                                 ·          -  ·          -  ·     589958  ·          2 %  ·          -  │
·········································································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16Inputs                                     ·     592871  ·     592883  ·     592882  ·          2 %  ·          -  │
·········································································|·············|·············|·············|···············|··············
|  NearBlockVerificationWith16InputsIA                                   ·          -  ·          -  ·     584268  ·        1.9 %  ·          -  │
·········································································|·············|·············|·············|···············|··············
|  Verifier                                                              ·          -  ·          -  ·    1180829  ·        3.9 %  ·          -  │
·········································································|·············|·············|·············|···············|··············
|  VerifierWith16Inputs                                                  ·          -  ·          -  ·    1535671  ·        5.1 %  ·          -  │
·------------------------------------------------------------------------|-------------|-------------|-------------|---------------|-------------·

  32 passing (14s)

```

** Deploy into testnet

```shell
npx hardhat run --network goerli scripts/deploy_verifier.ts

Verifier deployed to: 0xe4a1B222D308896d09deFA29f89cAb596fBAbbDf

npx hardhat run --network goerli scripts/deploy_NearBlockVerification.ts

NearBlockVerification deployed to: 0x63F526335DB8458c76914BdBD88F0A97E1B6b157
```

** Tests in testnet

```shell
export PROOF_PATH=test/proof_with_16_inputs_01.json && npx hardhat run --network goerli scripts/test_verifierWith16Inputs.ts
export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network goerli scripts/test_verifier.ts
export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network goerli scripts/test_NearBlockVerification.ts
```

** Verification

```shell
export PROOF_PATH=test/proof_with_witness.json && npx hardhat run --network goerli scripts/verification.ts

hash:  0xbc3b7ad2c4a1269c8bbc161ee8d9fd3bdd4ee11af49aede8eb8a920e9e344647
nearBlockVerification.isProofedHash:  true

```

## Implementation of Near Protocol ZK light client

## Headers proving of epoch blocks

#### To prove that an arbitrary block was indeed included in blockchain, we want to prove that a set of validator that produced that block is valid and actual take place in calculating `next_bp_hash`


#### Let's consider arbitrary block from the [Near Explorer](https://explorer.near.org/blocks/qzPg1pgc96QvWFPVeERhjcPi5MfjDnFx7jWHMhDsvFV) and its hash `qzPg1pgc96QvWFPVeERhjcPi5MfjDnFx7jWHMhDsvFV`

Underpinning idea is to replicate near core's logic for calculating `next_bp_hash` and compare it to the real values obtained from blockchain through RPC commands. The logic is the following:

```rust
   pub fn compute_bp_hash(
        epoch_manager: &dyn EpochManagerAdapter,
        epoch_id: EpochId,
        prev_epoch_id: EpochId,
        last_known_hash: &CryptoHash,
    ) -> Result<CryptoHash, Error> {
        let bps = epoch_manager.get_epoch_block_producers_ordered(&epoch_id, last_known_hash)?; <--------- step 1 is to acquire block producers for that epoch 
        let protocol_version = epoch_manager.get_epoch_protocol_version(&prev_epoch_id)?;
        if checked_feature!("stable", BlockHeaderV3, protocol_version) {
            let validator_stakes = bps.into_iter().map(|(bp, _)| bp);
            Ok(CryptoHash::hash_borsh_iter(validator_stakes)) <--------- step 2 is to compute bp_hash from the validator_stakes
        } else {
            let validator_stakes = bps.into_iter().map(|(bp, _)| bp.into_v1());
            Ok(CryptoHash::hash_borsh_iter(validator_stakes)) <--------- same step 2 
        }
    }

```

Representative scheme:

![image](https://github.com/ZpokenWeb3/zk-light-client-implementation/assets/58668238/19584862-d23c-4518-b868-af9e36e9dc5f)


1) Configure account in config.json file

```json
{
  "block_hash": "qzPg1pgc96QvWFPVeERhjcPi5MfjDnFx7jWHMhDsvFV",
  "network": 1 // 0 - for TESTNET, 1 for MAINNET
}
```

2) Query the ordered validators for the N-th epoch through RPC command `EXPERIMENTAL_validators_ordered`


```
 http post https://rpc.mainnet.near.org \
 jsonrpc=2.0 \
 method=EXPERIMENTAL_validators_ordered \
 params:='["qzPg1pgc96QvWFPVeERhjcPi5MfjDnFx7jWHMhDsvFV"]' \
 id=dontcare
```

3) Replicate nearcore logic for compute_bp_hash

```rust
    let validator_stakes = validators_ordered_response
        .result
        .into_iter()
        .map(|validator| {
            ValidatorStake::new_v1(
                AccountId::from_str(&validator.account_id).unwrap(),
                PublicKey::from_str(&validator.public_key).unwrap(),
                validator.stake.parse().unwrap(),
            )
        });

    let computed_bp_hash = CryptoHash::hash_borsh_iter(validator_stakes);

    println!("Computed BP hash {:?}", computed_bp_hash);
```

So now we have
`Computed BP hash CdXTGjuJgpwEMQzKDxirXSvcZr6fxMc9SFWMm8MgnKrY
`

4) Calculated hash_borsh have to be equal to the next_bp_hash for all blocks from the previous epochs. So lets query block info for the block from the previous epoch supposing that there is [43200 blocks in one epoch](https://docs.near.org/concepts/basics/epoch).
```
    const BLOCKS_IN_EPOCH: u128 = 43_200;

    let previous_epoch_block_height = current_block_height - BLOCKS_IN_EPOCH;

    let previous_epoch_block_request = BlockRequestByHeight {
        jsonrpc: "2.0",
        id: "dontcare",
        method: "block",
        params: BlockParamHeight {
            block_id: previous_epoch_block_height,
        },
    };

    let previous_epoch_block_response: BlockResponse = client
        .post(rpc_url)
        .json(&previous_epoch_block_request)
        .send()
        .await?
        .json()
        .await?;


    println!(
        "\nPrevious epoch block  {:?}",
        previous_epoch_block_response.result.header
    );

    println!(
        "computed hash {} == {} stored hash in previous epoch block",
        computed_bp_hash, previous_epoch_block_response.result.header.next_bp_hash
    );

```

5) Output formatted for convenience:

```
Previous epoch block  BlockHeader { 
    hash: "Fw5TPKqZW1pHyLLaCvCnLw1huAirqAgW1gP4dUjxv6ra", 
    prev_hash: "5L2Wj9ELLGiYfUZ1KLBUhySKjMS8Xkcw27iDoLpXL2Xk",
    block_merkle_root: "Ec96rPYqcQmf2dh4EobZiZfdyMpzVdsf6J1yK9K1imTR", 
    prev_state_root: "3AzGBHg2YjPJ4qVYq6sNT2r4kiQ4WJsjkn9rNqLrGvQu", 
    height: 103018316, 
    next_bp_hash: "CdXTGjuJgpwEMQzKDxirXSvcZr6fxMc9SFWMm8MgnKrY",    <--------- desired field 
    epoch_id: "ATocmfYagxFxUyVgNtqKtVSSyEjjhVRN6UyEyPk2xPuJ", 
    next_epoch_id: "GPgmf1kKFPqmbxXQexnH2ZFPX8FG3StMQjLuL7Rjhesq" 
    }
```
and

```
computed hash CdXTGjuJgpwEMQzKDxirXSvcZr6fxMc9SFWMm8MgnKrY == CdXTGjuJgpwEMQzKDxirXSvcZr6fxMc9SFWMm8MgnKrY stored hash in previous epoch block
```

6) And success, it means our block was indeed included by the block producers and calculated correctly


## Implementation of Near Protocol ZK light client based on proving headers of epoch blocks

## **Description**

In our current scheme, we create a chain of epoch blocks.

We use the epoch block structure from the NEAR protocol.

In the current implementation, we recursively prove the computational integrity of only epoch blocks. These proofs contain only proofs for the hash of epoch blocks.

The figure below shows the proving scheme, which contains:
- Bi are the epoch blocks;
- H(Bi) are the of the epoch blocks to be proved;
- C.S.P is the proving algorithm, where C is a computational scheme Ci(Xi, Wi), (i = 0...n-1) of the verification algorithm V (hash verification), S are the public settings (Spi, Svi) = S(Ci(Xi, Wi)), (i = 1...n), where Spi are public prover settings, Svi are public verifier settings, Xi and Wi are private inputs and witnesses respectively, P is a generator of a proof of computational integrity;
- ∏i is a proof, which is verified for each block and provided for the proof generation of the next block in a chain to make a recursively verified chain of proofs.

![proving epoch blocks](https://github.com/ZpokenWeb3/zk-light-client-implementation/blob/main/schemes/prove_epoch_blocks.png)

This is a simplified version of the proving system, where we will additionally prove signatures (of the block producer & validators) for epoch blocks and the whole set of proofs (hash, producer ‘s & validators’ signatures) for ordinary blocks.


## **Results**

### Time for the 100 epoch blocks
After run, you will see output similar to the next one:
```
[INFO  plonky2::util::timing] 89.6174s to Build proofs parallel
[INFO  plonky2::util::timing] 115.5254s to Compose parallel
```
So, the total time to compute on our machine (32 threads) was 205 seconds (3:25).

mod utils;

use crate::utils::{
    block_hash_from_header, BlockParamHeight, BlockParamString, BlockRequest, BlockRequestByHeight,
    BlockResponse, Config, ValidatorsOrderedResponse,
};
use near_primitives::hash::CryptoHash;
use near_primitives::types::validator_stake::ValidatorStake;
use near_primitives::types::AccountId;

use near_crypto::{PublicKey, Signature};
use near_primitives::block::BlockHeader;
use near_primitives::block_header::{Approval, ApprovalInner};
use near_primitives::borsh::BorshSerialize;
use near_primitives::views::BlockHeaderInnerLiteView;
use reqwest::Client;
use serde_json::json;
use sha2::Digest;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // -------------- initial settings  --------------

    let mut file_next_bp_hash_proving =
        File::create("script/output/next_bp_hash_proving.txt").expect("Unable to create file");
    let mut file_block_hash_proving =
        File::create("script/output/block_hash_proving.txt").expect("Unable to create file");
    let mut file_validator_bytes_representation =
        File::create("script/output/validator_bytes_representation.txt")
            .expect("Unable to create file");
    let mut file_approvals_proving =
        File::create("script/output/approvals_proving.txt").expect("Unable to create file");
    let mut file_block_header_json = File::create("script/output/block_header.json").unwrap();
    let mut file_validators_ordered_json =
        File::create("script/output/validators_ordered.json").unwrap();

    let config_str = fs::read_to_string("script/config.json").unwrap();
    let config: Config = serde_json::from_str(&config_str).unwrap();
    let block_hash = config.block_hash;

    let (rpc_url_active, rpc_url_archival) = match config.network {
        0 => (
            "https://rpc.testnet.near.org",
            "https://archival-rpc.testnet.near.org",
        ),
        1 => (
            "https://rpc.mainnet.near.org",
            "https://archival-rpc.mainnet.near.org",
        ),
        _ => {
            panic!("Wrong network. Should be testnet OR mainnet")
        }
    };

    // -------------- querying current block info --------------

    let client = Client::new();

    let block_request = BlockRequest {
        jsonrpc: "2.0",
        id: "dontcare",
        method: "block",
        params: BlockParamString {
            block_id: block_hash.parse().unwrap(),
        },
    };

    let rpc_url = if client
        .post(rpc_url_active)
        .json(&block_request)
        .send()
        .await
        .is_ok()
    {
        rpc_url_active
    } else {
        rpc_url_archival
    };

    let block_response: BlockResponse = client
        .post(rpc_url)
        .json(&block_request)
        .send()
        .await?
        .json()
        .await?;

    writeln!(file_next_bp_hash_proving, "next_bp_hash PROVING\n").expect("Unable to write to file");

    let block_hash = block_response.result.header.hash.clone();
    let current_block_height = block_response.result.header.height as u128;

    // -------------- querying EXPERIMENTAL_validators_ordered for current block --------------

    let validators_ordered_request = json!({
        "jsonrpc": "2.0",
        "method": "EXPERIMENTAL_validators_ordered",
        "params": vec![block_hash],
        "id": "dontcare"
    });

    let validators_ordered_response: ValidatorsOrderedResponse = client
        .post(rpc_url)
        .json(&validators_ordered_request)
        .send()
        .await?
        .json()
        .await?;

    let validators_ordered_json_data = serde_json::to_string(&validators_ordered_response).unwrap();
    file_validators_ordered_json
        .write_all(validators_ordered_json_data.as_bytes())
        .unwrap();

    // -------------- serializing EXPERIMENTAL_validators_ordered into ValidatorStake structure --------------

    let validator_stakes: Vec<ValidatorStake> = validators_ordered_response
        .result
        .into_iter()
        .map(|validator| {
            ValidatorStake::new_v1(
                AccountId::from_str(&validator.account_id).unwrap(),
                PublicKey::from_str(&validator.public_key).unwrap(),
                validator.stake.parse().unwrap(),
            )
        })
        .collect();

    // -------------- two-part hashing algorithm for next_bp_hash --------------

    let iter = validator_stakes.clone().into_iter();
    let n = u32::try_from(iter.len()).unwrap();
    let mut hasher = sha2::Sha256::default();
    let mut len_bytes = n.to_le_bytes().try_to_vec().unwrap();
    let mut final_bytes: Vec<u8> = vec![];
    let mut experimental_validators_ordered_bytes: Vec<u8> = vec![];

    final_bytes.append(&mut len_bytes);

    hasher.write_all(&n.to_le_bytes()).unwrap();

    writeln!(
        file_next_bp_hash_proving,
        "First part of the hashing: EXPERIMENTAL_validators_ordered len in bytes: {:?}\n\n",
        n.to_le_bytes().try_to_vec().unwrap()
    )
    .expect("Unable to write to file");

    let count = iter
        .inspect(|value| {
            writeln!(file_validator_bytes_representation, "{:?}\naccount_id bytes: {:?}\npublic key bytes: {:?}\nstake bytes: {:?}\nwhole byte representation in bytes:  {:?}\n\n",
                     value,
                     BorshSerialize::try_to_vec(&value.account_id()).unwrap(),
                     BorshSerialize::try_to_vec(&value.public_key()).unwrap(),
                     BorshSerialize::try_to_vec(&value.stake()).unwrap(),
                     BorshSerialize::try_to_vec(&value).unwrap())
                .expect("Unable to write to file");
            final_bytes.append(&mut BorshSerialize::try_to_vec(&value).unwrap());
            experimental_validators_ordered_bytes.append(&mut BorshSerialize::try_to_vec(&value).unwrap());
            BorshSerialize::serialize(&value, &mut hasher).unwrap()
        })
        .count();

    assert_eq!(n as usize, count);

    let computed_bp_hash = CryptoHash(hasher.clone().finalize().into());

    // -------------- next_bp_hash calculation results output --------------

    writeln!(
        file_next_bp_hash_proving,
        "Second part of the hashing EXPERIMENTAL_validators_ordered as ValidatorStake: {:?}\n\n",
        experimental_validators_ordered_bytes
    )
    .expect("Unable to write to file");

    writeln!(
        file_next_bp_hash_proving,
        "EXPERIMENTAL_validators_ordered input array of bytes: {:?}\n\n",
        final_bytes
    )
    .expect("Unable to write to file");

    writeln!(
        file_validator_bytes_representation,
        "EXPERIMENTAL_validators_ordered input array of bytes: {:?}",
        final_bytes
    )
    .expect("Unable to write to file");

    writeln!(
        file_next_bp_hash_proving,
        "Computed BP hash in bytes: {:?}\n\n",
        hasher.clone().finalize().bytes()
    )
    .expect("Unable to write to file");

    writeln!(
        file_next_bp_hash_proving,
        "Computed BP hash {:?}\n\n",
        computed_bp_hash
    )
    .expect("Unable to write to file");

    // -------------- querying previous epoch block info --------------

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

    writeln!(
        file_next_bp_hash_proving,
        "Previous epoch block  {:?}\n\n",
        previous_epoch_block_response.result.header
    )
    .expect("Unable to write to file");

    writeln!(
        file_next_bp_hash_proving,
        "computed hash {} == {} stored hash in previous epoch block",
        computed_bp_hash, previous_epoch_block_response.result.header.next_bp_hash
    )
    .expect("Unable to write to file");

    // -------------- block hash proving --------------

    writeln!(file_block_hash_proving, "block hash PROVING\n\n",).expect("Unable to write to file");

    writeln!(
        file_block_hash_proving,
        "Current block BlockHeaderView:\t{:?}\n\n",
        block_response.result.header,
    )
    .expect("Unable to write to file");

    let block_header_inner_lite_view_json_data =
        serde_json::to_string(&BlockHeader::from(block_response.result.header.clone())).unwrap();

    file_block_header_json
        .write_all(block_header_inner_lite_view_json_data.as_bytes())
        .unwrap();

    writeln!(
        file_block_hash_proving,
        "Current block that are used for calculating block hash BlockHeaderInnerLiteView:  {:?}\n\n",
        &BlockHeaderInnerLiteView::from(BlockHeader::from(block_response.result.header.clone()))
    )
        .expect("Unable to write to file");

    writeln!(
        file_block_hash_proving,
        "Current block that are used for calculating block hash in bytes BlockHeaderInnerLiteView:  {:?}\n\n",
        BorshSerialize::try_to_vec(&BlockHeaderInnerLiteView::from(BlockHeader::from(block_response.result.header.clone()))).unwrap(),
    )
        .expect("Unable to write to file");

    writeln!(
        file_block_hash_proving,
        "Current block next_bp_hash in bytes: {:?}\n\n",
        BorshSerialize::try_to_vec(&block_response.result.header.next_bp_hash).unwrap(),
    )
    .expect("Unable to write to file");

    // -------------- block hash calculation from the BlockHeaderInnerLiteView structure --------------

    let computed_block_hash =
        block_hash_from_header(BlockHeader::from(block_response.result.header.clone()));

    // -------------- block hash calculation results output --------------

    writeln!(
        file_block_hash_proving,
        "computed block hash in bytes {:?}\n\n",
        BorshSerialize::try_to_vec(&computed_block_hash.unwrap()).unwrap(),
    )
    .expect("Unable to write to file");

    writeln!(
        file_block_hash_proving,
        "Calculated block hash from BlockHeaderInnerLiteView {:?} == {:?} BlockHeaderView\n\n",
        computed_block_hash.unwrap(),
        block_response.result.header.hash,
    )
    .expect("Unable to write to file");

    assert_eq!(
        computed_block_hash.unwrap(),
        block_response.result.header.hash,
        "Computed block hash has to be equal to obtained from RPC BlockHeaderView\n\n"
    );

    // -------------- approvals  proving --------------

    let block_header = BlockHeader::from(block_response.result.header.clone());

    let approvals = block_header.approvals();

    // Generate a message to be signed by validators
    let message_to_sign = Approval::get_data_for_sig(
        &if block_header.prev_height().unwrap() + 1 == block_header.height() {
            ApprovalInner::Endorsement(*block_header.prev_hash())
        } else {
            ApprovalInner::Skip(block_header.prev_height().unwrap())
        },
        block_header.height(),
    );

    writeln!(
        file_approvals_proving,
        "Message for verification  {:?} \n",
        message_to_sign
    )
    .expect("Unable to write to file");

    let mut total_stake: u128 = 0;
    let mut signed_stake: u128 = 0;
    for (pos, approval) in approvals.iter().enumerate() {
        match approval {
            None => {
                let validator: &ValidatorStake = &validator_stakes[pos];
                total_stake += validator.stake();

                writeln!(
                    file_approvals_proving,
                    "Missed approvals for validator {:?} \n",
                    validator
                )
                .expect("Unable to write to file");
            }
            Some(approval) => {
                let validator: &ValidatorStake = &validator_stakes[pos];
                total_stake += validator.stake();
                let verify: bool =
                    approval.verify(message_to_sign.as_ref(), validator.public_key());
                if verify {
                    signed_stake += validator.stake();

                    writeln!(
                        file_approvals_proving,
                        "Approvals {} successfully verified for validator {:?} \n",
                        approval, validator
                    )
                    .expect("Unable to write to file");
                } else {
                    writeln!(
                        file_approvals_proving,
                        "Approvals {} NOT verified for validator {:?} \n",
                        approval, validator
                    )
                    .expect("Unable to write to file");
                }
            }
        }
    }

    assert!(total_stake*2/3 < signed_stake,
               "Sum of validators stakes that signed the block is less than 2/3 of sum of all validators stakes");

    writeln!(
        file_approvals_proving,
        "Total stake sum   {}\n",
        total_stake
    )
    .expect("Unable to write to file");

    writeln!(
        file_approvals_proving,
        "Signed stake sum   {}\n",
        signed_stake
    )
    .expect("Unable to write to file");

    Ok(())
}

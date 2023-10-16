mod utils;

use crate::utils::{
    block_hash_from_header, BlockParamHeight, BlockParamString, BlockRequest, BlockRequestByHeight,
    BlockResponse, Config, ValidatorsOrderedResponse,
};
use near_primitives::hash::CryptoHash;
use near_primitives::types::validator_stake::ValidatorStake;
use near_primitives::types::AccountId;

use near_crypto::PublicKey;
use near_primitives::block::BlockHeader;
use near_primitives::borsh::BorshSerialize;
use reqwest::Client;
use serde_json::json;
use sha2::Digest;
use std::fs;
use std::io::{Read, Write};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    println!("Current block  {:?}\n", block_response.result.header);

    let computed_block_hash =
        block_hash_from_header(BlockHeader::from(block_response.result.header.clone()));

    println!(
        "Calculated block hash from BlockHeader {:?} == {:?} BlockHeaderView\n",
        computed_block_hash.unwrap(), block_response.result.header.hash
    );

    assert_eq!(
        computed_block_hash.unwrap(),
        block_response.result.header.hash,
        "Computed block hash has to be equal to obtained from RPC BlockHeaderView\n"
    );

    let block_hash = block_response.result.header.hash.clone();
    let current_block_height = block_response.result.header.height as u128;

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

    // Calculates hash of a borsh-serialised representation of list of objects.
    //
    // This behaves as if it first collected all the items in the iterator into
    // a vector and then calculating hash of borsh-serialised representation of
    // that vector.
    //
    // Panics if the iterator lies about its length.
    let iter = validator_stakes;
    let n = u32::try_from(iter.len()).unwrap();
    let mut hasher = sha2::Sha256::default();
    hasher.write_all(&n.to_le_bytes()).unwrap();

    let count = iter
        .inspect(|value| {
            BorshSerialize::serialize(&value, &mut hasher).unwrap()
        }
        )
        .count();

    assert_eq!(n as usize, count);

    let computed_bp_hash = CryptoHash(hasher.clone().finalize().into());

    println!("Computed BP hash {:?}\n", hasher.clone().finalize().bytes());
    println!("Computed BP hash {:?}\n", computed_bp_hash);

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
        "Previous epoch block  {:?}\n",
        previous_epoch_block_response.result.header
    );

    println!(
        "computed hash {} == {} stored hash in previous epoch block\n",
        computed_bp_hash, previous_epoch_block_response.result.header.next_bp_hash
    );

    Ok(())
}

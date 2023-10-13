mod utils;

use crate::utils::{
    BlockParamHeight, BlockParamString, BlockRequest, BlockRequestByHeight, BlockResponse, Config,
    ValidatorsOrderedResponse,
};
use near_primitives::hash::CryptoHash;
use near_primitives::types::validator_stake::ValidatorStake;
use near_primitives::types::AccountId;

use near_crypto::PublicKey;
use reqwest::Client;
use serde_json::json;
use std::fs;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_str = fs::read_to_string("script/config.json").unwrap();
    let config: Config = serde_json::from_str(&config_str).unwrap();
    let block_hash = config.block_hash;

    let rpc_url = match config.network {
        0 => "https://rpc.testnet.near.org",
        1 => "https://rpc.mainnet.near.org",
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

    let block_response: BlockResponse = client
        .post(rpc_url)
        .json(&block_request)
        .send()
        .await?
        .json()
        .await?;

    println!("Current block  {:?}", block_response.result.header);

    let block_hash = block_response.result.header.hash.clone();
    let current_block_height = block_response.result.header.height;

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

    let computed_bp_hash = CryptoHash::hash_borsh_iter(validator_stakes);

    println!("Computed BP hash {:?}", computed_bp_hash);

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

    Ok(())
}

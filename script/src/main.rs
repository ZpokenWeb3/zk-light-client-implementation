mod utils;
mod calculate_bp_hash;

use tokio::time::{sleep, Duration};

use std::fs;
use std::fs::File;
use std::io::Write;
use std::str::FromStr;
use near_primitives::hash::CryptoHash;
use near_primitives::types::AccountId;
use reqwest::{Client, Response};
use serde_json::json;
use crate::utils::{BlockParamHeight, BlockParamString, BlockRequest, BlockRequestByHeight, BlockResponse, Config, ValidatorsOrderedRequest, ValidatorsOrderedResponse};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // let mut file = File::create("result_with_proofs.txt").expect("Unable to create file");
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

    let epoch_id = block_response.result.header.epoch_id.clone();
    let block_hash = block_response.result.header.hash.clone();

    let validators_ordered_request = json!({
        "jsonrpc": "2.0",
        "method": "EXPERIMENTAL_validators_ordered",
        "params": vec![block_hash],
        "id": "dontcare"
    });

    let validators_ordered_response_now: ValidatorsOrderedResponse = client
        .post(rpc_url)
        .json(&validators_ordered_request)
        .send()
        .await?
        .json()
        .await?;

    let validators_ordered_request_by_epoch_id = json!({
        "jsonrpc": "2.0",
        "method": "EXPERIMENTAL_validators_ordered",
        "params": vec![epoch_id],
        "id": "dontcare"
    });

    let validators_ordered_response_now_epoch_id: ValidatorsOrderedResponse = client
        .post(rpc_url)
        .json(&validators_ordered_request_by_epoch_id)
        .send()
        .await?
        .json()
        .await?;


    println!("block info now {:?}\n", block_response.result.header);
    println!("validators now  by epoch id {:?}\n", validators_ordered_response_now_epoch_id);
    println!("validators now by block id {:?}\n", validators_ordered_response_now);
    println!("next bp hash calculated now block id {:?}\n", CryptoHash::hash_borsh_iter(validators_ordered_response_now.result.iter().map(|validator| validator.stake.clone()).into_iter()));
    println!("next bp hash calculated now epoch id {:?}\n", CryptoHash::hash_borsh_iter(validators_ordered_response_now_epoch_id.result.iter().map(|validator| validator.stake.clone()).into_iter()));

    const BLOCKS_IN_EPOCH: u128 = 43_200;

    let block_hash = block_response.result.header.hash.clone();
    let current_block_height = block_response.result.header.height;
    let block_height_two_epoch_prior = current_block_height - 2 * BLOCKS_IN_EPOCH;

    let block_request_two_epoch_prior = BlockRequestByHeight {
        jsonrpc: "2.0",
        id: "dontcare",
        method: "block",
        params: BlockParamHeight {
            block_id: block_height_two_epoch_prior,
        },
    };

    let block_response_two_epochs_prior: BlockResponse = client
        .post(rpc_url)
        .json(&block_request_two_epoch_prior)
        .send()
        .await?
        .json()
        .await?;


    let epoch_id_two_epochs_prior = block_response_two_epochs_prior.result.header.epoch_id.clone();
    let epoch_id_two_epochs_prior_hash = block_response_two_epochs_prior.result.header.hash.clone();

    let validators_ordered_request = json!({
        "jsonrpc": "2.0",
        "method": "EXPERIMENTAL_validators_ordered",
        "params": vec![epoch_id_two_epochs_prior],
        "id": "dontcare"
    });

    let validators_ordered_response: ValidatorsOrderedResponse = client
        .post(rpc_url)
        .json(&validators_ordered_request)
        .send()
        .await?
        .json()
        .await?;



    let validators_ordered_request_hash = json!({
        "jsonrpc": "2.0",
        "method": "EXPERIMENTAL_validators_ordered",
        "params": vec![epoch_id_two_epochs_prior_hash],
        "id": "dontcare"
    });

    let validators_ordered_response_hash: ValidatorsOrderedResponse = client
        .post(rpc_url)
        .json(&validators_ordered_request_hash)
        .send()
        .await?
        .json()
        .await?;


    println!("\n\nblock info two epochs prior {:?}", block_response_two_epochs_prior.result.header);
    println!(" validators two epochs prior {:?}", validators_ordered_response);

    println!("hash borsh iter epoch {:?}", CryptoHash::hash_borsh_iter(validators_ordered_response.result.iter().map(|validator| validator.stake.clone()).into_iter()));

    println!("hash borsh iter hash {:?}", CryptoHash::hash_borsh_iter(validators_ordered_response_hash.result.iter().map(|validator| validator.stake.clone()).into_iter()));

    Ok(())
}

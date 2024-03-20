use std::{fs::File, io::Read, num::ParseIntError, str::FromStr};

use near_crypto::PublicKey;
use near_primitives::{
    block_header::BlockHeader,
    hash::CryptoHash,
    types::{AccountId, validator_stake::ValidatorStake},
    views::BlockHeaderView,
};
use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::types::{BlockParamString, BlockRequest, BlockResponse, ValidatorsOrderedResponse};

pub fn vec_u32_to_u8(data: &Vec<u32>) -> Vec<u8> {
    let capacity = 32 / 8 * data.len();
    let mut output = Vec::<u8>::with_capacity(capacity);
    for &value in data {
        output.push((value >> 24) as u8);
        output.push((value >> 16) as u8);
        output.push((value >> 8) as u8);
        output.push(value as u8);
    }
    output
}

pub fn vec_u8_to_u32(data: &Vec<u8>) -> Vec<u32> {
    let capacity = data.len() / 4 as usize;
    let mut output = Vec::<u32>::with_capacity(capacity);
    for i in (0..data.len()).step_by(4) {
        let value = ((data[i] as u32) << 24) | ((data[i + 1] as u32) << 16) | ((data[i + 2] as u32) << 8) | ((data[i + 3] as u32));
        output.push(value);
    }
    output
}

pub fn decode_hex(s: &String) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn get_sha256_hash(msg: &[u8]) -> Result<Vec<u8>, ParseIntError> {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let hash = hasher.finalize();
    decode_hex(&format!("{:x}", hash))
}

pub fn u8bit_to_u8byte(bits: &[u8]) -> Vec<u8> {
    assert!(bits.len() > 8);
    assert_eq!(bits.len() % 2, 0);
    let len = bits.len() / 8;
    let mut bytes: Vec<u8> = (0..len).map(|_| 0).collect();
    let mut j = 7;
    for i in 0..bits.len() {
        bytes[i / 8] |= bits[i] << j;
        j -= 1;
    }
    bytes
}

/// Loads a block header from a JSON file.
///
/// # Arguments
///
/// * `path` - A string slice representing the path to the JSON file containing block header data.
///
/// # Returns
///
/// Returns a result containing the block hash and the corresponding `BlockHeader` if the operation succeeds.
pub fn load_block_header(path: &str) -> Result<(CryptoHash, BlockHeader), anyhow::Error> {
    let mut file = File::open(path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    let block_response: BlockHeaderView = serde_json::from_str(&data)?;
    let block_header: BlockHeader = BlockHeader::from(block_response.clone());
    Ok((block_response.hash, block_header))
}

/// Loads a block and its header from an RPC endpoint.
///
/// This asynchronous function sends a request to the Near RPC endpoint to retrieve
/// information about a block identified by its hash.
///
/// # Arguments
///
/// * `hash` - A string slice representing the hash of the block to be loaded.
///
/// # Returns
///
/// Returns a result containing a tuple with the block hash and its header if the operation succeeds.
///
/// # Errors
///
/// Returns an error if there are any issues with the RPC request or response handling.
pub async fn load_block_from_rpc(hash: &str) -> Result<(CryptoHash, BlockHeader), anyhow::Error> {
    let rpc_url = "https://compatible-light-crater.near-mainnet.quiknode.pro/332447effce5b1cec9f320e24bc52cfa62882e1a/";

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let block_request = BlockRequest {
        jsonrpc: "2.0",
        id: "dontcare",
        method: "block",
        params: BlockParamString {
            block_id: hash.parse().unwrap(),
        },
    };

    let block_response: BlockResponse = client
        .post(rpc_url)
        .json(&block_request)
        .send()
        .await?
        .json()
        .await?;
    let header = BlockHeader::from(block_response.result.header);

    Ok((*header.hash(), header))
}

/// Loads validators and their stakes from a JSON file.
///
/// This function reads validator data from the specified JSON file located at `path`.
/// The JSON file should contain a list of validators with their account IDs, public keys,
/// and stakes. The function parses this JSON data and constructs a vector of `ValidatorStake`
/// structs representing each validator along with their stake.
///
/// # Arguments
///
/// * `path` - A string slice representing the path to the JSON file containing validator data.
///
/// # Returns
///
/// Returns a result containing a vector of `ValidatorStake` structs if the operation succeeds.
///
/// # Errors
///
/// Returns an error if there are any issues reading or parsing the JSON file.
pub fn load_validators(path: &str) -> Result<Vec<ValidatorStake>, anyhow::Error> {
    let mut file = File::open(path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    let validator_response: ValidatorsOrderedResponse = serde_json::from_str(&data)?;
    let validator_stakes: Vec<ValidatorStake> = validator_response
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
    Ok(validator_stakes)
}

/// Asynchronously loads validator information from RPC endpoint.
///
/// # Arguments
///
/// * `block_hash` - A string representing the hash of the block for which validator information is requested.
///
/// # Returns
///
/// Returns a `Result` containing a vector of `ValidatorStake` objects representing validator information
/// if the operation is successful.
///
/// # Errors
///
/// This function may return an error if:
///
/// * The RPC call fails.
/// * The response from the RPC server is invalid or cannot be parsed.
/// * Validator data cannot be deserialized into `ValidatorStake` objects.
pub async fn load_validators_from_rpc(
    block_hash: &str,
) -> Result<Vec<ValidatorStake>, anyhow::Error> {
    let rpc_url = "https://compatible-light-crater.near-mainnet.quiknode.pro/332447effce5b1cec9f320e24bc52cfa62882e1a/";

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

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

    let _validators_ordered_json_data =
        serde_json::to_string(&validators_ordered_response).unwrap();

    // -------------- serializing EXPERIMENTAL_validators_ordered into ValidatorStake structure --------------

    let validator_stakes = validators_ordered_response
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

    Ok(validator_stakes)
}

use anyhow::Result;
use crate::types::{BlockParamString, BlockParamHeight, BlockRequest, BlockRequestByHeight, BlockResponse, RpcErrorResponse, ValidatorsOrderedResponse, HeaderDataFields};
use near_crypto::PublicKey;
use near_primitives::{
    block_header::BlockHeader,
    hash::CryptoHash,
    types::{validator_stake::ValidatorStake, AccountId},
    views::BlockHeaderView,
    borsh,
};
use reqwest::Client;
use serde_json::json;
use std::{env, fs::File, io::Read, str::FromStr};

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

/// Loads a block hash from a JSON file, simulating loading a hash from a contract.
///
/// # Arguments
///
/// * `path` - A string slice representing the path to the JSON file containing block hash.
///
/// # Returns
///
/// Returns a result containing the block hash and the corresponding `BlockHeader` if the operation succeeds.
pub fn load_block_hash(path: &str) -> Result<CryptoHash, anyhow::Error> {
    let mut file = File::open(path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    let block_hash: CryptoHash = serde_json::from_str(&data)?;
    Ok(block_hash)
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
    let rpc_url = env::var("NEAR_RPC").expect("NEAR_PRC parameter missed");

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

    let block_response_text = client
        .post(rpc_url)
        .json(&block_request)
        .send()
        .await?
        .text()
        .await?;

    println!("Raw response: {}", block_response_text);

    // Try to parse it as a successful BlockResponse or an error RpcErrorResponse
    if let Ok(block_response) = serde_json::from_str::<BlockResponse>(&block_response_text) {
        // Handle the successful block response
println!("HASH: {:#?}", block_response);
        let header = BlockHeader::from(block_response.result.header);
        Ok((*header.hash(), header))
    } else if let Ok(rpc_error_response) = serde_json::from_str::<RpcErrorResponse>(&block_response_text) {
        // Handle the error response
        eprintln!(
            "RPC Error: {} - {:?}",
            rpc_error_response.error.message,
            rpc_error_response.error
        );
        Err(anyhow::Error::msg(format!(
            "RPC request failed: {}",
            rpc_error_response.error.message
        )))
    } else {
        // If we couldn't parse the response, return a generic error
        Err(anyhow::Error::msg("Failed to parse RPC response"))
    }
}

/// Loads a block and its header from an RPC endpoint.
///
/// This asynchronous function sends a request to the Near RPC endpoint to retrieve
/// information about a block identified by its hash.
///
/// # Arguments
///
/// * `height` - Represents the height of the block to be loaded.
///
/// # Returns
///
/// Returns a result containing a tuple with the block hash and its header if the operation succeeds.
///
/// # Errors
///
/// Returns an error if there are any issues with the RPC request or response handling.
pub async fn load_block_by_height_from_rpc(height: u64) -> Result<(CryptoHash, BlockHeader), anyhow::Error> {
    let rpc_url = env::var("NEAR_RPC").expect("NEAR_PRC parameter missed");

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let block_request = BlockRequestByHeight {
        jsonrpc: "2.0",
        id: "dontcare",
        method: "block",
        params: BlockParamHeight {
            block_id: height,
        },
    };

    let block_response_text = client
        .post(rpc_url)
        .json(&block_request)
        .send()
        .await?
	.text()
        .await?;

    println!("Raw response: {}", block_response_text);

    // Try to parse it as a successful BlockResponse or an error RpcErrorResponse
    if let Ok(block_response) = serde_json::from_str::<BlockResponse>(&block_response_text) {
        // Handle the successful block response
        let header = BlockHeader::from(block_response.result.header);
        Ok((*header.hash(), header))
    } else if let Ok(rpc_error_response) = serde_json::from_str::<RpcErrorResponse>(&block_response_text) {
        // Handle the error response
        eprintln!(
            "RPC Error: {} - {:?}",
            rpc_error_response.error.message,
            rpc_error_response.error
        );
        Err(anyhow::Error::msg(format!(
            "RPC request failed: {}",
            rpc_error_response.error.message
        )))
    } else {
        // If we couldn't parse the response, return a generic error
        Err(anyhow::Error::msg("Failed to parse RPC response"))
    }
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
    let rpc_url = env::var("NEAR_RPC").expect("NEAR_PRC parameter missed");

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

/// Set data for the given epochs.
///
/// # Arguments
///
/// # When proving randomly selected blocks, the function sets {epoch_id_i, epoch_id_i_1, epoch_id_i_2}.
/// # epoch_id_i is used for Block_i. epoch_id_i_1 is used for bp_hash for epoch_id_i. epoch_id_i_2 is used for epoch_id for epoch_id_i.
///
/// # When proving epoch  blocks, the function sets {epoch_id_i, epoch_id_i_1, epoch_id_i_2, epoch_id_i_3}.
/// # epoch_id_i is used for Block_0. epoch_id_i_1 is used for Block_n-1 and bp_hash for epoch_id_i.
/// # epoch_id_i_2 is used for bp_hash for epoch_id_i_1 and epoch_id for epoch_id_i.
/// # epoch_id_i_3 is used for epoch_id for epoch_id_i.
///
/// * `epoch_id_i` - Epoch_id of the epoch, where the chosen block is.
/// * `epoch_id_i_1` - Epoch_id of Epoch_i-1.
/// * `epoch_id_i_2` - Epoch_id of Epoch_i-2.
/// * `epoch_id_i_3` - Epoch_id of Epoch_i-3.
///
/// # Returns
///
/// Returns an array representing data used to prove block BFT finality:
/// * Epoch blocks that are used to prove bp_hash & epoch_id.
///   Hashes & blocks for Block_0 & Block_n-1 to prove bp_hash & epoch_id -> Vec<(Vec<u8>, Vec<u8>)>.
///   It is represented in the following form: [Block_0 (Epoch_i-1), Block_n-1 (Epoch_i-2), Block_n-1 (Epoch_i-3) (to prove new epoch blocks)].
/// * Blocks that are used to prove BFT finality of the chosen block(s).
///   Specified block data and blocks -> Vec<(BlockDataForFinality, Vec<u8>)>.
///   It is represented in the following form: [Block_i+4, Block_i+3, Block_i+2, Block_i+1, Block_i] to prove random Block_i.
///   It is represented in the following form: [Block_i+4, Block_i+3, Block_i+2, Block_i+1, Block_0, Block_n-1] to prove new epoch blocks.
///
pub fn set_blocks(
    // for Block_i or Block_0->epoch blocks
    epoch_id_i: String,
    // for Block_0 and/or Block_n-1->epoch blocks
    epoch_id_i_1: String,
    // for Block_n-1
    epoch_id_i_2: String,
    // for Block_n-1
    epoch_id_i_3: Option<String>,
) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, Vec<(HeaderDataFields, Vec<u8>)>)> {
    // Extract epoch blocks: Block_0, Block_n-1, Block_n-1 (optionally).
    let mut epoch_blocks: Vec<(Vec<u8>, Vec<u8>)> = vec![];
    // Extract blocks to prove finality: Block_i+4, Block_i+3, Block_i+2, Block_i+1, Block_i/Block_0, Block_n-1.
    let mut blocks: Vec<(HeaderDataFields, Vec<u8>)> = vec![];

    // Search for folder by epoch_id_i_1.
    // Extract Block_0 header.
    let mut folder = epoch_id_i_1.clone();
    let mut file = "block-0.json".to_string();
    let mut path = format!("../data/epochs/{folder}/{file}");
    let (_, mut block_data) = load_block_header(&path)?;
    // Extract Block_0 hash (it should be stored in the contract).
    folder = epoch_id_i_1.clone() + "_STORED";
    path = format!("../data/epochs/{folder}/{file}");
    let mut block_hash = load_block_hash(&path)?;
    epoch_blocks.push((borsh::to_vec(&block_hash)?, borsh::to_vec(&block_data)?));

    // Search for folder by epoch_id_i_2.
    // Extract Block_n-1.
    folder = epoch_id_i_2.clone();
    file = "block-last.json".to_string();
    path = format!("../data/epochs/{folder}/{file}");
    (_, block_data) = load_block_header(&path)?;
    // Extract Block_n-1 hash (it should be stored in the contract).
    folder = epoch_id_i_2.clone() + "_STORED";
    path = format!("../data/epochs/{folder}/{file}");
    block_hash = load_block_hash(&path)?;
    epoch_blocks.push((borsh::to_vec(&block_hash)?, borsh::to_vec(&block_data)?));

    // Set Block_n-1 (Epoch_i-3) optionally.
    if let Some(epoch_id_i_3) = epoch_id_i_3.clone() {
        // Search for folder by epoch_id_i_3.
        // Extract Block_n-1.
        folder = epoch_id_i_3.clone();
        file = "block-last.json".to_string();
        path = format!("../data/epochs/{folder}/{file}");
        (_, block_data) = load_block_header(&path)?;
        // Extract Block_n-1 hash (it should be stored in the contract).
        folder = epoch_id_i_3.clone() + "_STORED";
        path = format!("../data/epochs/{folder}/{file}");
        block_hash = load_block_hash(&path)?;
        epoch_blocks.push((borsh::to_vec(&block_hash)?, borsh::to_vec(&block_data)?));
    }

    // Define block type.
    let block_type = match epoch_id_i_3 {
        Some(_) => "block-".to_string(),
        None => "random-".to_string(),
    };

    // There should be at least five consecutive blocks to prove BFT finality.
    let mut block_num = 4;
    let mut i = 0;
    folder = epoch_id_i.clone();
    while block_num >= 0 {
        // Search for folders by blocks_hash_i. Extract blocks.
        file = block_type.clone() + block_num.to_string().as_str() + ".json";
        path = format!("../data/epochs/{folder}/{file}");
        (block_hash, block_data) = load_block_header(&path)?;
        let mut approvals: Option<Vec<Vec<u8>>> = None;
        approvals = Some(
            block_data
                .approvals()
                .iter()
                .map(|approval| borsh::to_vec(approval).unwrap())
                .collect(),
        );

        let block = HeaderDataFields {
            hash: block_hash.0.to_vec(),
            height: Some(block_data.height()),
            prev_hash: Some(block_data.prev_hash().0.to_vec()),
            bp_hash: Some(block_data.next_bp_hash().0.to_vec()),
            epoch_id: Some(block_data.epoch_id().0 .0.to_vec()),
            next_epoch_id: Some(block_data.next_epoch_id().0 .0.to_vec()),
            last_ds_final_hash: Some(block_data.last_ds_final_block().0.to_vec()),
            last_final_hash: Some(block_data.last_final_block().0.to_vec()),
            approvals,
        };

        blocks.push((block, borsh::to_vec(&block_data)?));

        block_num -= 1;
        i += 1;
    }

    // Set the sixth block (Block_n-1) if the function proves the epoch blocks.
    if let Some(epoch_id_i_3) = epoch_id_i_3.clone() {
        // Search for folders by blocks_hash_i. Extract blocks. Extract Block_n-1.
        folder = epoch_id_i_1.clone();
        file = "block-last.json".to_string();
        path = format!("../data/epochs/{folder}/{file}");
        (block_hash, block_data) = load_block_header(&path)?;
        let block = HeaderDataFields {
            hash: block_hash.0.to_vec(),
            height: Some(block_data.height()),
            prev_hash: Some(block_data.prev_hash().0.to_vec()),
            bp_hash: Some(block_data.next_bp_hash().0.to_vec()),
            epoch_id: Some(block_data.epoch_id().0 .0.to_vec()),
            next_epoch_id: Some(block_data.next_epoch_id().0 .0.to_vec()),
            last_ds_final_hash: Some(block_data.last_ds_final_block().0.to_vec()),
            last_final_hash: Some(block_data.last_final_block().0.to_vec()),
            approvals: None,
        };
        blocks.push((block, borsh::to_vec(&block_data)?));
    }

    Ok((epoch_blocks, blocks))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;

    #[test]
    fn test_vec_u32_to_u8() {
        let data = vec![0x11223344, 0xAABBCCDD];
        assert_eq!(
            vec_u32_to_u8(&data),
            vec![0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD]
        );
    }

    #[test]
    fn test_vec_u32_to_u8_random() {
        for i in 0..10000 {
            let data: Vec<u32> = (0..i).map(|_| random::<u32>() as u32).collect();
            vec_u32_to_u8(&data);
        }
    }

    #[test]
    fn test_load_block_header() -> Result<(), anyhow::Error> {
        let block_data = load_block_header("../data/next_block_header.json");
        assert!(block_data.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_load_block_from_rpc() -> Result<(), anyhow::Error> {
        env::set_var("NEAR_RPC", "https://rpc.mainnet.near.org");
        let block_data = load_block_from_rpc("RuywEaMPnWXkTuRU6LN376T435MnEvb4oeNo5hhMPED").await;
        assert!(block_data.is_ok());
        Ok(())
    }

    #[test]
    fn test_load_validators() -> Result<(), anyhow::Error> {
        let validators = load_validators("../data/validators_ordered.json");
        assert!(validators.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn test_load_validators_from_rpc() -> Result<(), anyhow::Error> {
        env::set_var("NEAR_RPC", "https://rpc.mainnet.near.org");
        let validators =
            load_validators_from_rpc("RuywEaMPnWXkTuRU6LN376T435MnEvb4oeNo5hhMPED").await;
        assert!(validators.is_ok());
        Ok(())
    }
}

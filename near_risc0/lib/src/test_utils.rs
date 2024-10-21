use std::fs::File;
use std::io::Read;
use std::str::FromStr;

use anyhow::Result;
use near_primitives_core::hash::CryptoHash;
use near_primitives_core::types::AccountId;

use near_primitives::{block_header::BlockHeader, views::BlockHeaderView};

use crate::types::{types::*, validators::*};
use crate::types::responses::ValidatorsOrderedResponse;
use crate::types::signature::PublicKey;

/// Parses a block hash string into a `CryptoHash` object.
pub fn parse_block_hash(block_hash: &str) -> Result<CryptoHash> {
    let block_hash: CryptoHash = match CryptoHash::from_str(block_hash) {
        Ok(hash) => hash,
        Err(e) => return Err(anyhow::anyhow!("Failed to parse block hash: {}", e)),
    };

    Ok(block_hash)
}

pub fn load_block_header(path: &str) -> Result<(CryptoHash, BlockHeader), anyhow::Error> {
    let mut file = File::open(path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    let block_response: BlockHeaderView = serde_json::from_str(&data)?;
    let block_header: BlockHeader = BlockHeader::from(block_response.clone());
    let block_hash: CryptoHash = CryptoHash(block_header.hash().0);
    Ok((block_hash, block_header))
}

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

pub fn load_block_hash(path: &str) -> Result<CryptoHash, anyhow::Error> {
    let mut file = File::open(path)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    let block_hash: CryptoHash = serde_json::from_str(&data)?;
    Ok(block_hash)
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
/// * `main_path` - The path to the directory that contains data of the specified epochs.
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
    main_path: &str,
    // for Block_i or Block_0->epoch blocks
    epoch_id_i: String,
    // for Block_0 and/or Block_n-1->epoch blocks
    epoch_id_i_1: String,
    // for Block_n-1
    epoch_id_i_2: String,
    // for Block_n-1
    epoch_id_i_3: Option<String>,
) -> Result<(Vec<Block>, Vec<Block>)> {
    // Extract epoch blocks: Block_0, Block_n-1, Block_n-1 (optionally).
    let mut epoch_blocks: Vec<Block> = vec![];
    // Extract blocks to prove finality: Block_i+4, Block_i+3, Block_i+2, Block_i+1, Block_i/Block_0, Block_n-1.
    let mut blocks: Vec<Block> = vec![];

    // Search for folder by epoch_id_i_1.
    // Extract Block_0 header.
    let mut folder = epoch_id_i_1.clone();
    let mut file = "block-0.json".to_string();
    let mut path = format!(
        "{}/{}/{}",
        main_path,
        folder,
        file
    );
    let (_, mut block_data) = load_block_header(&path)?;
    // Extract Block_0 hash (it should be stored in the contract).
    folder = epoch_id_i_1.clone() + "_STORED";
    path = format!(
        "{}/{}/{}",
        main_path,
        folder,
        file
    );
    let mut block_hash = load_block_hash(&path)?;
    epoch_blocks.push(Block::try_from((block_hash, block_data, BlockType::BLOCK))?);

    // Search for folder by epoch_id_i_2.
    // Extract Block_n-1.
    folder = epoch_id_i_2.clone();
    file = "block-last.json".to_string();
    path = format!(
        "{}/{}/{}",
        main_path,
        folder,
        file
    );
    (_, block_data) = load_block_header(&path)?;
    // Extract Block_n-1 hash (it should be stored in the contract).
    folder = epoch_id_i_2.clone() + "_STORED";
    path = format!(
        "{}/{}/{}",
        main_path,
        folder,
        file
    );
    block_hash = load_block_hash(&path)?;
    epoch_blocks.push(Block::try_from((block_hash, block_data, BlockType::BLOCK))?);

    // Set Block_n-1 (Epoch_i-3) optionally.
    if let Some(epoch_id_i_3) = epoch_id_i_3.clone() {
        // Search for folder by epoch_id_i_3.
        // Extract Block_n-1.
        folder = epoch_id_i_3.clone();
        file = "block-last.json".to_string();
        path = format!(
            "{}/{}/{}",
            main_path,
            folder,
            file
        );
        (_, block_data) = load_block_header(&path)?;
        // Extract Block_n-1 hash (it should be stored in the contract).
        folder = epoch_id_i_3.clone() + "_STORED";
        path = format!(
            "{}/{}/{}",
            main_path,
            folder,
            file
        );
        block_hash = load_block_hash(&path)?;
        epoch_blocks.push(Block::try_from((block_hash, block_data, BlockType::BLOCK))?);
    }

    // Define block type.
    let block_type = match epoch_id_i_3 {
        Some(_) => "block-".to_string(),
        None => "random-".to_string(),
    };

    // There should be at least five consecutive blocks to prove BFT finality.
    let mut block_num = 4;
    folder = epoch_id_i.clone();
    while block_num >= 0 {
        // Search for folders by blocks_hash_i. Extract blocks.
        file = block_type.clone() + block_num.to_string().as_str() + ".json";
        path = format!(
            "{}/{}/{}",
            main_path,
            folder,
            file
        );
        (block_hash, block_data) = load_block_header(&path)?;
        blocks.push(Block::try_from((block_hash, block_data, BlockType::RANDOM))?);
        block_num -= 1;
    }

    // Set the sixth block (Block_n-1) if the function proves the epoch blocks.
    if let Some(_) = epoch_id_i_3.clone() {
        // Search for folders by blocks_hash_i. Extract blocks. Extract Block_n-1.
        folder = epoch_id_i_1.clone();
        file = "block-last.json".to_string();
        path = format!(
            "{}/{}/{}",
            main_path,
            folder,
            file
        );
        (block_hash, block_data) = load_block_header(&path)?;
        blocks.push(Block::try_from((block_hash, block_data, BlockType::RANDOM))?);
    }

    Ok((epoch_blocks, blocks))
}

/// Set validators for the given epochs.
///
/// # Arguments
///
/// * `main_path` - The path to the directory that contains data of the specified epochs.
/// * `num_epoch_blocks` - number of epochs: 3 to prove randomly selected block, 4 for epoch blocks.
/// * `epoch_id_i` - Hash of the Epoch i.
/// * `epoch_id_i_1` - Hash of the Epoch i-1.
///
/// # Returns
///
/// Returns the list of validators for the given epochs.
///
pub fn set_validators(
    main_path: &str,
    num_epoch_blocks: usize,
    epoch_id_i: &str,
    epoch_id_i_1: &str,
) -> Result<Validators> {
    let path = format!(
        "{}/{}/validators.json",
        main_path,
        epoch_id_i,
    );
    let validators: Vec<ValidatorStake> = load_validators(&path)?.try_into().expect("Error validators.");
    // Load list of validators for Epoch_i-1 from RPC for Block_n-1.
    let mut validators_n_1: Option<Vec<ValidatorStake>> = None;
    if num_epoch_blocks == 3 {
        let path = format!(
            "{}/{}/validators.json",
            main_path,
            epoch_id_i_1,
        );
        let validators = load_validators(&path)?.try_into().expect("Error validators.");
        validators_n_1 = Some(validators);
    }
    Ok(Validators {
        validators_n: validators,
        validators_n_1,
    })
}



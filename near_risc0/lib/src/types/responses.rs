use serde::{Deserialize, Serialize};

use near_primitives::types::AccountId;
use near_primitives::views::{BlockHeaderView, ChunkHeaderView};
use near_primitives::views::validator_stake_view::ValidatorStakeView;

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockResponse {
    pub result: BlockView,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorStakeResponse {
    pub result: Vec<ValidatorStakeView>,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorsOrderedResponse {
    pub result: Vec<ValidatorOrdered>,
}

/// Represents an ordered validator structure.
///
/// This structure defines the ordered data of a validator, including the account ID (`account_id`),
/// the public key (`public_key`), the stake amount (`stake`), and the version of the validator
/// stake structure (`validator_stake_struct_version`).
///
/// # Fields
///
/// * `account_id` - A string representing the account ID of the validator.
/// * `public_key` - A string representing the public key of the validator.
/// * `stake` - A string representing the stake amount of the validator.
/// * `validator_stake_struct_version` - A string representing the version of the validator stake structure.
///
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorOrdered {
    pub account_id: String,
    pub public_key: String,
    pub stake: String,
    pub validator_stake_struct_version: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub block_hash: String,
    pub network: u8,
}

#[derive(Debug, Serialize)]
pub struct BlockRequest {
    pub jsonrpc: &'static str,
    pub id: &'static str,
    pub method: &'static str,
    pub params: BlockParamString,
}

#[derive(Debug, Serialize)]
pub struct BlockRequestByHeight {
    pub jsonrpc: &'static str,
    pub id: &'static str,
    pub method: &'static str,
    pub params: BlockParamHeight,
}

#[derive(Debug, Serialize)]
pub struct BlockParamString {
    pub block_id: String,
}

#[derive(Debug, Serialize)]
pub struct BlockParamHeight {
    pub block_id: u64,
}

#[derive(Debug, Serialize)]
pub struct BlockParamFinality {
    pub finality: String,
}

/// Represents a view of a block.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BlockView {
    /// NEAR Account Identifier.
    pub author: AccountId,
    /// The header of the block.
    pub header: BlockHeaderView,
    pub chunks: Vec<ChunkHeaderView>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Chunk {
    pub chunk_hash: String,
    pub outcome_root: String,
    pub prev_state_root: String,
}

#[derive(Debug, Serialize)]
pub struct ValidatorsOrderedRequest {
    pub jsonrpc: &'static str,
    pub id: &'static str,
    pub method: &'static str,
    pub params: Vec<&'static str>,
}

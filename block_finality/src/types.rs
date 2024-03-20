use near_primitives::block_header::BlockHeader;
use near_primitives::hash::CryptoHash;
use near_primitives::types::AccountId;
use near_primitives::views::{BlockHeaderView, validator_stake_view::ValidatorStakeView};
use near_primitives::views::ChunkHeaderView;
use serde::{Deserialize, Serialize};

/// Represents the type for signature & public key in bytes.
pub const TYPE_BYTE: usize = 1;
/// Represents the size of protocol version in bytes.
pub const PROTOCOL_VERSION_BYTES: usize = 4;
/// Represents the size of block height in bytes.
pub const BLOCK_HEIGHT_BYTES: usize = 8;
/// Represents the size of stake in bytes.
pub const STAKE_BYTES: usize = 16;
/// Represents the size of a public key in bytes.
pub const PK_BYTES: usize = 32;
/// Represents the size of a signature in bytes.
pub const SIG_BYTES: usize = 64;
/// Represents the size of a inner lite part of a block in bytes.
pub const INNER_LITE_BYTES: usize = 208;

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockResponse {
    pub result: BlockView,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorStakeResponse {
    pub result: Vec<ValidatorStakeView>,
}

/// Represents the data of a block header.
///
/// # Fields
///
/// * `prev_hash` - A vector of bytes representing the hash of the previous block.
/// * `inner_lite` - A vector of bytes representing the lite inner part of the header.
/// * `inner_rest` - A vector of bytes representing the rest of the inner part of the header.
///
pub struct HeaderData {
    pub prev_hash: Vec<u8>,
    pub inner_lite: Vec<u8>,
    pub inner_rest: Vec<u8>,
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
    pub block_id: u128,
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

/// Represents the input data for proving signatures in parallel using distributed system nats.
#[derive(Deserialize, Serialize)]
pub struct InputTask {
    /// The message data for the signature.
    pub message: Vec<u8>,
    /// The approval data for the signature.
    pub approval: Vec<u8>,
    /// The validator data for the signature.
    pub validator: Vec<u8>,
    /// The index of the signature in array of approvals.
    pub signature_index: usize,
}

/// Represents the output data after proving signatures in parallel using distributed system nats.
#[derive(Serialize, Deserialize)]
pub struct OutputTask {
    /// The proof data generated during the signature proving process.
    pub proof: Vec<u8>,
    /// The verifier data generated during the proving process.
    pub verifier_data: Vec<u8>,
    /// The index of the signature in array of approvals.
    pub signature_index: usize,
}

/// Retrieve the block hash from a block header.
pub fn block_hash_from_header(header: BlockHeader) -> Option<CryptoHash> {
    Some(*header.hash())
}
use near_primitives::block::BlockHeader;
use near_primitives::hash::CryptoHash;
use near_primitives::types::AccountId;
use near_primitives::views::{BlockHeaderView, ChunkHeaderView};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockResponse {
    pub result: BlockView,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BlockView {
    pub author: AccountId,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorsOrderedResponse {
    pub result: Vec<ValidatorOrdered>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorOrdered {
    pub account_id: String,
    pub public_key: String,
    pub stake: String,
    pub validator_stake_struct_version: String,
}

pub fn block_hash_from_header(header: BlockHeader) -> Option<CryptoHash> {
    Some(*header.hash())
}

use near_primitives::views::ViewStateResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct ViewStateRequest {
    pub jsonrpc: &'static str,
    pub id: &'static str,
    pub method: &'static str,
    pub params: ViewStateParams,
}

#[derive(Debug, Serialize)]
pub struct ViewStateParams {
    pub request_type: &'static str,
    pub finality: &'static str,
    pub account_id: String,
    pub prefix_base64: &'static str,
    pub include_proof: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewStateResponseForProof {
    pub result: ViewStateResult,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewStateResponseForValues {
    pub result: ViewStateResultForValues,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct ViewStateResultForValues {
    pub block_hash: String,
    pub values: Vec<StateItemForValue>,
    pub proof: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct StateItemForValue {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResultData {
    pub block_height: u128,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct StateItemValues {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub account: String,
    pub network: u8,
}

#[derive(Debug, Serialize)]
pub struct BlockRequestOptionOne {
    pub jsonrpc: &'static str,
    pub id: &'static str,
    pub method: &'static str,
    pub params: BlockParamString,
}

#[derive(Debug, Serialize)]
pub struct BlockRequestOptionTwo {
    pub jsonrpc: &'static str,
    pub id: &'static str,
    pub method: &'static str,
    pub params: BlockParamBlockHeight,
}

#[derive(Debug, Serialize)]
pub struct BlockParamString {
    pub block_id: String,
}

#[derive(Debug, Serialize)]
pub struct BlockParamBlockHeight {
    pub block_id: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockResponse {
    pub result: BlockResultData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockResultData {
    pub author: String,
    pub chunks: Vec<Chunk>,
    pub header: BlockHeader,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Chunk {
    pub chunk_hash: String,
    pub outcome_root: String,
    pub prev_state_root: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub block_merkle_root: String,
    pub prev_state_root: String,
    pub height: u128,
}

// pub fn decode_base64(encoded: &str) -> Result<String, &'static str> {
//     // Decode the base64 string to bytes
//     let decoded_bytes = match base64::decode(encoded) {
//         Ok(bytes) => bytes,
//         Err(_) => return Err("Invalid base64 encoding"),
//     };
//
//     // Convert the bytes to a UTF-8 string
//     match String::from_utf8(decoded_bytes) {
//         Ok(decoded_string) => Ok(decoded_string),
//         Err(_) => Err("Invalid UTF-8 sequence"),
//     }
// }

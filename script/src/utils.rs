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
    pub hash: String,
    pub prev_hash: String,
    pub block_merkle_root: String,
    pub prev_state_root: String,
    pub height: u128,
    pub next_bp_hash: String,
    pub epoch_id: String,
    pub next_epoch_id: String,
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

//
// #[derive(Debug, Serialize)]
// pub struct ValidatorsRequest {
//     pub jsonrpc: &'static str,
//     pub id: &'static str,
//     pub method: &'static str,
//     pub params: EpochIdParam,
// }
//
//
// #[derive(Debug, Serialize)]
// pub struct EpochIdParam {
//     pub epoch_id: String,
// }
// //
//
// #[derive(Debug, Serialize, Deserialize)]
// pub struct ValidatorsResponse {
//     pub result: ValidatorsResponseData,
// }
//
// #[derive(Debug, Serialize, Deserialize)]
// pub struct ValidatorsResponseData {
//     pub current_validators: Vec<Validator>,
//     pub epoch_height: u128,
//     pub epoch_start_height: u128,
//     pub next_validators: Vec<Validator>,
// }
//
//
// #[derive(Debug, Serialize, Deserialize)]
// pub struct Validator {
//     pub account_id: String,
//     pub public_key: String,
//     pub shards: Vec<u128>,
//     pub stake: u128,
// }



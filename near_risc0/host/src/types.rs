use std::fmt::Display;
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, )]
pub struct EpochProvingTask {
    #[serde(rename = "currentEpochHash")]
    pub epoch_id_i_block_hash: String,

    #[serde(rename = "prevEpochStartHash")]
    pub epoch_id_i_1_block_hash: String,

    #[serde(rename = "prevEpochMinus1EndHash")]
    pub epoch_id_i_2_block_hash: String,

    #[serde(rename = "prevEpochMinus2EndHash")]
    pub epoch_id_i_3_block_hash_last: String,

    #[serde(rename = "prevEpochEndHash")]
    pub epoch_id_i_1_block_hash_last: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, )]
pub struct RandomProvingTask {
    #[serde(rename = "currentBlockHash")]
    pub epoch_id_i_hash_i: String,

    #[serde(rename = "previousEpochStartHash")]
    pub epoch_id_i_1_hash_0: String,

    #[serde(rename = "previousEpochEndHash")]
    pub epoch_id_i_2_hash_last_str: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, )]
pub struct RandomProvingResult {
    #[serde(rename = "currentBlockHash")]
    pub epoch_id_i_block_hash: String,

    pub journal: String,

    pub proof: String,

    pub status: String,
}


#[derive(Serialize, Deserialize, Debug, Clone, )]
pub struct EpochProvingResult {
    #[serde(rename = "currentBlockHash")]
    pub block_hash_n_0: String,

    #[serde(rename = "currentBlockHeight")]
    pub block_height_n_0: u64,

    #[serde(rename = "previousBlockHash")]
    pub block_hash_n_1: String,

    pub status: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, )]
pub struct VerificationRequest {
    pub receipt: Receipt,
}


#[derive(Serialize, Deserialize, Debug, Clone, )]
pub struct VerificationResponse {
    pub status: String,
}

#[derive(Serialize, Deserialize)]
pub struct HealthCheckTask {
    pub status: String,
}
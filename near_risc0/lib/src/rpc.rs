use std::str::FromStr;
use std::time::Duration;

use near_primitives_core::hash::CryptoHash;

use serde::Deserialize;
use serde_json::{json, Value};
use thiserror::Error;

use crate::test_utils::parse_block_hash;
use crate::types::native::ProverInput;
use crate::types::responses::{BlockParamHeight, BlockParamString, BlockResponse, ValidatorsOrderedResponse};
use crate::types::types::{Block, BlockType};
use near_crypto::PublicKey;
use near_primitives::block_header::BlockHeader;
use near_primitives::types::validator_stake::ValidatorStake;
use near_primitives::types::AccountId;
use reqwest::{Client, Response};

#[derive(Deserialize, Debug)]
struct RpcErrorResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: String,
    error: RpcError,
}

#[derive(Deserialize, Debug)]
struct RpcError {
    #[allow(dead_code)]
    code: i32,
    message: String,
    #[allow(dead_code)]
    data: String,
    name: String,
    cause: CauseDetails,
}

#[derive(Deserialize, Debug)]
struct CauseDetails {
    #[allow(dead_code)]
    info: std::collections::HashMap<String, String>,
    name: String,
}

#[derive(Debug, Error, Clone)]
pub enum JsonClientError {
    /// Indicates that an unknown block was requested.
    ///
    /// # Arguments
    /// * `String` - The name of error cause.
    ///
    /// # Possible Causes
    /// - The requested block has not been produced yet.
    /// - The block has been garbage-collected by the node.
    ///
    /// # Suggested Solutions
    /// - Verify that the requested block exists.
    /// - If the block was produced more than 5 epochs ago, try requesting it from an archival node.
    #[error("Unknown block: {0}")]
    UnknownBlock(String),

    /// Indicates that the node is still syncing and cannot fulfill the request.
    ///
    /// # Arguments
    /// * `String` - The name of error cause.
    ///
    /// # Possible Causes
    /// - The requested block is not yet available in the node's database because the node is still syncing.
    ///
    /// # Suggested Solutions
    /// - Wait until the node finishes syncing.
    /// - Alternatively, send the request to a different node that is already synced.
    #[error("Node is not synced yet: {0}")]
    NotSyncedYet(String),

    /// Indicates that an unknown epoch was requested.
    ///
    /// # Arguments
    /// * `String` - The name of error cause.
    ///
    /// # Suggested Solutions
    /// - Ensure the requested epoch is valid and exists.
    #[error("Unknown epoch: {0}")]
    UnknownEpoch(String),

    /// Indicates a parse error occurred during the request.
    ///
    /// # Arguments
    /// * `String` - The name of error cause.
    ///
    /// # Possible Causes
    /// - Passed arguments cannot be parsed due to missing arguments or incorrect formats.
    ///
    /// # Suggested Solutions
    /// - Check the arguments provided in the request.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Indicates an internal server error occurred within the node.
    ///
    /// # Arguments
    /// * `String` - The name of error cause.
    ///
    /// # Possible Causes
    /// - The node encountered an unexpected error or is overloaded.
    ///
    /// # Suggested Solutions
    /// - Retry the request later.
    /// - Try sending the request to a different node.
    #[error("Internal server error: {0}")]
    InternalError(String),

    /// Represents any unexpected errors that do not fit into the predefined categories.
    ///
    /// # Arguments
    /// * `String` - A message detailing the unexpected error.
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),

    /// Represents a generic error that doesn't fall under the other categories.
    ///
    /// # Arguments
    /// * `String` - A message detailing the error.
    #[error("Other error: {0}")]
    Other(String),
}

impl From<RpcError> for JsonClientError {
    fn from(error: RpcError) -> Self {
        match error.name.as_str() {
            "HANDLER_ERROR" =>
                if error.cause.name == "UNKNOWN_BLOCK" {
                    JsonClientError::UnknownBlock(error.data)
                } else if error.cause.name == "NOT_SYNCED_YET" {
                    JsonClientError::NotSyncedYet(error.cause.name)
                } else if error.cause.name == "UNKNOWN_EPOCH" {
                    JsonClientError::UnknownEpoch(error.cause.name)
                } else {
                    JsonClientError::UnexpectedError(error.message)
                }
            "REQUEST_VALIDATION_ERROR" => JsonClientError::ParseError(error.cause.name),
            "INTERNAL_ERROR" => JsonClientError::InternalError(error.cause.name),
            _ => JsonClientError::UnexpectedError(error.message),
        }
    }
}

pub const ARCHIVAL_RPC: &str = "https://archival-rpc.mainnet.near.org";
pub const MAIN_NET_RPC: &str = "https://rpc.mainnet.near.org";

const NUM_BLOCKS_EPOCH: u64 = 43_200;

pub struct JsonClient {
    reqwest_client: Client,
    url: String,
}

impl JsonClient {
    pub fn setup(url: Option<String>) -> anyhow::Result<Self> {
        Ok(
            JsonClient {
                reqwest_client: Client::builder().danger_accept_invalid_certs(true).build()?,
                url: if url.is_some() {
                    url.unwrap()
                } else {
                    MAIN_NET_RPC.to_string()
                },
            }
        )
    }

    fn set_url(&mut self, url: &str) {
        self.url = url.to_string();
    }

    fn get_url(&mut self) -> String {
        self.url.to_string()
    }

    /// This function checks whether to use the MainNet or an archival node.
    /// It compares the height of requested block against the latest optimistic block on MainNet.
    /// If the block lags behind by more than 4 epochs, it switches to an archival node.
    /// If the block is not found, it switches to the archival node.
    ///
    /// # Arguments
    /// * `block_hash` - A string representing the hash of the block for which information is being requested.
    ///
    /// # Returns
    ///
    /// Returns a `JsonClientError` if the operation is unsuccessful.
    ///
    /// # Errors
    ///
    /// This function may return an error if:
    ///
    /// * The RPC request fails.
    /// * The response from the RPC server is invalid or cannot be parsed.
    pub async fn check_rpc_correctness(&mut self, block_hash: &str) -> Result<(), JsonClientError> {
        let block_request = json!({
            "jsonrpc": "2.0",
            "id": "dontcare",
            "method": "block",
            "params": BlockParamString {
                block_id: block_hash.to_string(),
            },
        });
        let current_block_result = self.send_request(&self.url, &block_request).await;

        match current_block_result {
            Ok(response_text) => {
                let current_block_response: BlockResponse = serde_json::from_str(&response_text)
                    .map_err(|e| JsonClientError::UnexpectedError(format!("Cannot serialize response: {}", e).to_string()))?;

                let optimistic_block_request = json!({
                    "jsonrpc": "2.0",
                    "id": "dontcare",
                    "method": "block",
                    "params": {
                        "finality": "optimistic",
                        },
                    }
                );

                let latest_block_text = self.send_request(MAIN_NET_RPC, &optimistic_block_request).await?;
                let latest_block_response: BlockResponse = serde_json::from_str(&latest_block_text)
                    .map_err(|e| JsonClientError::UnexpectedError(format!("Cannot serialize response: {}", e).to_string()))?;
                let current_block_header = BlockHeader::from(current_block_response.result.header);
                let latest_block_header = BlockHeader::from(latest_block_response.result.header);

                if current_block_header.height() < latest_block_header.height() - NUM_BLOCKS_EPOCH * 4 {
                    self.set_url(ARCHIVAL_RPC);
                }

                Ok(())
            }
            Err(JsonClientError::ParseError(message)) => {
                Err(JsonClientError::ParseError(message))
            }
            Err(JsonClientError::InternalError(message)) => {
                Err(JsonClientError::InternalError(format!("Server error: {}", message)))
            }
            Err(JsonClientError::UnexpectedError(message)) => {
                Err(JsonClientError::UnexpectedError(format!("Unexpected error: {}", message)))
            }
            Err(JsonClientError::UnknownEpoch(message)) => {
                Err(JsonClientError::UnknownEpoch(format!("Unknown epoch error: {}", message)))
            }
            Err(JsonClientError::UnknownBlock(_)) => {
                // Assume the block is not present on MainNet. If the block hash is incorrect,
                // the program will panic when trying to fetch the inputs required for proving,
                // which may lead to unexpected behavior or crashes.
                self.set_url(ARCHIVAL_RPC);

                Ok(())
            }
            Err(JsonClientError::NotSyncedYet(_)) => {
                tokio::time::sleep(Duration::from_millis(2000)).await;
                Ok(())
            }
            Err(JsonClientError::Other(message)) => {
                Err(JsonClientError::Other(format!("Unexpected error: {}", message)))
            }
        }
    }

    /// Sends an HTTP POST request to the configured RPC endpoint using the provided JSON request.
    ///
    /// # Arguments
    ///
    /// * `request` - A reference to a `serde_json::Value` object representing the JSON-RPC request to be sent.
    ///
    /// # Returns
    ///
    /// Returns a `Result<String, JsonClientError>` containing the server's response as a string on success.
    /// If the request fails or an error occurs, a corresponding `JsonClientError` is returned.
    ///
    /// # Errors
    ///
    /// This function may return the following errors:
    ///
    /// * `JsonClientError::UnexpectedError` - If the request fails to send, or if an unknown error occurs.
    /// * `JsonClientError::ParseError` - If the server returns a 400 status code, indicating a bad request (e.g., invalid parameters).
    /// * `JsonClientError::InternalError` - If the server returns a 500 status code, indicating an internal error on the RPC server.
    /// * `JsonClientError::UnexpectedBlock` - If the server returns a 200 status code, but a block not found in DB.
    /// * `JsonClientError::UnexpectedEpoch` - If the server returns a 200 status code, but an epoch not found in DB.
    /// * `JsonClientError::NotSyncedYet` - If the server returns a 200 status code, but node is still syncing and cannot fulfill the request.
    pub async fn send_request(&self, rpc: &str, request: &Value) -> Result<String, JsonClientError> {
        let response: Response = self
            .reqwest_client
            .post(rpc)
            .json(&request)
            .send()
            .await
            .map_err(|e| JsonClientError::UnexpectedError(e.to_string()))?;

        let status = response.status();
        let response_text = response.text().await.unwrap_or_default();

        match status.as_u16() {
            200 => {
                if let Ok(error_response) = serde_json::from_str::<RpcErrorResponse>(&response_text) {
                    return Err(JsonClientError::from(error_response.error));
                }
                Ok(response_text)
            }
            400 => Err(JsonClientError::ParseError(
                "Bad request - check the parameters.".to_string(),
            )),
            500 => Err(JsonClientError::InternalError(
                "Internal server error - try again later.".to_string(),
            )),
            _ => Err(JsonClientError::UnexpectedError(format!(
                "Unexpected status code: {} - {}",
                status,
                response_text
            ))),
        }
    }

    /// Prepares the input for the prover by fetching necessary blocks and validators from RPC.
    ///
    /// # Errors
    ///
    /// * Returns `JsonClientError` if there are issues with RPC correctness checks, loading blocks, or setting validators.
    pub async fn prepare_input(
        &mut self,
        // Bi Ei to prove random Bi (maybe used for B0 Ei, if prove epoch blocks).
        epoch_id_i_hash_i: &str,
        // Optional (Bn-1 Ei-1, if prove epoch blocks).
        epoch_id_i_1_hash_last: Option<&str>,
        // B0 Ei-1 for Bi to prove next_bp_hash.
        epoch_id_i_1_hash_0: &str,
        // Bn-1 Ei-2 for Bi to prove epoch_id (maybe also used for Bn-1 Ei-1 to prove next_bp_hash, if prove epoch blocks).
        epoch_id_i_2_hash_last: &str,
        // Optional (Bn-1 Ei-3 for Bn-1 Ei-1 to prove epoch_id, if prove epoch blocks).
        epoch_id_i_3_hash_last: Option<&str>,
    ) -> Result<ProverInput, JsonClientError> {
        self.check_rpc_correctness(epoch_id_i_hash_i).await?;
        let (epoch_blocks, blocks) = self.set_blocks_from_rpc(
            epoch_id_i_hash_i,
            epoch_id_i_1_hash_last,
            epoch_id_i_1_hash_0,
            epoch_id_i_2_hash_last,
            epoch_id_i_3_hash_last,
        ).await?;

        let validators = self.set_validators_from_rpc(
            epoch_id_i_hash_i,
            epoch_id_i_1_hash_last,
        )
            .await?;

        self.set_url(MAIN_NET_RPC);

        Ok(ProverInput {
            epoch_blocks,
            blocks,
            validators,
        })
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
        &self,
        block_hash: &str,
    ) -> Result<Vec<ValidatorStake>, JsonClientError> {
        let validators_ordered_request = json!({
                "jsonrpc": "2.0",
                "method": "EXPERIMENTAL_validators_ordered",
                "params": vec![block_hash],
                "id": "dontcare"
            }
        );

        let response_text = self.send_request(ARCHIVAL_RPC, &validators_ordered_request).await?;
        let validators_ordered_response: ValidatorsOrderedResponse = serde_json::from_str(&response_text)
            .map_err(|e| JsonClientError::UnexpectedError(format!("Cannot serialize response: {}", e).to_string()))?;

        // -------------- serializing EXPERIMENTAL_validators_ordered into ValidatorStake structure --------------

        let validator_stakes: Result<Vec<ValidatorStake>, JsonClientError> = validators_ordered_response
            .result
            .into_iter()
            .map(|validator| {
                let account_id = AccountId::from_str(&validator.account_id)
                    .map_err(|e| JsonClientError::UnexpectedError(format!("Cannot parse from str: {}", e)))?;
                let public_key = PublicKey::from_str(&validator.public_key)
                    .map_err(|e| JsonClientError::UnexpectedError(format!("Cannot parse from str: {}", e)))?;
                let stake = validator.stake.parse()
                    .map_err(|e| JsonClientError::UnexpectedError(format!("Cannot parse from str: {}", e)))?;

                Ok(ValidatorStake::new_v1(account_id, public_key, stake))
            })
            .collect();

        validator_stakes
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
    pub async fn load_block_by_hash_from_rpc(&self, block_hash: &str) -> Result<(CryptoHash, BlockHeader), JsonClientError> {
        let block_request = json!( {
            "jsonrpc": "2.0",
            "id": "dontcare",
            "method": "block",
            "params": BlockParamString {
                block_id: block_hash.parse()
                .map_err(|e| JsonClientError::UnexpectedError(format!("Cannot serialize response: {}", e).to_string()))?,
            },
        });
        let response_text = self.send_request(&self.url, &block_request).await?;
        let block_response: BlockResponse = serde_json::from_str(&response_text)
            .map_err(|e| JsonClientError::UnexpectedError(format!("Cannot serialize response: {}", e).to_string()))?;
        let header = BlockHeader::from(block_response.result.header);
        Ok((CryptoHash(header.hash().0), header))
    }

    /// Loads a block and its header from an RPC endpoint.
    ///
    /// This asynchronous function sends a request to the Near RPC endpoint to retrieve
    /// information about a block identified by its height.
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
    pub async fn load_block_by_height_from_rpc(&self, height: u64) -> Result<(CryptoHash, BlockHeader), JsonClientError> {
        let block_request = json!( {
            "jsonrpc": "2.0",
            "id": "dontcare",
            "method": "block",
            "params": BlockParamHeight {
                block_id: height,
            },
        });

        let response_text = self.send_request(&self.url, &block_request).await?;
        let block_response: BlockResponse = serde_json::from_str(&response_text)
            .map_err(|e| JsonClientError::UnexpectedError(format!("Cannot serialize response: {}", e).to_string()))?;
        let header = BlockHeader::from(block_response.result.header);
        Ok((CryptoHash(header.hash().0), header))
    }

    /// Sets blocks from the RPC by loading data for various epoch block hashes.
    ///
    /// # Arguments
    ///
    /// * `epoch_id_i_block_hash` - The block hash for the current epoch (Block_i).
    /// * `epoch_id_i_1_block_hash` - The block hash for the previous epoch (Block_0).
    /// * `epoch_id_i_2_block_hash` - The block hash for Block_n-1.
    /// * `epoch_id_i_3_block_hash_last` - An optional block hash for the last Block_n-1 (if applicable).
    /// * `epoch_id_i_1_block_hash_last` - An optional block hash for the last Block_0 (if applicable).
    /// # Returns
    ///
    /// * Returns a `Result` containing a tuple of two vectors:
    ///   - A vector of `Block` representing epoch blocks (Block_0, Block_n-1, and optionally Block_n-1).
    ///   - A vector of `Block` representing blocks to prove finality (Block_i+4 to Block_i).
    ///
    /// # Errors
    ///
    /// * Returns `JsonClientError::Other` for any errors encountered while loading block data or parsing block hashes.
    /// * Returns a `JsonClientError` corresponding to RPC errors.
    pub async fn set_blocks_from_rpc(
        &self,
        // Bi Ei to prove random Bi (maybe used for B0 Ei, if prove epoch blocks).
        epoch_id_i_hash_i: &str,
        // Optional (Bn-1 Ei-1, if prove epoch blocks).
        epoch_id_i_1_hash_last: Option<&str>,
        // B0 Ei-1 for Bi to prove next_bp_hash.
        epoch_id_i_1_hash_0: &str,
        // Bn-1 Ei-2 for Bi to prove epoch_id (maybe also used for Bn-1 Ei-1 to prove next_bp_hash, if prove epoch blocks).
        epoch_id_i_2_hash_last: &str,
        // Optional (Bn-1 Ei-3 for Bn-1 Ei-1 to prove epoch_id, if prove epoch blocks).
        epoch_id_i_3_hash_last: Option<&str>,
    ) -> Result<(Vec<Block>, Vec<Block>), JsonClientError> {
        // Extract epoch blocks: Block_0, Block_n-1, Block_n-1 (optionally).
        let mut epoch_blocks: Vec<Block> = vec![];
        // Extract blocks to prove finality: Block_i+4, Block_i+3, Block_i+2, Block_i+1, Block_i/Block_0, Block_n-1 (optionally).
        let mut blocks: Vec<Block> = vec![];

        // Extract B0 Ei-1 for Bi to prove next_bp_hash.
        let (_, block_data) = self.load_block_by_hash_from_rpc(epoch_id_i_1_hash_0).await?;
        let block_hash: CryptoHash = parse_block_hash(epoch_id_i_1_hash_0)
            .map_err(|e| JsonClientError::Other(e.to_string()))?;
        epoch_blocks.push(Block::try_from((block_hash, block_data, BlockType::BLOCK))
            .map_err(|e| JsonClientError::Other(e.to_string()))?);
        // Extract Bn-1 Ei-2 for Bi to prove epoch_id.
        let (_, block_data) = self.load_block_by_hash_from_rpc(epoch_id_i_2_hash_last).await?;
        let block_hash: CryptoHash = parse_block_hash(epoch_id_i_2_hash_last)
            .map_err(|e| JsonClientError::Other(e.to_string()))?;
        epoch_blocks.push(Block::try_from((block_hash, block_data, BlockType::BLOCK))
            .map_err(|e| JsonClientError::Other(e.to_string()))?);
        // Optionally extract Bn-1 Ei-3 for Bn-1 Ei-1 to prove epoch_id.
        if let Some(hash) = epoch_id_i_3_hash_last.clone() {
            let (_, block_data) = self.load_block_by_hash_from_rpc(hash).await?;
            let block_hash: CryptoHash = parse_block_hash(hash)
                .map_err(|e| JsonClientError::Other(e.to_string()))?;
            epoch_blocks.push(Block::try_from((block_hash, block_data, BlockType::BLOCK))
                .map_err(|e| JsonClientError::Other(e.to_string()))?);
        }

        // Define block height to load next four blocks.
        let mut block_height = {
            let (_, block_data) = self.load_block_by_hash_from_rpc(epoch_id_i_hash_i).await?;
            block_data.height()
        };
        let mut block_num = 4;
        block_height += 4;
        while block_num >= 0 {
            let (block_hash, block_data) = self.load_block_by_height_from_rpc(block_height).await?;
            blocks.push(Block::try_from((block_hash, block_data, BlockType::RANDOM))
                .map_err(|e| JsonClientError::Other(e.to_string()))?);
            block_num -= 1;
            block_height -= 1;
        }
        // Optionally extract Bn-1 Ei-1, if prove epoch blocks
        if let Some(_) = epoch_id_i_3_hash_last.clone() {
            // Search for folders by blocks_hash_i. Extract blocks. Extract Block_n-1.
            let (block_hash, block_data) = self.load_block_by_hash_from_rpc(epoch_id_i_1_hash_last.unwrap()).await?;
            blocks.push(Block::try_from((block_hash, block_data, BlockType::RANDOM))
                .map_err(|e| JsonClientError::Other(e.to_string()))?);
        }
        Ok((epoch_blocks, blocks))
    }

    /// Fetches and sets validator data from the RPC for the given epoch blocks.
    ///
    /// # Arguments
    ///
    /// * `num_epoch_blocks` - The number of epochal blocks. If it's 3, the function will also fetch
    ///   validator stakes from the previous epoch.
    /// * `epoch_id_i_block_hash` - The block hash for the current epoch (`Epoch_i`) for which the validator stakes
    ///   will be fetched.
    /// * `epoch_id_i_1_block_hash` - The block hash for the previous epoch (`Epoch_i-1`) for which validator stakes
    ///   may be fetched if `num_epoch_blocks == 3`.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing a `Validators` struct, which includes:
    /// * `validators_n` - A list of `ValidatorStake` objects for the current epoch.
    /// * `validators_n_1` - An optional list of `ValidatorStake` objects for the previous epoch if `num_epoch_blocks == 3`.
    ///
    /// # Errors
    ///
    /// This function may return the following errors:
    ///
    /// * `JsonClientError::Other` - If there is an error converting the validator stakes from raw data.
    /// * `JsonClientError::UnknownEpoch` - If the RPC request fails because the requested validator data is unavailable.
    /// * `JsonClientError::InternalError` - If the RPC request fails due to an internal server error.
    /// * `JsonClientError::ParseError` - If the RPC request fails due to a malformed request body.
    pub async fn set_validators_from_rpc(
        &self,
        epoch_id_i_block_hash: &str,
        epoch_id_i_1_block_hash: Option<&str>,
    ) -> Result<crate::types::types::Validators, JsonClientError> {
        let validators: Vec<crate::types::validators::ValidatorStake> =
            self.load_validators_from_rpc(epoch_id_i_block_hash).await?
                .into_iter()
                .map(|stake| convert_validator_stake(stake)
                    .map_err(|err| JsonClientError::Other(format!("Error converting validator stake: {}", err))))
                .collect::<Result<Vec<_>, JsonClientError>>()?;

        // Load list of validators for Epoch_i-1 from RPC for Block_n-1.
        let validators_n_1 = match epoch_id_i_1_block_hash.clone() {
            Some(hash) => {
                let validators_n_1: Vec<crate::types::validators::ValidatorStake> =
                    self.load_validators_from_rpc(hash).await?
                        .into_iter()
                        .map(|stake| convert_validator_stake(stake)
                            .map_err(|err| JsonClientError::Other(format!("Error converting validator stake: {}", err))))
                        .collect::<Result<Vec<_>, JsonClientError>>()?;
                Some(
                    validators_n_1
                )
            }
            None => { None }
        };
        Ok(crate::types::types::Validators {
            validators_n: validators,
            validators_n_1,
        })
    }
}

/// Converts a `ValidatorStakeV1` from the NEAR primitives to the internal `ValidatorStakeV1` type.
fn convert_validator_stake_v1(
    stake: near_primitives::types::ValidatorStakeV1,
) -> anyhow::Result<crate::types::validators::ValidatorStakeV1> {
    Ok(crate::types::validators::ValidatorStakeV1 {
        account_id: stake.account_id,
        public_key: crate::types::signature::PublicKey::from_str(&stake.public_key.to_string())?,
        stake: stake.stake,
    })
}

/// Converts a `ValidatorStake` (versioned enum) into the corresponding internal `ValidatorStake` type.
fn convert_validator_stake(
    stake: ValidatorStake
) -> anyhow::Result<crate::types::validators::ValidatorStake> {
    match stake {
        ValidatorStake::V1(v1) => Ok(crate::types::validators::ValidatorStake::V1(convert_validator_stake_v1(v1)?)),
    }
}

#[cfg(test)]
#[cfg(all(test, feature = "rpc", feature = "test-utils"))]
mod tests {
    use crate::rpc::{JsonClient, ARCHIVAL_RPC, MAIN_NET_RPC};
    use crate::test_utils::{set_blocks, set_validators};
    use crate::types::native::ProverInput;

    const DEFAULT_PATH: &str = "../../data/epochs";

    #[tokio::test]
    async fn test_load_validators_from_rpc() {
        let block_hash = "CRTZ7cQd77rvfS57Y7M36P1vLhran9HyQFEpTLxHRf9t";

        let client = JsonClient::setup(Some(ARCHIVAL_RPC.to_string())).unwrap();

        let result = client.load_validators_from_rpc(block_hash).await;

        assert!(result.is_ok(), "Failed to load validators from RPC");
        let validators = result.unwrap();
        assert!(!validators.is_empty(), "No validators returned");
    }

    #[tokio::test]
    async fn test_load_block_by_hash_from_rpc() {
        let block_hash = "Envut7DwFF4Gbjg5uHHFnQ9om9Zo5FK43H6outpRJveV";

        let client = JsonClient::setup(Some(ARCHIVAL_RPC.to_string())).unwrap();

        let result = client.load_block_by_hash_from_rpc(block_hash).await;

        assert!(result.is_ok(), "Failed to load block from RPC");
    }

    #[tokio::test]
    async fn test_load_block_by_height_from_rpc() {
        let height = 121837908;

        let client = JsonClient::setup(Some(ARCHIVAL_RPC.to_string())).unwrap();

        let result = client.load_block_by_height_from_rpc(height).await;

        assert!(result.is_ok(), "Failed to load block from RPC");
    }

    #[tokio::test]
    async fn test_set_blocks_from_rpc() {
        // Load block data of different epochs.
        let epoch_id_i_hash_0 = "CbAHBGJ8VQot2m6KhH9PLasMgcDtkPJBfp9bjAEMJ8UK"; // B0 Ei to prove
        let epoch_id_i_1_hash_0 = "Envut7DwFF4Gbjg5uHHFnQ9om9Zo5FK43H6outpRJveV"; // B0 Ei-1
        let epoch_id_i_1_hash_last = "4RjXBrNcu39wutFTuFpnRHgNqgHxLMcGBKNEQdtkSBhy"; // Bn-1 Ei-1 to prove
        let epoch_id_i_2_hash_last = "CRTZ7cQd77rvfS57Y7M36P1vLhran9HyQFEpTLxHRf9t"; // Bn-1 Ei-2
        let epoch_id_i_3_hash_last = "HPi5yyZHZ91t5S4SPAAfEZwGYEqq5i6QjzXoVMi8ksae"; // Bn-1 Ei-3

        let mut client = JsonClient::setup(Some(ARCHIVAL_RPC.to_string())).expect("Error setup client");

        let result = client.prepare_input(
            epoch_id_i_hash_0,
            Some(epoch_id_i_1_hash_last),
            epoch_id_i_1_hash_0,
            epoch_id_i_2_hash_last,
            Some(epoch_id_i_3_hash_last),
        ).await;

        assert!(result.is_ok(), "Failed to load block from RPC");

        let input = result.unwrap();

        // Parse test data
        let epoch_id_i = "CRTZ7cQd77rvfS57Y7M36P1vLhran9HyQFEpTLxHRf9t".to_string();
        let epoch_id_i_1 = "HPi5yyZHZ91t5S4SPAAfEZwGYEqq5i6QjzXoVMi8ksae".to_string();
        let epoch_id_i_2 = "3JMehuv86nBynJ33VBUGAvfd9Ts8EfvytGJ8i8e45XPi".to_string();
        let epoch_id_i_3 = "89PT9SkLXB1FZHvW7EdQHxiSpm5ybuTCvjrGZWWhXMTz".to_string();
        let (expected_epoch_blocks, expected_blocks) = set_blocks(
            DEFAULT_PATH,
            epoch_id_i.clone(),
            epoch_id_i_1.clone(),
            epoch_id_i_2.clone(),
            Some(epoch_id_i_3.clone()),
        ).expect("Failed to read expected test data");

        assert_eq!(input.epoch_blocks, expected_epoch_blocks);
        assert_eq!(input.blocks, expected_blocks);
    }

    #[tokio::test]
    async fn test_prepare_prover_input() {
        let epoch_id_i_hash_0 = "CbAHBGJ8VQot2m6KhH9PLasMgcDtkPJBfp9bjAEMJ8UK";
        let epoch_id_i_1_hash_0 = "Envut7DwFF4Gbjg5uHHFnQ9om9Zo5FK43H6outpRJveV";
        let epoch_id_i_1_hash_last = "4RjXBrNcu39wutFTuFpnRHgNqgHxLMcGBKNEQdtkSBhy";
        let epoch_id_i_2_hash_last = "CRTZ7cQd77rvfS57Y7M36P1vLhran9HyQFEpTLxHRf9t";
        let epoch_id_i_3_hash_last = "HPi5yyZHZ91t5S4SPAAfEZwGYEqq5i6QjzXoVMi8ksae";

        let mut client = JsonClient::setup(Some(ARCHIVAL_RPC.to_string())).unwrap();

        let result = client.prepare_input(
            epoch_id_i_hash_0,
            Some(epoch_id_i_1_hash_last),
            epoch_id_i_1_hash_0,
            epoch_id_i_2_hash_last,
            Some(epoch_id_i_3_hash_last),
        ).await;

        assert!(result.is_ok(), "Failed to load block from RPC");

        let input = result.unwrap();

        // Parse test data
        let epoch_id_i = "CRTZ7cQd77rvfS57Y7M36P1vLhran9HyQFEpTLxHRf9t".to_string();
        let epoch_id_i_1 = "HPi5yyZHZ91t5S4SPAAfEZwGYEqq5i6QjzXoVMi8ksae".to_string();
        let epoch_id_i_2 = "3JMehuv86nBynJ33VBUGAvfd9Ts8EfvytGJ8i8e45XPi".to_string();
        let epoch_id_i_3 = "89PT9SkLXB1FZHvW7EdQHxiSpm5ybuTCvjrGZWWhXMTz".to_string();
        let (expected_epoch_blocks, expected_blocks) = set_blocks(
            DEFAULT_PATH,
            epoch_id_i.clone(),
            epoch_id_i_1.clone(),
            epoch_id_i_2.clone(),
            Some(epoch_id_i_3.clone()),
        ).expect("Failed to read expected blocks data");

        let validators = set_validators(
            DEFAULT_PATH,
            expected_epoch_blocks.len(),
            &epoch_id_i,
            &epoch_id_i_1,
        ).expect("Failed to read expected validators data");

        let expected_input = ProverInput {
            validators: validators,
            epoch_blocks: expected_epoch_blocks,
            blocks: expected_blocks,
        };

        assert_eq!(input, expected_input);
    }

    #[tokio::test]
    async fn test_set_validators_from_rpc() {
        let epoch_id_i_hash_0 = "CbAHBGJ8VQot2m6KhH9PLasMgcDtkPJBfp9bjAEMJ8UK";
        let epoch_id_i_1_hash_0 = "Envut7DwFF4Gbjg5uHHFnQ9om9Zo5FK43H6outpRJveV";

        let mut client = JsonClient::setup(Some(ARCHIVAL_RPC.to_string())).unwrap();

        let result = client.set_validators_from_rpc(
            epoch_id_i_hash_0,
            Some(epoch_id_i_1_hash_0),
        ).await;

        assert!(result.is_ok(), "Failed to load validators from RPC");

        let validators = result.unwrap();


        // Parse test data

        let epoch_id_i = "CRTZ7cQd77rvfS57Y7M36P1vLhran9HyQFEpTLxHRf9t";
        let epoch_id_i_1 = "HPi5yyZHZ91t5S4SPAAfEZwGYEqq5i6QjzXoVMi8ksae";
        let expected_validators = set_validators(
            DEFAULT_PATH,
            3,
            epoch_id_i,
            epoch_id_i_1,
        ).expect("Failed to read expected test data");

        assert_eq!(validators, expected_validators);
    }

    // Test if the block was produced more than 3 epochs ago. If so, switch to using the archival RPC.

    #[tokio::test]
    async fn test_change_rpc_to_archival() {
        let epoch_id_i_hash_0 = "CbAHBGJ8VQot2m6KhH9PLasMgcDtkPJBfp9bjAEMJ8UK";

        let mut client = JsonClient::setup(None).unwrap();

        let failed_fetch = client.load_block_by_hash_from_rpc(epoch_id_i_hash_0).await;

        assert_eq!(failed_fetch.is_err(), true);
        assert_eq!(client.get_url(), MAIN_NET_RPC.to_string());

        client.check_rpc_correctness(epoch_id_i_hash_0).await.expect("Failed to switch archival RPC");

        assert_eq!(client.get_url(), ARCHIVAL_RPC.to_string());

        let expected_fetch = client.load_block_by_hash_from_rpc(epoch_id_i_hash_0).await;
        assert_eq!(expected_fetch.is_ok(), true);

    }
}

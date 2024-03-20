extern crate core;

mod nibble_slice;
mod proof_verifier;
mod raw_node;
mod utils;

use tokio::time::{sleep, Duration};

use crate::proof_verifier::ProofVerifier;
use crate::utils::{
    BlockParamBlockHeight, BlockParamString, BlockRequestOptionOne, BlockRequestOptionTwo,
    BlockResponse, Config, ViewStateParams, ViewStateRequest, ViewStateResponseForProof,
    ViewStateResponseForValues,
};
use near_primitives::types::AccountId;
use reqwest::{Client, Error};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::process::exit;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // open outcome for writing
        let mut file = File::create("result_with_proofs.txt").expect("Unable to create file");

        // reading config for the account
        let config_str = fs::read_to_string("config.json").unwrap();

        let config: Config = serde_json::from_str(&config_str).unwrap();

        let account_id = AccountId::from_str(&*config.account).unwrap();

        let rpc_url = match config.network {
            0 => "https://rpc.testnet.near.org",
            1 => "https://rpc.mainnet.near.org",
            _ => {
                panic!("Wrong network. Should be testnet OR mainnet")
            }
        };

        // querying state for the account
        let view_state_request = ViewStateRequest {
            jsonrpc: "2.0",
            id: "dontcare",
            method: "query",
            params: ViewStateParams {
                request_type: "view_state",
                finality: "final",
                account_id: account_id.to_string(),
                prefix_base64: "",
                include_proof: true,
            },
        };

        let client = Client::new();

        // constructing and verifying proof for all key-value pairs
        if client
            .post(rpc_url)
            .json(&view_state_request)
            .send()
            .await?
            .json::<ViewStateResponseForProof>()
            .await
            .is_err()
        {
            panic!(
                "State of contract {}  is too large to be viewed",
                account_id
            );
        } else {
            let view_state_response_for_proof: ViewStateResponseForProof = client
                .post(rpc_url)
                .json(&view_state_request)
                .send()
                .await?
                .json()
                .await?;

            let view_state_response_for_values: ViewStateResponseForValues = client
                .post(rpc_url)
                .json(&view_state_request)
                .send()
                .await?
                .json()
                .await?;

            let proof_verifier =
                ProofVerifier::new(view_state_response_for_proof.result.proof).unwrap();

            assert!(!proof_verifier.get_nodes().is_empty(), "Proof isn't valid");
            let mut result_proof_boolean = vec![];

            for root in proof_verifier.get_nodes_hashes() {
                for state_item in &view_state_response_for_proof.result.values {
                    let is_true = proof_verifier.verify(
                        &root,
                        &account_id,
                        &state_item.key.to_vec(),
                        Some(&state_item.value.to_vec()),
                    );
                    if is_true {
                        result_proof_boolean.push((is_true, root));

                        writeln!(file, "Key: {:?}", state_item.key)
                            .expect("Unable to write to file");
                        writeln!(file, "Value: {:?}", state_item.value)
                            .expect("Unable to write to file");
                        writeln!(file, "State Root: {:?}", root).expect("Unable to write to file");
                        writeln!(
                            file,
                            "Block Hash: {:?}",
                            view_state_response_for_values.result.block_hash.as_str()
                        )
                            .expect("Unable to write to file");
                        writeln!(
                            file,
                            "----------------------------------------------------------"
                        )
                            .expect("Unable to write to file");
                    }
                }
            }

            assert_eq!(
                result_proof_boolean.len(),
                view_state_response_for_proof.result.values.len(),
                "Proof for the key-value pair isn't verified."
            );

            assert!(
                result_proof_boolean
                    .iter()
                    .any(|(is_true, _)| *is_true == true),
                "Proof for the key-value pair isn't verified."
            );

            // getting last block by hash from the previous query function
            let block_request = BlockRequestOptionOne {
                jsonrpc: "2.0",
                id: "dontcare",
                method: "block",
                params: BlockParamString {
                    block_id: view_state_response_for_values.result.block_hash,
                },
            };

            let block_response: BlockResponse = client
                .post(rpc_url)
                .json(&block_request)
                .send()
                .await?
                .json()
                .await?;

            let mut block_height_iter = block_response.result.header.height;

            let state_root = result_proof_boolean.first().unwrap().clone().1.to_string();

            loop {
                let block_request = BlockRequestOptionTwo {
                    jsonrpc: "2.0",
                    id: "dontcare",
                    method: "block",
                    params: BlockParamBlockHeight {
                        block_id: block_height_iter.clone(),
                    },
                };

                if client
                    .post(rpc_url)
                    .json(&block_request)
                    .send()
                    .await?
                    .json::<BlockResponse>()
                    .await
                    .is_err()
                {
                    block_height_iter -= 1;
                    continue;
                } else {
                    let block_response: BlockResponse = client
                        .post(rpc_url)
                        .json(&block_request)
                        .send()
                        .await?
                        .json()
                        .await?;

                    for chunk in block_response.result.chunks.iter() {
                        if chunk.prev_state_root == state_root {
                            writeln!(
                                file,
                                "{}",
                                format!(
                                    "success prev_state_root {:?} for the block {:?}",
                                    chunk.prev_state_root, block_response.result.header.height
                                )
                            )
                                .expect("Unable to write to file");
                            println!("Script finished!");
                            exit(0);
                        }
                    }
                }

                block_height_iter -= 1;
                println!("new iteration\n");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }

    Ok(())
}

use alloy_sol_types::SolValue;
use near_primitives_core::borsh::from_slice;
use risc0_zkvm::guest::env;
use std::io::Read;

use lib::types::native::ProverInput;
use lib::types::types::{PublicValuesEpoch, PublicValuesRandom};
use lib::verification::*;

fn main() {
    // Read the input.
    let start = env::cycle_count();
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes).unwrap();

    let ProverInput {
        epoch_blocks,
        blocks,
        validators,
    } = from_slice::<ProverInput>(&input_bytes).unwrap();
    let end = env::cycle_count();
    eprintln!("Read input: {}", end - start);

    let start = env::cycle_count();

    // Check the length of the extracted data for epochs.
    assert!(
        (2..=3).contains(&epoch_blocks.len()),
        "epoch_blocks length must be between 3 and 4."
    );
    // Check the length of the extracted data for blocks.
    assert!(
        (5..=6).contains(&blocks.len()),
        "blocks length must be between 5 and 6."
    );
    // Check the length of the list of validators.
    assert!(
        validators.validators_n.len() > 0,
        "validators list must contain data."
    );

    // Check block hashes for epoch blocks.
    check_hashes(&epoch_blocks);

    // Check block hashes for B4, B3, B2.
    check_hashes(&blocks[0..3]);

    // Check heights for B4, B3, B2.
    let b4_height = blocks[0].header.height.expect("No height.");
    let b3_height = blocks[1].header.height.expect("No height.");
    let b2_height = blocks[2].header.height.expect("No height.");
    check_heights(b4_height, b3_height, b2_height);

    // Check last_ds_final_block, last_final_block for B4, B3, B2.
    let b4_ds = blocks[0]
        .header
        .last_ds_final_hash
        .as_ref()
        .expect("No last_ds_final_block for B4.");

    let b4_bft = blocks[0]
        .header
        .last_final_hash
        .as_ref()
        .expect("No last_final_block for B4.");

    let b3_ds = blocks[1]
        .header
        .last_ds_final_hash
        .as_ref()
        .expect("No last_ds_final_block for B3.");

    assert_eq!(
        &blocks[2].header.hash, b3_ds,
        "Incorrect hash: {} or ds: {} for B2",
        blocks[2].header.hash, b3_ds
    );

    assert_eq!(
        &blocks[2].header.hash, b4_bft,
        "Incorrect hash: {} or bft: {} for B2",
        blocks[2].header.hash, b4_bft
    );

    assert_eq!(
        &blocks[1].header.hash, b4_ds,
        "Incorrect hash: {} or ds: {} for B3",
        blocks[1].header.hash, b4_ds
    );

    // Check hashes for B1, Bi/B0 and Bn-1 (optionally).
    check_hashes(&blocks[3..]);

    // Check prev_hash for all blocks.
    check_prev_hashes(&blocks);

    // Check epoch_id for all blocks.
    check_epoch_id(&epoch_blocks, &blocks);

    // Check next_bp_hash.
    check_bp_hash(&epoch_blocks, &validators);

    // Check signatures.
    let start_measure_signatures = env::cycle_count();
    check_signatures(&blocks, &validators);
    let end_measure_signatures = env::cycle_count();
    eprintln!(
        "Check signatures: {}",
        end_measure_signatures - start_measure_signatures
    );

    let end = env::cycle_count();
    eprintln!("Check block: {}", end - start);

    match blocks.len() {
        5 => {
            let output = PublicValuesRandom {
                selector: 0,
                currentBlockHash: blocks[4].header.hash.0.into(),
                currentEpochHash: epoch_blocks[1].header.hash.0.into(),
                previousEpochHash: epoch_blocks[0].header.hash.0.into(),
            };
            env::commit_slice(output.abi_encode().as_slice());
        }
        6 => {
            let output = PublicValuesEpoch{
                selector: 1,
                // Hash of B0.
                currentBlockHash: blocks[4].header.hash.0.into(),
                // Hash of B_n-1.
                previousBlockHash: blocks[5].header.hash.0.into(),
                // Height of B0.
                currentBlockHashHeight: blocks[4].header.height.expect("No height."),
                // Height of B0.
                previousBlockHashHeight: blocks[5].header.height.expect("No height."),
            };
            // Write hashes to the journal
            env::commit_slice(output.abi_encode().as_slice());
        }
        _ => {
            panic!("Invalid blocks.len() {}", blocks.len());
        }
    }
}

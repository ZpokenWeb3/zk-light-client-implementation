use anyhow::{Ok, Result};
use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use hex::{decode, encode};
use log::{info, Level};
use near_bft_finality::prove_bft::bft::prove_block_bft;
use near_bft_finality::prove_bft::block_finality::*;
use near_bft_finality::prove_block_data::signatures::generate_signed_message;
use near_bft_finality::prove_crypto::{
    recursion::recursive_proof,
    sha256::{prove_sub_hashes_u32, sha256_proof_u32},
};
use near_bft_finality::types::*;
use near_bft_finality::utils::{
    load_block_by_height_from_rpc, load_block_from_rpc, load_block_hash, load_block_header,
    load_validators, load_validators_from_rpc, set_blocks,
};
use near_crypto::{PublicKey, Signature};
use near_primitives::borsh;
use near_primitives::borsh::BorshDeserialize;
use near_primitives::hash::{hash, CryptoHash};
use near_primitives::views::BlockHeaderView;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::timed;
use plonky2::util::{serialization::DefaultGateSerializer, timing::TimingTree};
use plonky2_bn128::config::PoseidonBN128GoldilocksConfig;
use plonky2_field::extension::Extendable;
use plonky2_field::types::PrimeField64;
use serde_json::json;
use std::fs;
use std::fs::File;
use std::io::BufWriter;
use std::str::FromStr;

const STORAGE_PATH: &str = "./proofs";
const EPOCH_PATH: &str = "./proofs/epoch";

pub async fn prove_epoch_blocks(
    client: Option<nats::Connection>,
    timing_tree: &mut TimingTree,
) -> Result<(), anyhow::Error> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type Cbn128 = PoseidonBN128GoldilocksConfig;

    //loop {
/*
        let path = format!("{EPOCH_PATH}/last_known_height.json");
        let height_bytes = fs::read(path).expect("Height reading error");
        let mut last_known_height: u64 = u64::from_be_bytes(height_bytes.try_into().unwrap());
	println!("Height {}", last_known_height);
        let mut last_block_height: u64 = last_known_height + (EPOCH_DURATION - 1);
        let mut first_block_height: u64 = last_known_height + EPOCH_DURATION;
        let (mut lkb_hash, mut lkb_block) = load_block_by_height_from_rpc(last_known_height).await?;
        let (mut bn_1_hash, mut bn_1_block) = (lkb_hash.clone(), lkb_block.clone());
        let (mut b0_hash, mut b0_block) = (lkb_hash.clone(), lkb_block.clone());
        while true {
            // Load Bn-1.
            (bn_1_hash, bn_1_block) = load_block_by_height_from_rpc(last_block_height).await?;
            // Load B0.
            (b0_hash, b0_block) = load_block_by_height_from_rpc(first_block_height).await?;
            if (lkb_block.epoch_id().0 == bn_1_block.epoch_id().0)
                && (bn_1_hash == b0_block.next_epoch_id().0)
                && (bn_1_hash == *b0_block.prev_hash())
            {
                break;
            }
            last_block_height += 1;
            first_block_height += 1;
        }
        // Search & load hashes from files.
        // Load stored B0 for new B0.
        let hash = lkb_hash.to_string();
println!("search for: {}", hash); 
	 let path = format!("{EPOCH_PATH}/{hash}/hash.json");
        let ep1_b0_stored_hash: String = fs::read_to_string(path).expect("Hash reading error");
	let ep1_b0_stored_hash = ep1_b0_stored_hash.trim();
println!("hash: {}", ep1_b0_stored_hash);
        let ep1_b0_stored_hash_bytes = bs58::decode(ep1_b0_stored_hash)
            .into_vec()
            .expect("Invalid Base58 string");
        let ep1_b0_stored_hash =
            CryptoHash::try_from(ep1_b0_stored_hash_bytes.as_slice()).expect("Invalid hash length");
        let ep1_b0_stored_block = lkb_block.clone();
        let (ep1_b0_sh_bytes, ep1_b0_sb_bytes) = (
            borsh::to_vec(&ep1_b0_stored_hash)?,
            borsh::to_vec(&ep1_b0_stored_block)?,
        );
        println!("ep1 b0 hash {}", ep1_b0_stored_hash);
        // Load stored Bn-1 for new B0 & Bn-1.
        let hash = lkb_block.next_epoch_id().0.to_string();
println!("search for: {}", hash);
        let path = format!("{EPOCH_PATH}/{hash}/hash.json");
        let ep2_bn_1_stored_hash: String = fs::read_to_string(path).expect("Hash reading error");
	let ep2_bn_1_stored_hash = ep2_bn_1_stored_hash.trim();
println!("hash: {}", ep2_bn_1_stored_hash);
        let ep2_bn_1_stored_hash_bytes = bs58::decode(ep2_bn_1_stored_hash)
            .into_vec()
            .expect("Invalid Base58 string");
        let ep2_bn_1_stored_hash =
            CryptoHash::try_from(ep2_bn_1_stored_hash_bytes.as_slice()).expect("Invalid hash length");
        let (_, ep2_bn_1_stored_block) = load_block_from_rpc(ep2_bn_1_stored_hash.to_string().as_str()).await?;
        let (ep2_bn_1_sh_bytes, ep2_bn_1_sb_bytes) = (
            borsh::to_vec(&ep2_bn_1_stored_hash)?,
            borsh::to_vec(&ep2_bn_1_stored_block)?,
        );
        println!("ep2 bn-1 hash {}", ep2_bn_1_stored_hash);
        // Load stored Bn-1 for new Bn-1.
        let hash = ep2_bn_1_stored_block.next_epoch_id().0.to_string();
println!("search for: {}", hash);
        let path = format!("{EPOCH_PATH}/{hash}/hash.json");
        let ep3_bn_1_stored_hash: String = fs::read_to_string(path).expect("Hash reading error");
	let ep3_bn_1_stored_hash = ep3_bn_1_stored_hash.trim();
println!("hash: {}", ep3_bn_1_stored_hash);
        let ep3_bn_1_stored_hash_bytes = bs58::decode(ep3_bn_1_stored_hash)
            .into_vec()
            .expect("Invalid Base58 string");
        let ep3_bn_1_stored_hash =
            CryptoHash::try_from(ep3_bn_1_stored_hash_bytes.as_slice()).expect("Invalid hash length");
        let (_, ep3_bn_1_stored_block) = load_block_from_rpc(ep3_bn_1_stored_hash.to_string().as_str()).await?;
        let (ep3_bn_1_sh_bytes, ep3_bn_1_sb_bytes) = (
            borsh::to_vec(&ep3_bn_1_stored_hash)?,
            borsh::to_vec(&ep3_bn_1_stored_block)?,
        );
        println!("ep2 bn-1 hash {}", ep3_bn_1_stored_hash);
        // Load B1, B2, B3, B4.
        let mut blocks = vec![];
	let mut approvals: Option<Vec<Vec<u8>>> = None;
	approvals = Some(
            bn_1_block
                .approvals()
                .iter()
                .map(|approval| borsh::to_vec(approval).unwrap())
                .collect(),
        );
	blocks.push((
            HeaderDataFields {
                hash: borsh::to_vec(&bn_1_hash)?,
                height: Some(bn_1_block.height()),
                prev_hash: Some(bn_1_block.prev_hash().0.to_vec()),
                bp_hash: Some(bn_1_block.next_bp_hash().0.to_vec()),
                epoch_id: Some(bn_1_block.epoch_id().0 .0.to_vec()),
                next_epoch_id: Some(bn_1_block.next_epoch_id().0 .0.to_vec()),
                last_ds_final_hash: Some(bn_1_block.last_ds_final_block().0.to_vec()),
                last_final_hash: Some(bn_1_block.last_final_block().0.to_vec()),
                approvals,
            },
            borsh::to_vec(&bn_1_block)?,
        ));
	let mut approvals: Option<Vec<Vec<u8>>> = None;
        approvals = Some(
            b0_block
                .approvals()
                .iter()
                .map(|approval| borsh::to_vec(approval).unwrap())
                .collect(),
        );
        blocks.push((
            HeaderDataFields {
                hash: borsh::to_vec(&b0_hash)?,
                height: Some(b0_block.height()),
                prev_hash: Some(b0_block.prev_hash().0.to_vec()),
                bp_hash: Some(b0_block.next_bp_hash().0.to_vec()),
                epoch_id: Some(b0_block.epoch_id().0 .0.to_vec()),
                next_epoch_id: Some(b0_block.next_epoch_id().0 .0.to_vec()),
                last_ds_final_hash: Some(b0_block.last_ds_final_block().0.to_vec()),
                last_final_hash: Some(b0_block.last_final_block().0.to_vec()),
                approvals,
            },
            borsh::to_vec(&b0_block)?,
        ));
        for i in 1..5 {
            let (b_hash, b_block) = load_block_by_height_from_rpc(first_block_height + i).await?;
            let mut approvals: Option<Vec<Vec<u8>>> = None;
            approvals = Some(
                b_block
                    .approvals()
                    .iter()
                    .map(|approval| borsh::to_vec(approval).unwrap())
                    .collect(),
            );
            blocks.push((
                HeaderDataFields {
                    hash: borsh::to_vec(&b_hash)?,
                    height: Some(b_block.height()),
                    prev_hash: Some(b_block.prev_hash().0.to_vec()),
                    bp_hash: Some(b_block.next_bp_hash().0.to_vec()),
                    epoch_id: Some(b_block.epoch_id().0 .0.to_vec()),
                    next_epoch_id: Some(b_block.next_epoch_id().0 .0.to_vec()),
                    last_ds_final_hash: Some(b_block.last_ds_final_block().0.to_vec()),
                    last_final_hash: Some(b_block.last_final_block().0.to_vec()),
                    approvals,
                },
                borsh::to_vec(&b_block)?,
            ));
        }
        // Load validators for B0 & Bn-1.
        // Epoch i.
        let validators_epi = load_validators_from_rpc(b0_hash.to_string().as_str()).await?;
        let validators_epi_bytes: Vec<Vec<u8>> = validators_epi
            .iter()
            .map(|value| borsh::to_vec(value).unwrap())
            .collect();
        // Epoch i-1.
        let validators_ep1 = load_validators_from_rpc(bn_1_hash.to_string().as_str()).await?;
        let validators_ep1_bytes: Vec<Vec<u8>> = validators_ep1
            .iter()
            .map(|value| borsh::to_vec(value).unwrap())
            .collect();
*/
        // Use mocked data.
        // Prove Block_0 & Block_n-1 from Epoch_i & Epoch_i-1.
        //let epoch_id_i = "4RjXBrNcu39wutFTuFpnRHgNqgHxLMcGBKNEQdtkSBhy".to_string();
        let epoch_id_i = "CRTZ7cQd77rvfS57Y7M36P1vLhran9HyQFEpTLxHRf9t".to_string();
        let epoch_id_i_1 = "HPi5yyZHZ91t5S4SPAAfEZwGYEqq5i6QjzXoVMi8ksae".to_string();
        let epoch_id_i_2 = "3JMehuv86nBynJ33VBUGAvfd9Ts8EfvytGJ8i8e45XPi".to_string();
        let epoch_id_i_3 = "89PT9SkLXB1FZHvW7EdQHxiSpm5ybuTCvjrGZWWhXMTz".to_string();
        let (epoch_blocks, blocks) = set_blocks(
            epoch_id_i.clone(),
            epoch_id_i_1.clone(),
            epoch_id_i_2.clone(),
            Some(epoch_id_i_3.clone()),
        )?;
        // Check the lenght of the extracted data for epochs.
        assert!(epoch_blocks.len() > 0);
        assert!(epoch_blocks.len() >= 2);
        assert!(epoch_blocks.len() <= 3);
        // Check the lenght of the extracted data for blocks.
        assert!(blocks.len() > 0);
        assert!(blocks.len() >= 5);
        assert!(blocks.len() <= 6);
        // Block_0 Epoch_i-1.
        let ep1_b0_sh_bytes = epoch_blocks[0].0.clone();
        let ep1_b0_sb_bytes = epoch_blocks[0].1.clone();
        // Block_n-1 of Epoch_i-2.
        let ep2_bn_1_sh_bytes = epoch_blocks[1].0.clone();
        let ep2_bn_1_sb_bytes = epoch_blocks[1].1.clone();
        // Block_n-1 of Epoch_i-3. Optionally.
        let mut ep3_bn_1_sh_bytes = epoch_blocks[2].0.clone();
        let mut ep3_bn_1_sb_bytes = epoch_blocks[2].1.clone();
        // Load list of validators for Epoch_i from RPC.
        let path = format!("../data/epochs/{epoch_id_i}/validators.json");
        let validators = load_validators(&path)?;
        let validators_epi_bytes: Vec<Vec<u8>> = validators
            .iter()
            .map(|value| borsh::to_vec(value).unwrap())
            .collect();
        // Load list of validators for Epoch_i-1 from RPC for Block_n-1.
        let path = format!("../data/epochs/{epoch_id_i_1}/validators.json");
        let validators = load_validators(&path)?;
        let validators_ep1_bytes: Vec<Vec<u8>> = validators
            .iter()
            .map(|value| borsh::to_vec(value).unwrap())
            .collect();
        // Prove B0 & Bn-1.
        let ((b0_data, b0_proof), b_n_1_data_proof) = prove_block_bft::<F, C, D>(
            &ep2_bn_1_sb_bytes,
            &ep2_bn_1_sh_bytes,
            &ep1_b0_sb_bytes,
            &ep1_b0_sh_bytes,
            Some(ep3_bn_1_sb_bytes),
            Some(ep3_bn_1_sh_bytes),
            blocks,
            Some(validators_epi_bytes),
            Some(validators_ep1_bytes),
            client,
            timing_tree,
        )?;
/*      Use when RPC data is used.
        // Create new last known height.
        last_known_height = first_block_height;
        let last_known_height_bytes = last_known_height.to_be_bytes();
        let path = format!("{HEIGHT_PATH}/last_known_height.json");
        fs::write(path, last_known_height_bytes).expect("Height writing error");
        let path = format!("{HEIGHT_PATH}/last_known_height.json");
        let height_bytes = fs::read(path).expect("Height reading error");
        let mut last_known_height: u64 = u64::from_be_bytes(height_bytes.try_into().unwrap());
        println!("HEIGHT: {}", last_known_height);
*/
	// Write proofs to file.
        // Wrap B0 in Cbn128 and write B0 proof to file.
        let (w_b0_data, w_b0_proof) = timed!(
            timing_tree,
            "aggregate final proof using BN128 config",
            recursive_proof::<F, Cbn128, C, D>(
                (&b0_data.common, &b0_data.verifier_only, &b0_proof,),
                None,
                Some(&b0_proof.public_inputs),
            )?
        );
        let hash_bytes: Vec<u8> = w_b0_proof.public_inputs[1..33]
            .iter()
            .map(|x| x.to_canonical_u64() as u8)
            .collect();
        let final_hash = CryptoHash(hash_bytes.clone().try_into().unwrap());
        info!("Block hash: {}", final_hash);
        // Create folder by the hash of the block.
        let str_hash = final_hash.to_string();
        let _ = fs::create_dir_all(format!("{STORAGE_PATH}/epoch/{str_hash}"));
        // Store VerifierCircuitData.
        let gate_serializer = DefaultGateSerializer;
        let verifier_data_bytes = w_b0_data
            .verifier_data()
            .to_bytes(&gate_serializer)
            .expect("Error reading verifier data");
        // Store VerifierCircuitData bin.
        let path = format!("{STORAGE_PATH}/epoch/{str_hash}/verifier_data.bin");
        fs::write(path, verifier_data_bytes).expect("Verifier data writing error");
        // Store VerifierCircuitData json.
        let path = format!("{STORAGE_PATH}/epoch/{str_hash}/verifier_data.json");
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &w_b0_data.verifier_only)?;
        // Store CommonData json.
        let path = format!("{STORAGE_PATH}/epoch/{str_hash}/common_data.json");
        let file = File::create(path)?;
        writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &w_b0_data.common)?;
        // Store ProofWithPublicInputs bin.
        let path = format!("{STORAGE_PATH}/epoch/{str_hash}/proof.bin");
        fs::write(path, w_b0_proof.to_bytes()).expect("Proof writing error");
        // Store ProofWithPublicInputs json.
        let path = format!("{STORAGE_PATH}/epoch/{str_hash}/proof.json");
        let file = File::create(path)?;
        writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &w_b0_proof)?;
        // Store hash.
        let path = format!("{STORAGE_PATH}/epoch/{str_hash}/hash.json");
        fs::write(path, final_hash.to_string()).expect("hash writing error");
	let hash_hex = encode(hash_bytes);
	let path = format!("{STORAGE_PATH}/epoch/{str_hash}/hash_hex.json");
        fs::write(path, hash_hex).expect("hash writing error");
        // Wrap Bn-1 in Cbn128 and write Bn-1 proof to file.
        let w_b_n_1_data_proof = match b_n_1_data_proof {
            Some((b_n_1_data, b_n_1_proof)) => Some(timed!(
                timing_tree,
                "aggregate final proof using BN128 config",
                recursive_proof::<F, Cbn128, C, D>(
                    (&b_n_1_data.common, &b_n_1_data.verifier_only, &b_n_1_proof,),
                    None,
                    Some(&b_n_1_proof.public_inputs),
                )?
            )),
            None => None,
        };
        if let Some((w_b_n_1_data, w_b_n_1_proof)) = w_b_n_1_data_proof.clone() {
            let hash_bytes: Vec<u8> = w_b_n_1_proof.public_inputs[1..33]
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            let final_hash = CryptoHash(hash_bytes.clone().try_into().unwrap());
            info!("Block hash: {}", final_hash);
            // Create folder by the hash of the block.
            let str_hash = final_hash.to_string();
            let _ = fs::create_dir_all(format!("{STORAGE_PATH}/epoch/{str_hash}"));
            // Store VerifierCircuitData.
            let gate_serializer = DefaultGateSerializer;
            let verifier_data_bytes = w_b_n_1_data
                .verifier_data()
                .to_bytes(&gate_serializer)
                .expect("Error reading verifier data");
            // Store VerifierCircuitData bin.
            let path = format!("{STORAGE_PATH}/epoch/{str_hash}/verifier_data.bin");
            fs::write(path, verifier_data_bytes).expect("Verifier data writing error");
            // Store VerifierCircuitData json.
            let path = format!("{STORAGE_PATH}/epoch/{str_hash}/verifier_data.json");
            let file = File::create(path)?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, &w_b_n_1_data.verifier_only)?;
            // Store CommonData json.
            let path = format!("{STORAGE_PATH}/epoch/{str_hash}/common_data.json");
            let file = File::create(path)?;
            writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, &w_b_n_1_data.common)?;
            // Store ProofWithPublicInputs bin.
            let path = format!("{STORAGE_PATH}/epoch/{str_hash}/proof.bin");
            fs::write(path, w_b_n_1_proof.to_bytes()).expect("Proof writing error");
            // Store ProofWithPublicInputs json.
            let path = format!("{STORAGE_PATH}/epoch/{str_hash}/proof.json");
            let file = File::create(path)?;
            writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, &w_b_n_1_proof)?;
            // Store hash.
            let path = format!("{STORAGE_PATH}/epoch/{str_hash}/hash.json");
            fs::write(path, final_hash.to_string()).expect("hash writing error");
	    let hash_hex = encode(hash_bytes);
            let path = format!("{STORAGE_PATH}/epoch/{str_hash}/hash_hex.json");
            fs::write(path, hash_hex).expect("hash writing error");
        }
	let pi: Vec<u8> = w_b0_proof
            .public_inputs
            .iter()
            .map(|x| x.to_canonical_u64() as u8)
            .collect();
        info!("Final PI len Bi/0 {}", pi.len());
        let hsh = CryptoHash(pi[1..33].try_into().unwrap());
        info!("Current block hash: {}", hsh);
        let hsh = CryptoHash(pi[33..65].try_into().unwrap());
        info!("Epoch_i-2 block hash: {}", hsh);
        let hsh = CryptoHash(pi[65..97].try_into().unwrap());
        info!("Epoch_i-1 block hash: {}", hsh);
	if let Some((_, w_b_n_1_proof)) = w_b_n_1_data_proof {
            let pi: Vec<u8> = w_b_n_1_proof
                .public_inputs
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            info!("Final PI len Bn-1 {}", pi.len());
            let hsh = CryptoHash(pi[1..33].try_into().unwrap());
            info!("Current block hash: {}", hsh);
            let hsh = CryptoHash(pi[33..65].try_into().unwrap());
            info!("Epoch_i-2 block hash: {}", hsh);
            let hsh = CryptoHash(pi[65..97].try_into().unwrap());
            info!("Epoch_i-1 block hash: {}", hsh);
    }
	
    //}
    Ok(())
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info, debug"));
    let mut timing = TimingTree::new("To prove block", Level::Info);
    prove_epoch_blocks(None, &mut timing).await?;
    timing.print();
    Ok(())
}

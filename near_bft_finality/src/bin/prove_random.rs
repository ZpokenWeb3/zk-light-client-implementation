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
use near_primitives::block::BlockHeader;
use near_primitives::borsh;
use near_primitives::borsh::BorshDeserialize;
use near_primitives::hash::{hash, CryptoHash};
use near_primitives::types::MerkleHash;
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

pub async fn prove_random_blocks(
    hash: &[u8],
    client: Option<nats::Connection>,
    timing_tree: &mut TimingTree,
) -> Result<(), anyhow::Error> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type Cbn128 = PoseidonBN128GoldilocksConfig;

    
    // Use mocked data.
    // Prove random block from Epoch_i.
    let epoch_id_i = "HPi5yyZHZ91t5S4SPAAfEZwGYEqq5i6QjzXoVMi8ksae".to_string();
    let epoch_id_i_1 = "3JMehuv86nBynJ33VBUGAvfd9Ts8EfvytGJ8i8e45XPi".to_string();
    let epoch_id_i_2 = "89PT9SkLXB1FZHvW7EdQHxiSpm5ybuTCvjrGZWWhXMTz".to_string();
    let (epoch_blocks, blocks) =
        set_blocks(epoch_id_i.clone(), epoch_id_i_1.clone(), epoch_id_i_2, None)?;
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
    let mut ep_i3_lb_hash_bytes: Option<Vec<u8>> = None;
    let mut ep_i3_lb_header_bytes: Option<Vec<u8>> = None;
    // Load list of validators for Epoch_i from RPC.
    let path = format!("../data/epochs/{epoch_id_i}/validators.json");
    let validators = load_validators(&path)?;
    let validators_bytes: Vec<Vec<u8>> = validators
        .iter()
        .map(|value| borsh::to_vec(value).unwrap())
        .collect();

/*
    // Load Bi Epoch i.
    let current_hash_bytes = bs58::decode(hash)
        .into_vec()
        .expect("Invalid Base58 string");
    let current_hash = CryptoHash::try_from(current_hash_bytes.as_slice()).expect("Invalid hash length");
    let (bi_hash, bi_block) = load_block_from_rpc(current_hash.to_string().as_str()).await?;
    let bi_height: u64 = bi_block.height();
    // Load Bn-1 Epoch i-1. Is used to load Bn-1 Epoch i-2.
    let ep1_bn_1_hash = bi_block.next_epoch_id().0;
    let (_, ep1_bn_1_block) = load_block_from_rpc(ep1_bn_1_hash.to_string().as_str()).await?;
    // Load Bn-1 Epoch i-2.
    let ep2_bn_1_hash = ep1_bn_1_block.next_epoch_id().0;
    let (_, ep2_bn_1_block) = load_block_from_rpc(ep2_bn_1_hash.to_string().as_str()).await?;
    // Search for this hash in stored hashes.
    let hash = ep2_bn_1_hash.to_string();
    let path = format!("{EPOCH_PATH}/{hash}/hash.json");
    let ep2_bn_1_stored_hash: String = fs::read_to_string(path).expect("Hash reading error");
    let ep2_bn_1_stored_hash = ep2_bn_1_stored_hash.trim();
    println!("hash: {}", ep2_bn_1_stored_hash);
    let ep2_bn_1_stored_hash_bytes = bs58::decode(ep2_bn_1_stored_hash)
        .into_vec()
        .expect("Invalid Base58 string");
    let ep2_bn_1_stored_hash =
        CryptoHash::try_from(ep2_bn_1_stored_hash_bytes.as_slice()).expect("Invalid hash length");
    let ep2_bn_1_height: u64 = ep2_bn_1_block.height();
    let (ep2_bn_1_sh_bytes, ep2_bn_1_sb_bytes) = (
        borsh::to_vec(&ep2_bn_1_stored_hash)?,
        borsh::to_vec(&ep2_bn_1_block)?,
    );
    // Load B0 Epoch i-1.
    let (mut ep1_b0_hash, mut ep1_b0_block) = (ep2_bn_1_hash.clone(), ep2_bn_1_block.clone());
    let mut ep1_b0_height: u64 = ep2_bn_1_height + 1;
    while true {
        (ep1_b0_hash, ep1_b0_block) = load_block_by_height_from_rpc(ep1_b0_height).await?;
        if ep2_bn_1_stored_hash == *ep1_b0_block.prev_hash()
            && ep2_bn_1_stored_hash == ep1_b0_block.next_epoch_id().0
        {
            break;
        }
        ep1_b0_height += 1;
    }
    // Search for this hash in stored hashes.
    let hash = ep1_b0_hash.to_string();
    let path = format!("{EPOCH_PATH}/{hash}/hash.json");
    let ep1_b0_stored_hash: String = fs::read_to_string(path).expect("Hash reading error");
    let ep1_b0_stored_hash = ep1_b0_stored_hash.trim();
    println!("hash: {}", ep1_b0_stored_hash);
    let ep1_b0_stored_hash_bytes = bs58::decode(ep1_b0_stored_hash)
        .into_vec()
        .expect("Invalid Base58 string");
    let ep1_b0_stored_hash =
        CryptoHash::try_from(ep1_b0_stored_hash_bytes.as_slice()).expect("Invalid hash length");
    let (ep1_b0_sh_bytes, ep1_b0_sb_bytes) = (
        borsh::to_vec(&ep1_b0_stored_hash)?,
        borsh::to_vec(&ep1_b0_block)?,
    );
    // Load B1, B2, B3, B4.
    let mut blocks = vec![];
    let mut approvals: Option<Vec<Vec<u8>>> = None;
    approvals = Some(
        bi_block
            .approvals()
            .iter()
            .map(|approval| borsh::to_vec(approval).unwrap())
            .collect(),
    );
    blocks.push((
        HeaderDataFields {
            hash: borsh::to_vec(&bi_hash)?,
            height: Some(bi_block.height()),
            prev_hash: Some(bi_block.prev_hash().0.to_vec()),
            bp_hash: Some(bi_block.next_bp_hash().0.to_vec()),
            epoch_id: Some(bi_block.epoch_id().0 .0.to_vec()),
            next_epoch_id: Some(bi_block.next_epoch_id().0 .0.to_vec()),
            last_ds_final_hash: Some(bi_block.last_ds_final_block().0.to_vec()),
            last_final_hash: Some(bi_block.last_final_block().0.to_vec()),
            approvals,
        },
        borsh::to_vec(&bi_block)?,
    ));
    for i in 1..5 {
        let (b_hash, b_block) = load_block_by_height_from_rpc(bi_height + i).await?;
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
    // Load validators for Bi.
    // Epoch i.
    let validators = load_validators_from_rpc(bi_hash.to_string().as_str()).await?;
    let validators_bytes: Vec<Vec<u8>> = validators
        .iter()
        .map(|value| borsh::to_vec(value).unwrap())
        .collect();
*/

    // Prove B0 & Bn-1.
    let ((bi_data, bi_proof), _) = prove_block_bft::<F, C, D>(
        &ep2_bn_1_sb_bytes,
        &ep2_bn_1_sh_bytes,
        &ep1_b0_sb_bytes,
        &ep1_b0_sh_bytes,
        None,
        None,
        blocks,
        Some(validators_bytes),
        None,
        client,
        timing_tree,
    )?;
    // Wrap Bi proof in Cbn128.
    let (w_bi_data, w_bi_proof) = timed!(
        timing_tree,
        "aggregate final proof using BN128 config",
        recursive_proof::<F, Cbn128, C, D>(
            (&bi_data.common, &bi_data.verifier_only, &bi_proof,),
            None,
            Some(&bi_proof.public_inputs),
        )?
    );
    // Write proof to file.
    let hash_bytes: Vec<u8> = w_bi_proof.public_inputs[1..33]
        .iter()
        .map(|x| x.to_canonical_u64() as u8)
        .collect();
    let final_hash = CryptoHash(hash_bytes.clone().try_into().unwrap());
    info!("Block hash: {}", final_hash);
    // Create folder by the hash of the block.
    let str_hash = final_hash.to_string();
    let _ = fs::create_dir_all(format!("{STORAGE_PATH}/random/{str_hash}"));
    // Store VerifierCircuitData.
    let gate_serializer = DefaultGateSerializer;
    let verifier_data_bytes = w_bi_data
        .verifier_data()
        .to_bytes(&gate_serializer)
        .expect("Error reading verifier data");
    // Store VerifierCircuitData bin.
    let path = format!("{STORAGE_PATH}/random/{str_hash}/verifier_data.bin");
    fs::write(path, verifier_data_bytes).expect("Verifier data writing error");
    // Store VerifierCircuitData json.
    let path = format!("{STORAGE_PATH}/random/{str_hash}/verifier_data.json");
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &w_bi_data.verifier_only)?;
    // Store CommonData json.
    let path = format!("{STORAGE_PATH}/random/{str_hash}/common_data.json");
    let file = File::create(path)?;
    writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &w_bi_data.common)?;
    // Store ProofWithPublicInputs bin.
    let path = format!("{STORAGE_PATH}/random/{str_hash}/proof.bin");
    fs::write(path, w_bi_proof.to_bytes()).expect("Proof writing error");
    // Store ProofWithPublicInputs json.
    let path = format!("{STORAGE_PATH}/random/{str_hash}/proof.json");
    let file = File::create(path)?;
    writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &w_bi_proof)?;
    // Store hash.
    let hash_hex = encode(hash_bytes);
    let path = format!("{STORAGE_PATH}/random/{str_hash}/hash.json");
    fs::write(path, hash_hex).expect("hash writing error");
    let pi: Vec<u8> = w_bi_proof
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
    Ok(())
}

#[tokio::main]
pub async fn main() -> Result<()> {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info, debug"));
    let mut timing = TimingTree::new("To prove block", Level::Info);
    let hash = "CGZPhFRkL3NvmGaXWBc6N7qJD519EUe6vyNpaEyDe2Ev".as_bytes();
    prove_random_blocks(hash, None, &mut timing).await?;
    timing.print();
    Ok(())
}

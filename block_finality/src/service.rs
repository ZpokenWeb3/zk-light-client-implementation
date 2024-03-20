use std::fs;
use std::fs::File;
use std::io::BufWriter;

use hex::encode;
use log::info;
use near_primitives::borsh;
use plonky2::plonk::circuit_data::VerifierCircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::timed;
use plonky2::util::serialization::DefaultGateSerializer;
use plonky2::util::timing::TimingTree;

use plonky2_bn128::config::PoseidonBN128GoldilocksConfig;

use crate::prove_block::{generate_signed_message, prove_header_hash};
use crate::recursion::recursive_proof;
use crate::types::{HeaderData, INNER_LITE_BYTES, PK_BYTES, SIG_BYTES, TYPE_BYTE};
use crate::utils::{load_block_from_rpc, load_validators_from_rpc, vec_u32_to_u8};

const STORAGE_PATH: &str = "./proofs";

pub async fn prove_current_epoch_block(
    prev_hash: &str,
    hash: &str,
    next_hash: &str,
    client: Option<nats::Connection>,
    timing_tree: &mut TimingTree,
) -> anyhow::Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type Cbn128 = PoseidonBN128GoldilocksConfig;
    let gate_serializer = DefaultGateSerializer;
    let mut path = format!("../proofs/{prev_hash}/bin/prev_epoch_block_data.bin");
    let prev_epoch_block_verifier_data_bytes = fs::read(path).expect("File not found");
    let prev_epoch_block_verifier_data: VerifierCircuitData<F, C, D> =
        VerifierCircuitData::from_bytes(prev_epoch_block_verifier_data_bytes, &gate_serializer)
            .expect("Error serializing verifier data");
    path = format!("../proofs/{prev_hash}/bin/prev_epoch_block_proof.bin");
    let prev_epoch_block_proof_bytes = fs::read(path).expect("File not found");
    let prev_epoch_block_proof: ProofWithPublicInputs<F, C, D> = ProofWithPublicInputs::from_bytes(
        prev_epoch_block_proof_bytes,
        &prev_epoch_block_verifier_data.common,
    )
        .expect("Error serializing proof");


    let (current_block_hash, current_block_header) = load_block_from_rpc(hash).await?;
    let (_, next_block_header) = load_block_from_rpc(next_hash).await?;

    let msg_to_sign = generate_signed_message(
        current_block_header.height(),
        next_block_header.height(),
        next_block_header
            .prev_height()
            .expect("No prev_height in next_block_header"),
        *next_block_header.prev_hash(),
    );

    let current_block_header_bytes = borsh::to_vec(&current_block_header)?;
    let current_block_hash_bytes = borsh::to_vec(&current_block_hash)?;
    let approvals_bytes: Vec<Vec<u8>> = next_block_header
        .approvals()
        .iter()
        .map(|approval| borsh::to_vec(approval).unwrap())
        .collect();
    let validators = load_validators_from_rpc(hash).await?;
    let validators_bytes: Vec<Vec<u8>> = validators
        .iter()
        .map(|value| borsh::to_vec(value).unwrap())
        .collect();
    let ((currentblock_header_data, currentblock_header_proof),
        (currentblock_data, currentblock_proof)) = timed!(timing_tree, "prove current block header", crate::prove_block::prove_current_block::<F, C, D>(
        &current_block_hash_bytes,
        &current_block_header_bytes,
        &msg_to_sign,
        approvals_bytes,
        validators_bytes,
        client,
        (&prev_epoch_block_verifier_data, &prev_epoch_block_proof),
        timing_tree
    )?);

    info!("Proof size {}", currentblock_proof.to_bytes().len());

    let (rec_data, rec_proof) = timed!(timing_tree, "aggregate final proof using BN128 config", recursive_proof::<F, Cbn128, C, D>(
        (
            &currentblock_data.common,
            &currentblock_data.verifier_only,
            &currentblock_proof,
        ),
        None,
        Some(&currentblock_proof.public_inputs),
    )?);

    info!(
        "Proof with BN128 config size {}",
        rec_proof.to_bytes().len()
    );

    let hash_u32: Vec<u32> = rec_proof.public_inputs.iter().map(|x| x.0 as u32).collect();
    let hash_bytes = vec_u32_to_u8(&hash_u32);
    let hash_hex1 = encode(&hash_bytes[0..32]);
    let hash_hex2 = encode(&hash_bytes[32..64]);
    let hash_hex = [hash_hex1, hash_hex2].concat();

    let _ = fs::create_dir_all(format!("{STORAGE_PATH}/{hash_hex}/bin"));
    let _ = fs::create_dir_all(format!("{STORAGE_PATH}/{hash_hex}/gnark"));

    // save as previous proof (header only)
    let gate_serializer = DefaultGateSerializer;
    let verifier_data_bytes = currentblock_header_data
        .verifier_data()
        .to_bytes(&gate_serializer)
        .expect("Error reading verifier data");


    let mut path = format!("../proofs/{hash_hex}/bin/prev_epoch_block_data.bin");
    fs::write(path, verifier_data_bytes.clone()).expect("Verifier data writing error");
    path = format!("{STORAGE_PATH}/{hash_hex}/bin/prev_epoch_block_proof.bin");
    fs::write(path, currentblock_header_proof.to_bytes()).expect("Proof writing error");

    // save as current proof
    let verifier_data_bytes = rec_data
        .verifier_data()
        .to_bytes(&gate_serializer)
        .expect("Error reading verifier data");

    let mut path = format!("../proofs/{hash_hex}/bin/current_block_data.bin");
    fs::write(path, verifier_data_bytes.clone()).expect("Verifier data writing error");
    path = format!("{STORAGE_PATH}/{hash_hex}/bin/current_block_proof.bin");
    fs::write(path, rec_proof.to_bytes()).expect("Proof writing error");

    path = format!("{STORAGE_PATH}/{hash_hex}/gnark/current_block_hexhash.json");
    fs::write(path, hash_hex.clone()).expect("hash_hex writing error");
    path = format!("{STORAGE_PATH}/{hash_hex}/gnark/current_block_proof.json");
    let mut file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &rec_proof)?;
    path = format!("{STORAGE_PATH}/{hash_hex}/gnark/current_block_vd.json");
    file = File::create(path)?;
    writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &rec_data.verifier_only)?;
    path = format!("{STORAGE_PATH}/{hash_hex}/gnark/current_block_cd.json");
    file = File::create(path)?;
    writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &rec_data.common)?;


    Ok(())
}

pub async fn prove_prev_epoch_block(prev_block_hash: &str, timing_tree: &mut TimingTree) -> anyhow::Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let (prev_epoch_block_hash, prev_epoch_block_header) =
        load_block_from_rpc(prev_block_hash).await?;

    let prev_epoch_block_header_bytes = borsh::to_vec(&prev_epoch_block_header)?;
    let prev_epoch_block_hash_bytes = borsh::to_vec(&prev_epoch_block_hash)?;

    let (prev_epoch_block_data, prev_epoch_block_proof) = timed!(timing_tree, "prove previous block", prove_header_hash::<F, C, D>(
        &prev_epoch_block_hash_bytes,
        &prev_epoch_block_header_bytes[(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES - PK_BYTES - PK_BYTES)..(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES - PK_BYTES)],
        HeaderData {
            prev_hash: prev_epoch_block_header_bytes[TYPE_BYTE..(TYPE_BYTE + PK_BYTES)].to_vec(),
            inner_lite: prev_epoch_block_header_bytes
                [(TYPE_BYTE + PK_BYTES)..(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES)]
                .to_vec(),
            inner_rest: prev_epoch_block_header_bytes[(TYPE_BYTE + PK_BYTES + INNER_LITE_BYTES)
                ..(prev_epoch_block_header_bytes.len() - SIG_BYTES - TYPE_BYTE)]
                .to_vec(),
        },
    timing_tree)?);

    info!("Proof size {}", prev_epoch_block_proof.to_bytes().len());

    let hash_u32: Vec<u32> = prev_epoch_block_proof
        .public_inputs[0..8]
        .iter()
        .map(|x| x.0 as u32)
        .collect();
    let hash_bytes = vec_u32_to_u8(&hash_u32);

    let gate_serializer = DefaultGateSerializer;
    let verifier_data_bytes = prev_epoch_block_data
        .verifier_data()
        .to_bytes(&gate_serializer)
        .expect("Error reading verifier data");

    let _ = fs::create_dir_all(format!("{STORAGE_PATH}/{prev_block_hash}/bin"));
    let _ = fs::create_dir_all(format!("{STORAGE_PATH}/{prev_block_hash}/gnark"));

    let mut path = format!("{STORAGE_PATH}/{prev_block_hash}/bin/prev_epoch_block_data.bin");
    fs::write(path, verifier_data_bytes).expect("Verifier data writing error");
    path = format!("{STORAGE_PATH}/{prev_block_hash}/bin/prev_epoch_block_proof.bin");
    fs::write(path, prev_epoch_block_proof.to_bytes()).expect("Proof writing error");

    path = format!("{STORAGE_PATH}/{prev_block_hash}/gnark/prev_epoch_block_hexhash.json");
    let hash_hex = encode(hash_bytes);
    fs::write(path, hash_hex).expect("hash_hex writing error");
    path = format!("{STORAGE_PATH}/{prev_block_hash}/gnark/prev_epoch_block_proof.json");
    let mut file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &prev_epoch_block_proof)?;
    path = format!("{STORAGE_PATH}/{prev_block_hash}/gnark/prev_epoch_block_vd.json)");
    file = File::create(path)?;
    writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &prev_epoch_block_data.verifier_only)?;
    path = format!("{STORAGE_PATH}/{prev_block_hash}/gnark/prev_epoch_block_cd.json");
    file = File::create(path)?;
    writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &prev_epoch_block_data.common)?;

    Ok(())
}

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use log::{Level, LevelFilter};
use near_crypto::signature::Signature;
use near_primitives::block::{
    BlockHeader, BlockHeaderInnerLite, BlockHeaderInnerRestV3, BlockHeaderV3,
};
use near_primitives::borsh::BorshSerialize;
use near_primitives::hash::CryptoHash;
use near_primitives::merkle::combine_hash;
use near_primitives::types::validator_stake::ValidatorStake;
use near_primitives::types::ValidatorStakeV1;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;
use plonky2_sha256::circuit::{array_to_bits, sha256_circuit, Sha256Targets};
use plonky2_sha256_j::hash::sha256::{CircuitBuilderHashSha2, WitnessHashSha2};
use plonky2_sha256_j::hash::{CircuitBuilderHash, HashInputTarget, HashOutputTarget};
use rayon::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::sync::RwLock;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

const D: usize = 2;

fn get_sha256_circuits(
    block_lengths: Vec<usize>,
) -> HashMap<
    usize,
    (
        CircuitData<GoldilocksField, PoseidonGoldilocksConfig, D>,
        Sha256Targets,
    ),
> {
    let mut cached_circuits: HashMap<usize, (CircuitData<F, C, D>, Sha256Targets)> = HashMap::new();
    for block_len in block_lengths {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
        let hash_targets = sha256_circuit(&mut builder, block_len * 8);
        let circuit_data = builder.build::<C>();

        cached_circuits.insert(block_len, (circuit_data, hash_targets));
    }
    cached_circuits
}

fn get_sha256_j_circuits(
    block_lengths: Vec<usize>,
) -> HashMap<usize, (CircuitData<F, C, D>, HashInputTarget, HashOutputTarget)> {
    let mut cached_circuits: HashMap<
        usize,
        (CircuitData<F, C, D>, HashInputTarget, HashOutputTarget),
    > = HashMap::new();
    for block_len in block_lengths {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let target_input = builder.add_virtual_hash_input_target(2, 512);
        let target_output = builder.hash_sha256(&target_input);
        let circuit_data = builder.build::<C>();

        cached_circuits.insert(block_len, (circuit_data, target_input, target_output));
    }
    cached_circuits
}

fn proof_with_inputs(
    block: &[u8],
    hash_targets: &Sha256Targets,
    circuit_data: &CircuitData<F, C, D>,
) -> ProofWithPublicInputs<F, C, D> {
    let block_bits = array_to_bits(block);

    let mut pw = PartialWitness::new();
    for i in 0..block_bits.len() {
        pw.set_bool_target(hash_targets.message[i], block_bits[i]);
    }

    let timing = TimingTree::new("prove", Level::Debug);
    let proof = circuit_data.prove(pw.to_owned()).unwrap();
    timing.print();

    proof
}

fn create_and_prove(
    block_header: &BlockHeaderV3,
    cached_circuits: &HashMap<usize, (CircuitData<F, C, D>, Sha256Targets)>,
) -> (ProofWithPublicInputs<F, C, D>, CircuitData<F, C, D>) {
    println!("proving...");
    let mut hasher = Sha256::new();

    let hash_inner = BlockHeader::compute_inner_hash(
        &block_header.inner_lite.try_to_vec().unwrap(),
        &block_header.inner_rest.try_to_vec().unwrap(),
    );

    let test = combine_hash(&hash_inner, &block_header.prev_hash);

    let block: &mut Vec<u8> = &mut Vec::new();
    let combine_hash = (hash_inner, block_header.prev_hash);
    combine_hash
        .serialize(block)
        .expect("failed to serialize to block");
    combine_hash
        .serialize(&mut hasher)
        .expect("failed to serialize to block");

    let final_hash = CryptoHash(hasher.finalize_reset().into());
    hasher.update(block.to_owned());
    let final_hash_manual = CryptoHash(hasher.finalize_reset().into());

    assert_eq!(test, final_hash_manual);
    assert_eq!(test, final_hash);

    let (block_circuit_data, sha256_targets) = cached_circuits.get(&block.len()).unwrap();

    let block_proof_with_pis = proof_with_inputs(&block, sha256_targets, block_circuit_data);

    block_circuit_data
        .verify(block_proof_with_pis.clone())
        .unwrap();

    (block_proof_with_pis, block_circuit_data.to_owned())
}

fn create_and_prove_j(
    block_header: &BlockHeaderV3,
    cached_circuits: &HashMap<usize, (CircuitData<F, C, D>, HashInputTarget, HashOutputTarget)>,
) -> (ProofWithPublicInputs<F, C, D>, CircuitData<F, C, D>) {
    println!("proving...");
    let hash_inner = BlockHeader::compute_inner_hash(
        &block_header.inner_lite.try_to_vec().unwrap(),
        &block_header.inner_rest.try_to_vec().unwrap(),
    );

    let test = combine_hash(&hash_inner, &block_header.prev_hash);

    let block: &mut Vec<u8> = &mut Vec::new();
    let combine_hash = (hash_inner, block_header.prev_hash);
    combine_hash
        .serialize(block)
        .expect("failed to serialize to block");

    let (block_circuit_data, target_input, target_output) =
        cached_circuits.get(&block.len()).unwrap();

    let mut pw = PartialWitness::new();
    pw.set_sha256_input_target(&target_input, &block);
    pw.set_sha256_output_target(&target_output, test.as_bytes());

    let block_proof_with_pis = block_circuit_data.prove(pw).unwrap();

    block_circuit_data
        .verify(block_proof_with_pis.clone())
        .unwrap();

    (block_proof_with_pis, block_circuit_data.to_owned())
}

fn compose(
    proof_with_pis_1: &ProofWithPublicInputs<F, C, D>,
    circuit_data_1: &CircuitData<F, C, D>,
    proof_with_pis_2: &ProofWithPublicInputs<F, C, D>,
    circuit_data_2: &CircuitData<F, C, D>,
) -> (ProofWithPublicInputs<F, C, D>, CircuitData<F, C, D>) {
    println!("composing...");
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let proof_with_pis_target_1 = builder.add_virtual_proof_with_pis(&circuit_data_1.common);
    let proof_with_pis_target_2 = builder.add_virtual_proof_with_pis(&circuit_data_2.common);

    let verifier_circuit_target_1 = VerifierCircuitTarget {
        constants_sigmas_cap: builder
            .add_virtual_cap(circuit_data_1.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let verifier_circuit_target_2 = VerifierCircuitTarget {
        constants_sigmas_cap: builder
            .add_virtual_cap(circuit_data_2.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };

    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&proof_with_pis_target_1, proof_with_pis_1);
    pw.set_proof_with_pis_target(&proof_with_pis_target_2, proof_with_pis_2);
    pw.set_cap_target(
        &verifier_circuit_target_1.constants_sigmas_cap,
        &circuit_data_1.verifier_only.constants_sigmas_cap,
    );
    pw.set_cap_target(
        &verifier_circuit_target_2.constants_sigmas_cap,
        &circuit_data_2.verifier_only.constants_sigmas_cap,
    );
    pw.set_hash_target(
        verifier_circuit_target_1.circuit_digest,
        circuit_data_1.verifier_only.circuit_digest,
    );
    pw.set_hash_target(
        verifier_circuit_target_2.circuit_digest,
        circuit_data_2.verifier_only.circuit_digest,
    );

    builder.verify_proof::<C>(
        &proof_with_pis_target_1,
        &verifier_circuit_target_1,
        &circuit_data_1.common,
    );
    builder.verify_proof::<C>(
        &proof_with_pis_target_2,
        &verifier_circuit_target_2,
        &circuit_data_2.common,
    );

    let circuit_data = builder.build::<C>();
    let proof = circuit_data.prove(pw).unwrap();
    (proof, circuit_data)
}

fn read_blocks() -> Vec<BlockHeaderV3> {
    let mut chain = Vec::new();

    let paths = fs::read_dir("../data/blocks").unwrap();

    for path in paths {
        let contents = fs::read_to_string(path.unwrap().path())
            .expect("Should have been able to read the file");

        let block: Value = serde_json::from_str(&contents).expect("failed to read json");

        let block: Value = block["header"].clone();

        let validator_proposals: Vec<ValidatorStakeV1> =
            serde_json::from_value(block["validator_proposals"].clone())
                .expect("Error in validator_proposals");

        let validator_proposals: Vec<ValidatorStake> = validator_proposals
            .into_iter()
            .map(|x| ValidatorStake::V1(x))
            .collect();

        let inner_rest = BlockHeaderInnerRestV3 {
            chunk_receipts_root: serde_json::from_value(block["chunk_receipts_root"].clone())
                .expect("Error in validator_proposals"),
            chunk_headers_root: serde_json::from_value(block["chunk_headers_root"].clone())
                .expect("Error in validator_proposals"),
            chunk_tx_root: serde_json::from_value(block["chunk_tx_root"].clone())
                .expect("Error in validator_proposals"),
            challenges_root: serde_json::from_value(block["challenges_root"].clone())
                .expect("Error in validator_proposals"),
            random_value: serde_json::from_value(block["random_value"].clone())
                .expect("Error in validator_proposals"),
            validator_proposals,
            chunk_mask: serde_json::from_value(block["chunk_mask"].clone())
                .expect("Error in validator_proposals"),
            gas_price: serde_json::from_value(block["gas_price"].clone())
                .expect("Error in validator_proposals"),
            total_supply: serde_json::from_value(block["total_supply"].clone())
                .expect("Error in validator_proposals"),
            challenges_result: serde_json::from_value(block["challenges_result"].clone())
                .expect("Error in validator_proposals"),
            last_final_block: serde_json::from_value(block["last_final_block"].clone())
                .expect("Error in validator_proposals"),
            last_ds_final_block: serde_json::from_value(block["last_ds_final_block"].clone())
                .expect("Error in validator_proposals"),
            block_ordinal: serde_json::from_value(block["block_ordinal"].clone())
                .expect("Error in validator_proposals"),
            prev_height: serde_json::from_value(block["prev_height"].clone())
                .expect("Error in validator_proposals"),
            epoch_sync_data_hash: serde_json::from_value(block["epoch_sync_data_hash"].clone())
                .expect("Error in validator_proposals"),
            approvals: serde_json::from_value(block["approvals"].clone())
                .expect("Error in validator_proposals"),
            latest_protocol_version: serde_json::from_value(
                block["latest_protocol_version"].clone(),
            )
            .expect("Error in validator_proposals"),
        };

        let prev_hash: CryptoHash =
            serde_json::from_value(block["prev_hash"].clone()).expect("Error in prev_hash");
        let hash: CryptoHash =
            serde_json::from_value(block["hash"].clone()).expect("Error in hash");
        let inner_lite: BlockHeaderInnerLite =
            serde_json::from_value(block.clone()).expect("Error innerlite");
        let signature: Signature =
            serde_json::from_value(block["signature"].clone()).expect("Error in sig");

        let header = BlockHeaderV3 {
            prev_hash,
            inner_lite,
            inner_rest,
            signature,
            hash,
        };
        chain.push(header);
    }
    chain
}

fn main() {
    let chain = read_blocks();

    let mut logger = env_logger::Builder::from_default_env();
    logger.format_timestamp(None);
    logger.filter_level(LevelFilter::Info);
    logger.try_init().unwrap();

    {
        //Parallel computation
        //Change number of blocks to process from 1 to 100 in .take().
        println!("Parsed");
        //let chain = chain.iter().take(5).collect::<Vec<&BlockHeaderV3>>(); //Remove to process all 100 blocks
        //println!("Take 5");
        let block_lenghts = vec![CryptoHash::default().as_bytes().len() * 2];
        let cached_circuits = Arc::new(RwLock::new(get_sha256_j_circuits(block_lenghts)));

        let timing = TimingTree::new("Build proofs parallel", Level::Info);
        let proofs: Vec<_> = chain
            .par_iter()
            .map(|block| create_and_prove_j(block, &cached_circuits.clone().read().unwrap()))
            .collect();
        timing.print();

        let timing = TimingTree::new("Compose parallel", Level::Info);
        let (proof, data) = proofs
            .par_iter()
            .cloned()
            .reduce_with(|acc, x| compose(&acc.0, &acc.1, &x.0, &x.1))
            .unwrap();
        timing.print();

        let proof_bytes = proof.to_bytes();
        println!("Final proof size: {} bytes", proof_bytes.len());
        data.verify(proof).unwrap();
    }

    {
        //Parallel computation
        //Change number of blocks to process from 1 to 100 in .take().
        println!("Parsed");
        //let chain = chain.iter().take(5).collect::<Vec<&BlockHeaderV3>>(); //Remove to process all 100 blocks
        //println!("Take 5");
        let block_lenghts = vec![CryptoHash::default().as_bytes().len() * 2];
        let cached_circuits = Arc::new(RwLock::new(get_sha256_circuits(block_lenghts)));

        let timing = TimingTree::new("Build proofs parallel", Level::Info);
        let proofs: Vec<_> = chain
            .par_iter()
            .map(|block| create_and_prove(block, &cached_circuits.clone().read().unwrap()))
            .collect();
        timing.print();

        let timing = TimingTree::new("Compose parallel", Level::Info);
        let (proof, data) = proofs
            .par_iter()
            .cloned()
            .reduce_with(|acc, x| compose(&acc.0, &acc.1, &x.0, &x.1))
            .unwrap();
        timing.print();

        let proof_bytes = proof.to_bytes();
        println!("Final proof size: {} bytes", proof_bytes.len());
        data.verify(proof).unwrap();
    }
}

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use itertools::Itertools;
use jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use log::{Level, LevelFilter};
use near_crypto::signature::Signature;
use near_primitives::block::{BlockHeaderInnerLite, BlockHeaderInnerRestV3, BlockHeaderV3};
use near_primitives::borsh::BorshSerialize;
use near_primitives::hash::CryptoHash;
use near_primitives::types::validator_stake::ValidatorStake;
use near_primitives::types::ValidatorStakeV1;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;
use plonky2_sha256_j::hash::sha256::{CircuitBuilderHashSha2, WitnessHashSha2};
use plonky2_sha256_j::hash::{CircuitBuilderHash, HashInputTarget, HashOutputTarget};
use rayon::prelude::*;
use serde_json::Value;
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Instant;
use std::{fs, io};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

const D: usize = 2;

fn get_sha256_circuits(
    lenghts: Vec<usize>,
) -> HashMap<usize, (CircuitData<F, C, D>, HashInputTarget, HashOutputTarget)> {
    let mut cached_circuits: HashMap<
        usize,
        (CircuitData<F, C, D>, HashInputTarget, HashOutputTarget),
    > = HashMap::new();
    for len in lenghts {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let block_count = (len * 8 + 65 + 511) / 512;
        let target_input = builder.add_virtual_hash_input_target(block_count, 512);
        let target_output = builder.hash_sha256(&target_input);
        let circuit_data = builder.build::<C>();

        cached_circuits.insert(len, (circuit_data, target_input, target_output));
    }
    cached_circuits
}

fn prove(
    validators_list: &Vec<u8>,
    cached_circuits: &HashMap<usize, (CircuitData<F, C, D>, HashInputTarget, HashOutputTarget)>,
) -> (ProofWithPublicInputs<F, C, D>, CircuitData<F, C, D>) {
    println!("proving...");

    let (block_circuit_data, target_input, target_output) =
        cached_circuits.get(&validators_list.len()).unwrap();

    let mut hasher = sha2::Sha256::default();
    hasher.update(validators_list.as_slice());

    let mut pw = PartialWitness::new();
    pw.set_sha256_input_target(&target_input, &validators_list);
    pw.set_sha256_output_target(&target_output, &hasher.finalize());

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

    let mut paths = fs::read_dir("../data/blocks")
        .unwrap()
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()
        .unwrap();

    paths.sort();

    for path in paths {
        let contents = fs::read_to_string(path).expect("Should have been able to read the file");

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

fn read_validators() -> Vec<Vec<u8>> {
    let mut validators = Vec::new();

    let mut paths = fs::read_dir("../data/validators")
        .unwrap()
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()
        .unwrap();

    paths.sort();

    for path in paths {
        let contents = fs::read_to_string(path).expect("Should have been able to read the file");
        let json: Value = serde_json::from_str(&contents).expect("failed to read json");
        let json_result: Value = json["result"].clone();

        let current_validators: Vec<ValidatorStakeV1> =
            serde_json::from_value(json_result).expect("Error in current_validators");
        let current_validators: Vec<ValidatorStake> = current_validators
            .into_iter()
            .map(|x| ValidatorStake::V1(x))
            .collect();

        let iter = current_validators.into_iter();
        let n = u32::try_from(iter.len()).unwrap();
        let mut serialized_list: Vec<u8> = n.to_le_bytes().to_vec();
        iter.for_each(|value| BorshSerialize::serialize(&value, &mut serialized_list).unwrap());

        validators.push(serialized_list);
    }
    validators
}

fn main() {
    let mut chain = read_blocks();
    let mut validators_lists = read_validators();

    chain.truncate(5);
    validators_lists.truncate(5);

    println!("Parsed");

    let mut logger = env_logger::Builder::from_default_env();
    logger.format_timestamp(None);
    logger.filter_level(LevelFilter::Info);
    logger.try_init().unwrap();

    let block_lenghts = validators_lists
        .iter()
        .map(|validator_list| validator_list.len())
        .sorted()
        .dedup()
        .collect_vec();
    println!("{:?}", block_lenghts);
    let cached_circuits = Arc::new(RwLock::new(get_sha256_circuits(block_lenghts)));

    let timing = TimingTree::new("Map-reduce", Level::Info);
    let now = Instant::now();

    // Simple map-reduce, works ony with small data samples.
    // let (proof, data) = validators_lists
    //     .par_iter()
    //     .map(|validator_list| prove(validator_list, &cached_circuits.clone().read().unwrap()))
    //     .reduce_with(|acc, x| compose(&acc.0, &acc.1, &x.0, &x.1))
    //     .unwrap();

    let (proof, data) = validators_lists
        .chunks(20)
        .map(|chunk| {
            chunk
                .par_iter()
                .map(|validator_list| {
                    prove(validator_list, &cached_circuits.clone().read().unwrap())
                })
                .reduce_with(|acc, x| compose(&acc.0, &acc.1, &x.0, &x.1))
                .unwrap()
        })
        .par_bridge()
        .reduce_with(|acc, x| compose(&acc.0, &acc.1, &x.0, &x.1))
        .unwrap();

    timing.print();
    println!("Map-reduce {}", now.elapsed().as_secs());

    let proof_bytes = proof.to_bytes();
    println!("Final proof size: {} bytes", proof_bytes.len());
    data.verify(proof).unwrap();
}

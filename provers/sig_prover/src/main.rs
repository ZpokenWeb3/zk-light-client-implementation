#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use log::{Level, LevelFilter};
use near_crypto::signature::Signature;
use near_primitives::block::{BlockHeaderInnerLite, BlockHeaderInnerRestV3, BlockHeaderV3};
use near_primitives::block_header::{Approval, ApprovalInner};
use near_primitives::hash::CryptoHash;
use near_primitives::types::validator_stake::ValidatorStake;
use near_primitives::types::ValidatorStakeV1;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;
use plonky2_ed25519::gadgets::eddsa::{ed25519_circuit, fill_ecdsa_targets, EDDSATargets};
use plonky2_field::extension::Extendable;
use serde_json::Value;
use std::fs;
use std::iter::zip;
use std::time::Instant;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

const D: usize = 2;

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

fn read_block() -> BlockHeaderV3 {
    let contents =
        fs::read_to_string("./data/block.json").expect("Should have been able to read the file");

    let block: Value = serde_json::from_str(&contents).expect("failed to read json");
    let block: Value = block["header"].clone();

    let validator_proposals: Vec<ValidatorStakeV1> =
        serde_json::from_value(block["validator_proposals"].clone())
            .expect("Error in validator_proposals");

    let validator_proposals: Vec<ValidatorStake> = validator_proposals
        .into_iter()
        .map(ValidatorStake::V1)
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
        latest_protocol_version: serde_json::from_value(block["latest_protocol_version"].clone())
            .expect("Error in validator_proposals"),
    };

    let prev_hash: CryptoHash =
        serde_json::from_value(block["prev_hash"].clone()).expect("Error in prev_hash");
    let hash: CryptoHash = serde_json::from_value(block["hash"].clone()).expect("Error in hash");
    let inner_lite: BlockHeaderInnerLite =
        serde_json::from_value(block.clone()).expect("Error innerlite");
    let signature: Signature =
        serde_json::from_value(block["signature"].clone()).expect("Error in sig");

    BlockHeaderV3 {
        prev_hash,
        inner_lite,
        inner_rest,
        signature,
        hash,
    }
}

fn read_validators() -> Vec<ValidatorStake> {
    let contents = fs::read_to_string("./data/validators.json")
        .expect("Should have been able to read the file");

    let json: Value = serde_json::from_str(&contents).expect("failed to read json");
    let json_result: Value = json["result"].clone();

    let current_validators: Vec<ValidatorStakeV1> =
        serde_json::from_value(json_result).expect("Error in current_validators");
    let current_validators: Vec<ValidatorStake> = current_validators
        .into_iter()
        .map(ValidatorStake::V1)
        .collect();
    current_validators
}

fn prove_ed25519_with_targets<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
    targets: &EDDSATargets,
    data: &CircuitData<F, C, D>,
) -> (ProofWithPublicInputs<F, C, D>, CircuitData<F, C, D>) {
    let mut pw = PartialWitness::new();
    fill_ecdsa_targets::<F, D>(&mut pw, msg, sigv, pkv, targets);

    let timing = TimingTree::new("prove", Level::Info);
    let proof = data.prove(pw).unwrap();
    timing.print();

    let timing = TimingTree::new("verify", Level::Info);
    data.verify(proof.clone()).expect("verify error");
    timing.print();

    (proof, data.clone())
}

fn main() {
    let block = read_block();
    let validators_lists = read_validators();

    println!("Parsed");

    let msg = Approval::get_data_for_sig(
        &ApprovalInner::Endorsement(block.prev_hash),
        block.inner_rest.prev_height + 1,
    );

    let mut logger = env_logger::Builder::from_default_env();
    logger.format_timestamp(None);
    logger.filter_level(LevelFilter::Info);
    logger.try_init().unwrap();

    let creds: Vec<_> = zip(validators_lists, block.inner_rest.approvals)
        .filter(|pair| pair.1.is_some())
        .filter(|pair| pair.1.as_ref().unwrap().verify(&msg, pair.0.public_key()))
        .map(|pair| {
            let sig = match pair.clone().1.unwrap() {
                Signature::ED25519(sig) => sig.to_bytes(),
                Signature::SECP256K1(_) => panic!(),
            };
            let pk = pair.0.public_key().clone();
            (pk.unwrap_as_ed25519().0.as_slice().to_owned(), sig)
        })
        .collect();

    println!("Valid sigs {}", creds.len());
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
    let targets = ed25519_circuit(&mut builder, msg.len() * 8);
    let data = builder.build::<C>();

    let timing = TimingTree::new("Map-reduce", Level::Info);
    let now = Instant::now();
    let (proof, data) = creds
        .iter()
        .map(|x| prove_ed25519_with_targets::<F, C, D>(msg.as_slice(), &x.1, &x.0, &targets, &data))
        .reduce(|acc, x| compose(&acc.0, &acc.1, &x.0, &x.1))
        .unwrap();
    timing.print();
    println!("Map-reduce {}", now.elapsed().as_secs());
    data.verify(proof).unwrap();
}

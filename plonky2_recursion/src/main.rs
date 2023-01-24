#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use plonky2::field::goldilocks_field::GoldilocksField;

use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, VerifierCircuitTarget,
};

use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use plonky2::util::timing::TimingTree;

use plonky2_recursion::hash::circuit::{array_to_bits, make_circuits};
use plonky2_recursion::sig::gadgets::eddsa::{fill_circuits, make_verify_circuits};

use ed25519_compact::*;
use log::{Level, LevelFilter};
use sha2::{Digest, Sha256};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;

const D: usize = 2;

fn make_genesis_circuit_and_proof(
    config: CircuitConfig,
    genesis_block: &[u8],
    genesis_hash: &[u8],
) -> (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>) {
    let block_bits = array_to_bits(genesis_block);
    let len = genesis_block.len() * 8;

    let mut builder = CircuitBuilder::<F, D>::new(config);
    let targets = make_circuits(&mut builder, len as u64);
    let mut pw = PartialWitness::new();

    for i in 0..len {
        pw.set_bool_target(targets.message[i], block_bits[i]);
        builder.register_public_input(targets.message[i].target);
    }

    let expected_res = array_to_bits(genesis_hash);
    for i in 0..expected_res.len() {
        if expected_res[i] {
            builder.assert_one(targets.digest[i].target);
        } else {
            builder.assert_zero(targets.digest[i].target);
        }
    }

    //  builder.add_verifier_data_public_inputs();

    let data = builder.build::<C>();

    let timing = TimingTree::new("prove", Level::Debug);
    let proof = data.prove(pw).unwrap();
    timing.print();

    let timing = TimingTree::new("verify", Level::Debug);
    match data.verify(proof.clone()) {
        Ok(()) => println!("Genesis proof: Ok!"),
        Err(x) => println!("{}", x),
    }
    timing.print();

    //println!("Proof with pis size is {}", size_of_val(&proof));
    //println!("Curcuit size is {}", size_of_val(&data));

    //println!("pub input {:?}", proof.public_inputs);
    //let proof_bytes = proof.to_bytes();
    //println!("Genesis proof: {} bytes", proof_bytes.len());

    (data, proof)
}

fn make_recursive_circuit_and_proof(
    config: CircuitConfig,
    block: &[u8],
    block_hash: &[u8],
    public_key: &[u8],
    signature: &[u8],
    circuit_data: &CircuitData<F, C, D>,
    proof_with_pis: &ProofWithPublicInputs<F, C, D>,
) -> (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>) {
    // println!("pub input of pis {:?}", proof_with_pis.public_inputs);

    let mut recursive_builder = CircuitBuilder::<F, D>::new(config);

    //hash
    let block_bits = array_to_bits(block);
    let len = block.len() * 8;
    let targets = make_circuits(&mut recursive_builder, len as u64);
    let mut pw = PartialWitness::new();

    //TODO make fiil cuircit for hash
    for i in 0..len {
        pw.set_bool_target(targets.message[i], block_bits[i]);
        recursive_builder.register_public_input(targets.message[i].target);
    }

    let expected_res = array_to_bits(block_hash);
    for i in 0..expected_res.len() {
        if expected_res[i] {
            recursive_builder.assert_one(targets.digest[i].target);
        } else {
            recursive_builder.assert_zero(targets.digest[i].target);
        }
    }

    //elliptic
    let targets = make_verify_circuits(&mut recursive_builder, block.len());
    fill_circuits::<F, D>(&mut pw, block, signature, public_key, &targets);

    //recursion
    let proof_with_pis_target =
        recursive_builder.add_virtual_proof_with_pis::<C>(&circuit_data.common);

    let verifier_circuit_target = VerifierCircuitTarget {
        constants_sigmas_cap: recursive_builder
            .add_virtual_cap(circuit_data.common.config.fri_config.cap_height),
        circuit_digest: recursive_builder.add_virtual_hash(),
    };

    recursive_builder.verify_proof::<C>(
        &proof_with_pis_target,
        &verifier_circuit_target,
        &circuit_data.common,
    );

    pw.set_proof_with_pis_target(&proof_with_pis_target, proof_with_pis);
    pw.set_verifier_data_target(&verifier_circuit_target, &circuit_data.verifier_only);

    let data = recursive_builder.build::<C>();
    let timing = TimingTree::new("prove", Level::Debug);
    let proof = data.prove(pw).unwrap();
    timing.print();

    let timing = TimingTree::new("verify", Level::Debug);
    match data.verify(proof.clone()) {
        Ok(()) => println!("Recursive proof: Ok!"),
        Err(x) => println!("{}", x),
    }
    timing.print();

    //    println!("Proof with pis size is {}", size_of_val(&proof));
    //    println!("Curcuit size is {}", size_of_val(&data));

    //println!("pub input {:?}", proof.public_inputs);
    //let proof_bytes = proof.to_bytes();
    //println!("Recursive proof: {} bytes", proof_bytes.len());

    (data, proof)
}

fn create_and_prove(
    hasher: &mut Sha256,
    config: &CircuitConfig,
    block_nonce: &[u8],
    block_1_hash: &[u8],
    block_1_circuit_data: &CircuitData<F, C, D>,
    block_1_proof_with_pis: &ProofWithPublicInputs<F, C, D>,
) -> (
    CircuitData<F, C, D>,
    ProofWithPublicInputs<F, C, D>,
    Vec<u8>,
) {
    let block_2 = ["Block".as_bytes(), block_nonce, block_1_hash].concat();
    hasher.update(block_2.to_owned());
    let block_2_hash = hasher.finalize_reset();
    //    println!("2 Block: {:?}", block_2);
    //    println!("2 Hash: {:#04X}", block_2_hash);
    let key_pair = KeyPair::from_seed(Seed::generate());
    let signature = key_pair.sk.sign(&block_2, Some(Noise::generate()));

    let (block_2_circuit_data, block_2_proof_with_pis) = make_recursive_circuit_and_proof(
        config.clone(),
        &block_2,
        &block_2_hash,
        key_pair.pk.as_ref(),
        signature.as_ref(),
        &block_1_circuit_data,
        &block_1_proof_with_pis,
    );
    let proof_bytes = block_2_proof_with_pis.to_bytes();
    println!("Recursive proof: {} bytes", proof_bytes.len());
    (
        block_2_circuit_data,
        block_2_proof_with_pis,
        (block_2_hash).to_vec(),
    )
}

fn main() {
    let mut hasher = Sha256::new();

    let config = CircuitConfig::wide_ecc_config();

    let mut logger = env_logger::Builder::from_default_env();
    logger.format_timestamp(None);
    logger.filter_level(LevelFilter::Debug);
    logger.try_init().unwrap();

    let genesis_block = "Genesis".as_bytes();
    hasher.update(genesis_block.to_owned());
    let genesis_hash = hasher.finalize_reset();
    //    println!("Genesis Block: {:?}", genesis_block);
    //    println!("Genesis Hash: {:#04X}", genesis_hash);
    let (genesis_circuit_data, genesis_proof_with_pis) =
        make_genesis_circuit_and_proof(config.clone(), &genesis_block, &genesis_hash);

    let block = ["Block 1".as_bytes(), genesis_hash.as_slice()].concat();
    hasher.update(block.to_owned());
    let block_hash = hasher.finalize_reset();
    let mut block_hash = block_hash.to_vec();
    //    println!("1 Block: {:?}", block_1);
    //    println!("1 Hash: {:#04X}", block_1_hash);
    let key_pair = KeyPair::from_seed(Seed::generate());
    let signature = key_pair.sk.sign(&block, Some(Noise::generate()));

    let (mut block_circuit_data, mut block_proof_with_pis) = make_recursive_circuit_and_proof(
        config.clone(),
        &block,
        &block_hash,
        key_pair.pk.as_ref(),
        signature.as_ref(),
        &genesis_circuit_data,
        &genesis_proof_with_pis,
    );

    for block_number in 2..=10 {
        (block_circuit_data, block_proof_with_pis, block_hash) = create_and_prove(
            &mut hasher,
            &config,
            block_number.to_string().as_bytes(),
            &block_hash,
            &block_circuit_data,
            &block_proof_with_pis,
        );
    }

    let proof_bytes = block_proof_with_pis.to_bytes();
    println!("Recursive proof: {} bytes", proof_bytes.len());

    block_circuit_data.verify(block_proof_with_pis).unwrap();
}

use std::collections::HashMap;

use anyhow::Result;
use log::Level;
use near_primitives::{borsh, hash::hash};
use plonky2::{
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
    util::timing::TimingTree,
};
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::Hasher;
use plonky2_field::extension::Extendable;

use plonky2_ed25519::gadgets::eddsa::{ed25519_circuit, EDDSATargets, fill_ecdsa_targets};
use plonky2_sha256::circuit::{array_to_bits, sha256_circuit, Sha256Targets};
use plonky2_sha256_u32::sha256::{CircuitBuilderHashSha2, WitnessHashSha2};
use plonky2_sha256_u32::types::CircuitBuilderHash;

use crate::{recursion::recursive_proof, utils::u8bit_to_u8byte};
use crate::utils::vec_u32_to_u8;

pub const SHA256_BLOCK: usize = 512;

/// Verifies that two proofs for hashes are valid & aggregates them into one proof. 
/// Concatenates hashes into one array, proves that a hash of the concatenation is equal to the third hash.
/// Aggregates two proofs: aggregation of first two hashes & proof of the third one, sets the third hash as public inputs.
/// All proving functions use u32 values.
/// See more [`prove_sub_hashes_bits`]
pub fn prove_sub_hashes_u32<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
    const D: usize,
>(
    set_pis_1: bool,
    set_pis_2: bool,
    pis_hash_1: &[F],
    pis_hash_2: &[F],
    final_hash: Option<&[u8]>,
    (hash_common_1, hash_verifier_1, hash_proof_1): (
        &CommonCircuitData<F, D>,
        &VerifierOnlyCircuitData<C, D>,
        &ProofWithPublicInputs<F, C, D>,
    ),
    hash_data_proof_2: Option<(
        &CommonCircuitData<F, D>,
        &VerifierOnlyCircuitData<C, D>,
        &ProofWithPublicInputs<F, C, D>,
    )>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
{
    let mut pis: Option<&[F]> = Option::None;
    let mut vec = vec![];
    if set_pis_1 {
        vec.append(&mut pis_hash_1.to_vec());
        pis = Some(vec.as_slice());
    }
    if set_pis_2 {
        vec.append(&mut pis_hash_2.to_vec());
        pis = Some(vec.as_slice());
    }
    let (inner_data, inner_proof) = recursive_proof(
        (&hash_common_1, &hash_verifier_1, &hash_proof_1),
        hash_data_proof_2,
        pis,
    )?;
    // prove hash based on two sub hashes
    let pi: Vec<u32> = inner_proof
        .public_inputs
        .iter()
        .map(|x| x.to_canonical_u64() as u32)
        .collect();
    let mut msg = vec_u32_to_u8(&pi);
    if hash_data_proof_2.is_none() {
        let mut hash: Vec<u8> = pis_hash_2
            .iter()
            .map(|x| x.to_noncanonical_u64() as u8)
            .collect();
        msg.append(&mut hash);
    }
    let mut final_hash_bytes = vec![];
    if final_hash.is_some() {
        final_hash_bytes = final_hash.unwrap().to_vec();
    } else {
        final_hash_bytes = borsh::to_vec(&hash(&msg))?;
    }
    let (hash_d, hash_p) = sha256_proof_u32(&msg, &final_hash_bytes)?;
    let (result_d, result_p) = recursive_proof(
        (&inner_data.common, &inner_data.verifier_only, &inner_proof),
        Some((&hash_d.common, &hash_d.verifier_only, &hash_p)),
        Some(&hash_p.public_inputs),
    )?;
    Ok((result_d, result_p))
}

/// Verifies that two proofs for hashes are valid & aggregates them into one proof. 
/// Concatenates hashes into one array, proves that a hash of the concatenation is equal to the third hash.
/// Aggregates two proofs: aggregation of first two hashes & proof of the third one, sets the third hash as public inputs.
/// All proving functions use bit values.
/// # Arguments
///
/// * `pis_hash_1` - A first hash represented as an array of field elements.
/// * `pis_hash_2` - A second hash represented as an array of field elements.
/// * `final_hash` - A hash of concatenation of pis_hash_1 & pis_hash_2.
/// * `(hash_common_1, hash_verifier_1, hash_proof_1)` - A proof for the first hash.
/// * `hash_data_proof_2` - A proof for the second hash (optional value).
/// * `set_pis_1` - A flag that indicates whether to set first hash as public inputs in aggregation.
/// * `set_pis_2` - A flag that indicates whether to set second hash as public inputs in aggregation.
///
/// # Returns
///
/// Returns a result containing the computed circuit data and the proof with public inputs.
/// - `CircuitData<F, C, D>`: The circuit data generated during the proof generation process.
/// - `ProofWithPublicInputs<F, C, D>`: The proof along with the third hash as public inputs.
///
pub fn prove_sub_hashes_bits<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
    const D: usize,
>(
    set_pis_1: bool,
    set_pis_2: bool,
    pis_hash_1: &[F],
    pis_hash_2: &[F],
    final_hash: Option<&[u8]>,
    (hash_common_1, hash_verifier_1, hash_proof_1): (
        &CommonCircuitData<F, D>,
        &VerifierOnlyCircuitData<C, D>,
        &ProofWithPublicInputs<F, C, D>,
    ),
    hash_data_proof_2: Option<(
        &CommonCircuitData<F, D>,
        &VerifierOnlyCircuitData<C, D>,
        &ProofWithPublicInputs<F, C, D>,
    )>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
    where
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
{
    let mut pis: Option<&[F]> = Option::None;
    let mut vec = vec![];
    if set_pis_1 {
        vec.append(&mut pis_hash_1.to_vec());
        pis = Some(vec.as_slice());
    }
    if set_pis_2 {
        vec.append(&mut pis_hash_2.to_vec());
        pis = Some(vec.as_slice());
    }
    let (inner_data, inner_proof) = recursive_proof(
        (&hash_common_1, &hash_verifier_1, &hash_proof_1),
        hash_data_proof_2,
        pis,
    )?;
    // prove hash based on two sub hashes
    let pi: Vec<u8> = inner_proof
        .public_inputs
        .iter()
        .map(|x| x.to_canonical_u64() as u8)
        .collect();
    let mut msg = u8bit_to_u8byte(&pi);
    if !set_pis_2 {
        let mut hash: Vec<u8> = pis_hash_2
            .iter()
            .map(|x| x.to_noncanonical_u64() as u8)
            .collect();
        msg.append(&mut hash);
    }
    let mut final_hash_bytes = vec![];
    if final_hash.is_some() {
        final_hash_bytes = final_hash.unwrap().to_vec();
    } else {
        final_hash_bytes = borsh::to_vec(&hash(&msg))?;
    }
    let (hash_d, hash_p) = sha256_proof_pis_bits(&msg, &final_hash_bytes, true)?;
    let (result_d, result_p) = recursive_proof(
        (&inner_data.common, &inner_data.verifier_only, &inner_proof),
        Some((&hash_d.common, &hash_d.verifier_only, &hash_p)),
        Some(&hash_p.public_inputs),
    )?;
    Ok((result_d, result_p))
}

/// Computes a SHA-256 proof with public inputs in format of u32 values for a given message and its hash.
///
/// # Arguments
///
/// * `msg` - A slice of bytes representing the message for which the proof is to be computed.
/// * `hash` - A slice of bytes representing the hash of the message.
///
/// # Returns
///
/// Returns a tuple containing the computed circuit data(proving schema) and the proof with public inputs.
/// - `CircuitData<F, C, D>`: The circuit data generated during the proof generation process.
/// - `ProofWithPublicInputs<F, C, D>`: The proof along with public inputs in u32 limbs.
///
/// # Panics
///
/// This function panics if the proof generation fails.
///
/// # Examples
///
/// ```rust
///
/// use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
/// use block_finality::prove_crypto::sha256_proof_u32;
///
/// const D: usize = 2;
/// type C = PoseidonGoldilocksConfig;
/// type F = <C as GenericConfig<D>>::F;
///
/// // Define a message and its corresponding hash
///
/// let message = "60";
/// let hash = "8d33f520a3c4cef80d2453aef81b612bfe1cb44c8b2025630ad38662763f13d3";
/// let input = hex::decode(message).unwrap();
/// let output = hex::decode(hash).unwrap();
///
/// // Compute SHA-256 proof
/// let (circuit_data, proof) = sha256_proof_u32::<F, C, D>(&input, &output)?;;
/// ```
pub fn sha256_proof_u32<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
    const D: usize,
>(
    msg: &[u8],
    hash: &[u8],
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    let len_in_bits = msg.len() * 8;
    let block_num = (len_in_bits + 64 + 512) / 512;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let hash_target = builder.add_virtual_hash_input_target(block_num, SHA256_BLOCK);
    let hash_output = builder.hash_sha256(&hash_target);
    for i in 0..hash_output.limbs.len() {
        builder.register_public_input(hash_output.limbs[i].0);
    }
    let data = builder.build::<C>();
    let mut pw = PartialWitness::new();
    pw.set_sha256_input_target(&hash_target, msg);
    pw.set_sha256_output_target(&hash_output, hash);
    let proof = data.prove(pw).unwrap();
    Ok((data, proof))
}

/// Computes SHA256 targets and proving scheme depending on specific message length in bits and save in HashMap in order to reuse.
pub fn get_sha256_circuit_targets_bits<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
    const D: usize,
>(
    msg_len_in_bits: usize,
    cached_circuits: &mut HashMap<usize, (CircuitData<F, C, D>, Sha256Targets)>,
) -> (CircuitData<F, C, D>, Sha256Targets) {
    match cached_circuits.get(&msg_len_in_bits) {
        Some(cache) => cache.clone(),
        None => {
            let mut builder =
                CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
            let targets = sha256_circuit(&mut builder, msg_len_in_bits);

            let timing = TimingTree::new("build", Level::Info);
            let circuit_data = builder.build::<C>();
            timing.print();

            cached_circuits.insert(msg_len_in_bits, (circuit_data.clone(), targets.clone()));

            (circuit_data, targets)
        }
    }
}

/// Computes SHA-256 proofs with bits public inputs for a given message and its hash, reusing existing circuit data bits or creating new.
/// See [`sha256_proof_pis_bits`] for more details.
pub fn sha256_proof_reuse_circuit_bits<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
    const D: usize,
>(
    msg: &[u8],
    hash: &[u8],
    sha256_circuits: &mut HashMap<usize, (CircuitData<F, C, D>, Sha256Targets)>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    let len_in_bits = msg.len() * 8;
    let (circuit_data, targets): (CircuitData<F, C, D>, Sha256Targets) =
        get_sha256_circuit_targets_bits(len_in_bits, sha256_circuits);
    let msg_bits = array_to_bits(msg);
    let hash_bits = array_to_bits(hash);
    let mut pw: PartialWitness<F> = PartialWitness::new();
    for i in 0..msg_bits.len() {
        pw.set_bool_target(targets.message[i], msg_bits[i]);
    }
    for i in 0..hash_bits.len() {
        pw.set_bool_target(targets.digest[i], hash_bits[i]);
    }
    let timing = TimingTree::new("prove", Level::Info);
    let proof = circuit_data.prove(pw)?;
    timing.print();
    Ok((circuit_data, proof))
}

/// Computes a SHA-256 proofs with bits public inputs for a given message and its hash.
///
/// # Arguments
///
/// * `msg` - A slice of bytes representing the message for which the proof is to be computed.
/// * `hash` - A slice of bytes representing the hash of the message.
/// * `sha256_circuits` - A mutable reference to a hashmap containing previously computed circuit
///   data and plonky2 targets.
///
/// # Returns
///
/// Returns a tuple containing the computed circuit data and the proof with bits public inputs.
/// - `CircuitData<F, C, D>`: The circuit data generated during the proof generation process.
/// - `ProofWithPublicInputs<F, C, D>`: The proof along with public inputs.
pub fn sha256_proof_pis_bits<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
    const D: usize,
>(
    msg: &[u8],
    hash: &[u8],
    set_pis: bool,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    let len_in_bits = msg.len() * 8;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let targets = sha256_circuit(&mut builder, len_in_bits);
    let msg_bits = array_to_bits(msg);
    let hash_bits = array_to_bits(hash);
    let mut pw: PartialWitness<F> = PartialWitness::new();
    for i in 0..msg_bits.len() {
        pw.set_bool_target(targets.message[i], msg_bits[i]);
    }
    for i in 0..hash_bits.len() {
        pw.set_bool_target(targets.digest[i], hash_bits[i]);
    }
    if set_pis {
        for i in 0..hash_bits.len() {
            builder.register_public_input(targets.digest[i].target);
        }
    }
    let timing = TimingTree::new("build", Level::Info);
    let circuit_data = builder.build::<C>();
    timing.print();
    let timing = TimingTree::new("prove", Level::Info);
    let proof = circuit_data.prove(pw)?;
    timing.print();
    Ok((circuit_data, proof))
}

pub fn get_ed25519_circuit_targets<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
    const D: usize,
>(
    msg_len_in_bits: usize,
    cached_circuits: &mut HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)>,
) -> (CircuitData<F, C, D>, EDDSATargets) {
    match cached_circuits.get(&msg_len_in_bits) {
        Some(cache) => cache.clone(),
        None => {
            let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
            let targets = ed25519_circuit(&mut builder, msg_len_in_bits);

            let timing = TimingTree::new("build", Level::Info);
            let circuit_data = builder.build::<C>();
            timing.print();

            cached_circuits.insert(msg_len_in_bits, (circuit_data.clone(), targets.clone()));

            (circuit_data, targets)
        }
    }
}

/// Creating ED25519 proof reusing proving schema and targets
pub fn ed25519_proof_reuse_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
    const D: usize,
>(
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
    ed25519_circuits: &mut HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    let len_in_bits = msg.len() * 8;
    let (circuit_data, targets): (CircuitData<F, C, D>, EDDSATargets) =
        get_ed25519_circuit_targets(len_in_bits, ed25519_circuits);
    let mut pw: PartialWitness<F> = PartialWitness::new();
    fill_ecdsa_targets::<F, D>(&mut pw, msg, sigv, pkv, &targets);
    let timing = TimingTree::new("prove", Level::Info);
    let proof = circuit_data.prove(pw)?;
    timing.print();
    Ok((circuit_data, proof))
}

/// Computes an Ed25519 proof for a given message, signature, and public key.
///
/// # Arguments
///
/// * `msg` - A slice of bytes representing the message for which the proof is to be computed.
/// * `sigv` - A slice of bytes representing the Ed25519 signature.
/// * `pkv` - A slice of bytes representing the Ed25519 public key.
/// * `circuit_data` - A tuple containing the existing proving schema and targets.
///
/// # Returns
///
/// Returns a result containing the computed Ed25519 proof with public inputs.
pub fn ed25519_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
    const D: usize,
>(
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
    circuit_data: (CircuitData<F, C, D>, EDDSATargets),
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw: PartialWitness<F> = PartialWitness::new();
    fill_ecdsa_targets::<F, D>(&mut pw, msg, sigv, pkv, &circuit_data.1);
    let timing = TimingTree::new("Prove signature", Level::Info);
    let proof = circuit_data.0.prove(pw)?;
    timing.print();
    Ok(proof)
}

/// Computes EDD5519 targets and proving schema depending on specific message length in bits.
pub fn get_ed25519_targets<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
    const D: usize,
>(
    msg_len_in_bits: usize
) -> anyhow::Result<(CircuitData<F, C, D>, EDDSATargets)> {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
    let targets = ed25519_circuit(&mut builder, msg_len_in_bits);
    let circuit_data = builder.build::<C>();
    Ok((circuit_data, targets))
}

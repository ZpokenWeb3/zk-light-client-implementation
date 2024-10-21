use crate::utils::vec_u32_to_u8;
use anyhow::Result;
use near_primitives::{borsh, hash::hash};
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::Hasher;
use plonky2::{
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use plonky2_field::extension::Extendable;
use plonky2_sha256_u32::sha256::{CircuitBuilderHashSha2, WitnessHashSha2};
use plonky2_sha256_u32::types::CircuitBuilderHash;

use super::recursion::recursive_proof;

pub const SHA256_BLOCK: usize = 512;

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
/// let (circuit_data, proof) = sha256_proof_u32::<F, C, D>(&input, &output).expect("Error proving sha256 hash");
/// ```
pub fn sha256_proof_u32<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
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

/// Verifies that two proofs for hashes are valid & aggregates them into one proof.
/// Concatenates hashes into one array, proves that a hash of the concatenation is equal to the third hash.
/// Aggregates two proofs: aggregation of first two hashes & proof of the third one, sets the third hash as public inputs.
/// All proving functions use u32 values.
/// # Arguments
///
/// * `pis_hash_1` - A first hash represented as an array of field elements as u32.
/// * `pis_hash_2` - A second hash represented as an array of field elements as u32.
/// * `final_hash` - A hash of concatenation of hashes as u8.
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
pub fn prove_sub_hashes_u32<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
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

    let final_hash_bytes = match final_hash {
        Some(final_hash) => final_hash.to_vec(),
        _ => borsh::to_vec(&hash(&msg))?,
    };

    let (hash_d, hash_p) = sha256_proof_u32(&msg, &final_hash_bytes)?;
    let (result_d, result_p) = recursive_proof(
        (&inner_data.common, &inner_data.verifier_only, &inner_proof),
        Some((&hash_d.common, &hash_d.verifier_only, &hash_p)),
        Some(&hash_p.public_inputs),
    )?;
    Ok((result_d, result_p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::{circuit_data, config::PoseidonGoldilocksConfig};
    use plonky2_field::types::Field;
    use rand::random;

    #[test]
    fn test_sha256_proof_u32_computation_with_public_inputs() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        const MSGLEN: usize = 1000;
        let msg: Vec<u8> = (0..MSGLEN).map(|_| random::<u8>() as u8).collect();
        let hash = hash(&msg);

        let (_data, _proof) = sha256_proof_u32::<F, C, D>(&msg, &hash.0)?;

        Ok(())
    }

    #[test]
    fn test_prove_sub_hashes_u32_aggregation_correctness() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        const MSGLEN: usize = 1000;
        let msg1: Vec<u8> = (0..MSGLEN).map(|_| random::<u8>() as u8).collect();
        let hash1 = hash(&msg1);
        let msg2: Vec<u8> = (0..MSGLEN).map(|_| random::<u8>() as u8).collect();
        let hash2 = hash(&msg2);
        let msg3 = [hash1.0, hash2.0].concat();
        let hash3 = hash(&msg3);

        let (d1, p1) = sha256_proof_u32::<F, C, D>(&msg1, &hash1.0)?;
        d1.verify(p1.clone())?;
        let (d2, p2) = sha256_proof_u32::<F, C, D>(&msg2, &hash2.0)?;
        d2.verify(p2.clone())?;
        let (d3, p3) = sha256_proof_u32::<F, C, D>(&msg3, &hash3.0)?;
        d3.verify(p3.clone())?;

        let (_data, _proof) = prove_sub_hashes_u32(
            true,
            true,
            &p1.public_inputs,
            &p2.public_inputs,
            Some(&hash3.0.to_vec()),
            (&d1.common, &d1.verifier_only, &p1),
            Some((&d2.common, &d2.verifier_only, &p2)),
        )?;

        Ok(())
    }
}

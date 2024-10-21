use anyhow::Result;
use near_primitives::borsh;
use near_primitives::hash::hash;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::Hasher;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;

use crate::prove_crypto::{
    recursion::recursive_proof,
    sha256::{prove_sub_hashes_u32, sha256_proof_u32},
};
use crate::types::*;

/// Proves the header hash for a given header data in u32 format.
///
/// This function generates proofs for the header hash bits using SHA-256 for the provided
/// header data.
///
/// # Arguments
///
/// * `header_hash` - A byte slice representing the header hash.
/// * `header_data` - The header data containing inner_lite, inner_rest, and prev_hash.
/// * `public_inputs` - Public inputs that are set optionally for this proof. If None, the block hash is set to PI.
///
/// # Returns
///
/// Returns a result containing the computed circuit data and the proof with public inputs.
///
pub fn prove_header_hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    header_hash: &[u8],
    header_data: HeaderData,
    public_inputs: Option<&[F]>,
    timing_tree: &mut TimingTree,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    // Prove hash for inner_lite data.
    let hash_lite = hash(&header_data.inner_lite);
    let hash_lite_bytes = borsh::to_vec(&hash_lite)?;
    let (d1, p1) = timed!(
        timing_tree,
        "prove inner_lite hash",
        sha256_proof_u32::<F, C, D>(&header_data.inner_lite, &hash_lite_bytes)?
    );
    // Prove hash for inner_rest data.
    let hash_rest = hash(&header_data.inner_rest);
    let hash_rest_bytes = borsh::to_vec(&hash_rest)?;
    let (d2, p2) = timed!(
        timing_tree,
        "prove inner_rest hash",
        sha256_proof_u32::<F, C, D>(&header_data.inner_rest, &hash_rest_bytes)?
    );
    // Verify proofs for inner_lite & inner_rest.
    // Concatenate them if both are valid and set hashes for inner_lite & inner_rest as PI.
    let (d3, p3) = timed!(
        timing_tree,
        "verify proofs for inner_lite & inner_rest, set hashes as PIs",
        prove_sub_hashes_u32::<F, C, D>(
            true,
            true,
            &p1.public_inputs,
            &p2.public_inputs,
            None,
            (&d1.common, &d1.verifier_only, &p1),
            Some((&d2.common, &d2.verifier_only, &p2)),
        )?
    );
    // Prove concatenation of inner_hash & prev_hash.
    let pis_hash_2: Vec<F> = header_data
        .prev_hash
        .iter()
        .map(|x| F::from_canonical_u8(*x))
        .collect();
    let (d4, p4) = timed!(
        timing_tree,
        "prove concatenation of inner_hash & prev_hash",
        prove_sub_hashes_u32::<F, C, D>(
            true,
            false,
            &p3.public_inputs,
            &pis_hash_2,
            Some(header_hash),
            (&d3.common, &d3.verifier_only, &p3),
            None,
        )?
    );
    d4.verify(p4.clone())?;
    // Verify (d4, p4) to set public_inputs as PI.
    if let Some(PI) = public_inputs {
        let (d5, p5) = timed!(
            timing_tree,
            "recursion to set specified public_inputs",
            recursive_proof::<F, C, C, D>(
                (&d4.common, &d4.verifier_only, &p4.clone()),
                None,
                Some(PI)
            )?
        );
        return Ok((d5, p5));
    }
    Ok((d4, p4))
}

/// Proves the correctness of a hash of validators list.
///
/// This function generates a proof to verify the correctness of a block producer hash (`bp_hash`)
/// based on the provided validators.
///
/// # Arguments
///
/// * `bp_hash` - A byte slice representing the block producer hash to be verified.
/// * `validators` - A vector containing byte slices representing the validators' data.
///
/// # Returns
///
/// Returns a result containing the computed circuit data and the proof with public inputs in format of u32
/// if the operation succeeds.
pub fn prove_bp_hash<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    bp_hash: &[u8],
    validators: Vec<Vec<u8>>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    let validators_len = u32::try_from(validators.len())?;
    let mut final_bytes: Vec<u8> = vec![];
    final_bytes.append(&mut validators_len.to_le_bytes().to_vec());
    let count = validators
        .iter()
        .map(|value| final_bytes.append(&mut (*value).to_vec()))
        .count();
    assert_eq!(count, validators.len());
    let (data, proof) = sha256_proof_u32::<F, C, D>(&final_bytes, bp_hash)?;
    Ok((data, proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{load_block_header, load_validators};
    use anyhow::Result;
    use async_nats::jetstream::stream::No;
    use log::info;
    use near_primitives::borsh::BorshSerialize;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use sha2::Digest;

    #[test]
    fn test_prove_header_hash_for_given_header_data() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let path = "../data/block_header_small.json".to_string();
        let (current_block_hash, current_block_header) = load_block_header(&path)?;
        let current_block_header_bytes = borsh::to_vec(&current_block_header)?;
        let current_block_header_hash_bytes = borsh::to_vec(&current_block_hash)?;

        let mut timing_tree = TimingTree::new("prove hash", Level::Info);

        let (_data, proof) = timed!(
            timing_tree,
            "prove hash of current block",
            prove_header_hash::<F, C, D>(
                &current_block_header_hash_bytes,
                HeaderData {
                    prev_hash: current_block_header_bytes[TYPE_BYTE..(TYPE_BYTE + PK_HASH_BYTES)]
                        .to_vec(),
                    inner_lite: current_block_header_bytes
                        [(TYPE_BYTE + PK_HASH_BYTES)..(TYPE_BYTE + PK_HASH_BYTES + INNER_LITE_BYTES)]
                        .to_vec(),
                    inner_rest:
                        current_block_header_bytes[(TYPE_BYTE + PK_HASH_BYTES + INNER_LITE_BYTES)
                            ..(current_block_header_bytes.len() - TYPE_BYTE - SIG_BYTES)]
                            .to_vec(),
                },
                None,
                &mut timing_tree
            )?
        );
        info!("Block hash proof size: {} bytes", proof.to_bytes().len());
        Ok(())
    }

    #[test]
    fn test_prove_block_prove_correctness_of_block_producer_hash() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let path = "../data/validators_ordered_small.json".to_string();
        let validators = load_validators(&path)?;
        let validators_bytes: Vec<Vec<u8>> = validators
            .iter()
            .map(|value| borsh::to_vec(value).unwrap())
            .collect();
        let path = "../data/prev_epoch_block_header_small.json".to_string();
        let (_, prev_epoch_block_header) = load_block_header(&path)?;
        let prev_epoch_block_header_bytes = borsh::to_vec(&prev_epoch_block_header)?;

        let bp_hash = prev_epoch_block_header_bytes[(TYPE_BYTE + PK_HASH_BYTES + INNER_LITE_BYTES
            - PK_HASH_BYTES
            - PK_HASH_BYTES)
            ..(TYPE_BYTE + PK_HASH_BYTES + INNER_LITE_BYTES - PK_HASH_BYTES)]
            .to_vec();

        let mut timing_tree = TimingTree::new("prove bp hash", Level::Info);

        // prove next_bp_hash
        let (_data, proof) = timed!(
            timing_tree,
            "prove next bp hash",
            prove_bp_hash::<F, C, D>(&bp_hash, validators_bytes)?
        );
        info!("Bp_hash proof size: {} bytes", proof.to_bytes().len());
        Ok(())
    }
}

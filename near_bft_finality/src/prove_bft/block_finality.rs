use crate::prove_block_data::header_bphash::*;
use crate::prove_block_data::keys_stakes::prove_valid_keys_stakes_in_valiators_list;
use crate::prove_block_data::primitives::{prove_consecutive_heights, prove_eq_array};
use crate::prove_block_data::signatures::{prove_approvals, prove_approvals_with_client};
use crate::prove_crypto::recursion::recursive_proof;
use crate::types::*;
use anyhow::{Ok, Result};
use core::panic;
use log::info;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::{CircuitData, CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;

/// Proves consecutive heights for three or four proofs.
/// # Arguments
///
/// * `proofs` - A set of proof for block headers.
///
/// # Returns
///
/// Returns a result containing the computed circuit data and the proof with public inputs.
/// - `CircuitData<F, C, D>`: The circuit data generated during the proof generation process.
/// - `ProofWithPublicInputs<F, C, D>`: The proof.
///
pub fn prove_consecutive_heights_proofs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    proofs: Vec<(
        CommonCircuitData<F, D>,
        VerifierOnlyCircuitData<C, D>,
        ProofWithPublicInputs<F, C, D>,
    )>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    assert!(proofs.len() >= 3);
    let h1_bytes: Vec<u8> = proofs[0].2.public_inputs[32..40]
        .iter()
        .map(|x| x.to_canonical_u64() as u8)
        .collect();
    let h2_bytes: Vec<u8> = proofs[1].2.public_inputs[32..40]
        .iter()
        .map(|x| x.to_canonical_u64() as u8)
        .collect();
    let h3_bytes: Vec<u8> = proofs[2].2.public_inputs[32..40]
        .iter()
        .map(|x| x.to_canonical_u64() as u8)
        .collect();
    let (data1, proof1) = prove_consecutive_heights::<F, C, D>(&h1_bytes, &h2_bytes)?;
    let (data2, proof2) = prove_consecutive_heights::<F, C, D>(&h2_bytes, &h3_bytes)?;
    let (mut agg_d, mut agg_p) = recursive_proof::<F, C, C, D>(
        (&data1.common, &data1.verifier_only, &proof1),
        Some((&data2.common, &data2.verifier_only, &proof2)),
        None,
    )?;
    if proofs.len() == 4 {
        let h4_bytes: Vec<u8> = proofs[3].2.public_inputs[32..40]
            .iter()
            .map(|x| x.to_canonical_u64() as u8)
            .collect();
        let (data3, proof3) = prove_consecutive_heights::<F, C, D>(&h3_bytes, &h4_bytes)?;
        (agg_d, agg_p) = recursive_proof::<F, C, C, D>(
            (&agg_d.common, &agg_d.verifier_only, &agg_p),
            Some((&data3.common, &data3.verifier_only, &proof3)),
            None,
        )?;
    }
    Ok((agg_d, agg_p))
}

/// Prove block header.
///
/// This function generates proofs for the header hash using SHA-256 for the provided
/// header data and sets hash, prev_hash, last_ds_final_block, last_final_block and bp_hash as public inputs.
///
/// # Arguments
///
/// * `hash_bytes` - A byte slice representing the header hash.
/// * `block_bytes` - The header data containing inner_lite, inner_rest, and prev_hash.
/// * `prev_hash_bytes` - A byte slice representing the field prev_hash of the block.
/// * `last_ds_final_hash_bytes` - A byte slice representing the field last_ds_final_hash_bytes of the block.
/// * `last_final_hash_bytes` - A byte slice representing the field last_final_hash_bytes of the block.
/// * `bp_hash_bytes` - A byte slice representing the field bp_hash_bytes of the block.
///
/// # Returns
///
/// Returns a result containing the computed circuit data and the proof with public inputs.
///
pub fn prove_block_header<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    hash_bytes: &[u8],
    block_bytes: &[u8],
    height: Option<u64>,
    epoch_id_bytes: Option<Vec<u8>>,
    prev_hash_bytes: Option<Vec<u8>>,
    last_ds_final_hash_bytes: Option<Vec<u8>>,
    last_final_hash_bytes: Option<Vec<u8>>,
    bp_hash_bytes: Option<Vec<u8>>,
    next_epoch_id_bytes: Option<Vec<u8>>,
    timing_tree: &mut TimingTree,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    // Prepare public inputs.
    let mut public_inputs = hash_bytes.to_vec();
    // Add height.
    if let Some(height) = height {
        let height_bytes = height.to_le_bytes();
        public_inputs.append(&mut height_bytes.to_vec());
    }
    // Add epoch_id.
    if let Some(mut epoch_id) = epoch_id_bytes {
        public_inputs.append(&mut epoch_id);
    }
    // Add previous hash.
    if let Some(mut prev_hash) = prev_hash_bytes {
        public_inputs.append(&mut prev_hash);
    }
    // Add last_ds_final_hash_bytes.
    if let Some(mut last_ds_final_hash) = last_ds_final_hash_bytes {
        public_inputs.append(&mut last_ds_final_hash);
    }
    // Add last_final_hash_bytes.
    if let Some(mut last_final_hash) = last_final_hash_bytes {
        public_inputs.append(&mut last_final_hash);
    }
    // Add bp_hash_bytes.
    if let Some(mut bp_hash) = bp_hash_bytes {
        // If bp_hash_bytes, then no prev_hash_bytes, last_ds_final_hash_bytes, last_final_hash_bytes.
        assert!(public_inputs.len() == 32);
        public_inputs.append(&mut bp_hash);
        // Add next_epoch_id_bytes.
        if let Some(mut next_epoch_id) = next_epoch_id_bytes {
            public_inputs.append(&mut next_epoch_id);
        }
    }
    let public_inputs_f: Vec<F> = public_inputs
        .iter()
        .map(|x| F::from_canonical_u8(*x))
        .collect();
    // Prove current_block hash.
    let (header_hash_data, header_hash_proof) = timed!(
        timing_tree,
        "prove hash of current block",
        prove_header_hash::<F, C, D>(
            &hash_bytes,
            HeaderData {
                prev_hash: block_bytes[TYPE_BYTE..(TYPE_BYTE + PK_HASH_BYTES)].to_vec(),
                inner_lite: block_bytes
                    [(TYPE_BYTE + PK_HASH_BYTES)..(TYPE_BYTE + PK_HASH_BYTES + INNER_LITE_BYTES)]
                    .to_vec(),
                inner_rest: block_bytes[(TYPE_BYTE + PK_HASH_BYTES + INNER_LITE_BYTES)
                    ..(block_bytes.len() - TYPE_BYTE - SIG_BYTES)]
                    .to_vec(),
            },
            Some(&public_inputs_f),
            timing_tree
        )?
    );
    info!(
        "Block hash proof size: {} bytes",
        header_hash_proof.to_bytes().len()
    );
    Ok((header_hash_data, header_hash_proof))
}

/// Prove finality (both Doomslug and BFT) of the block.
///
/// This function generates proofs of computational integrity of block data to prove its finality.
///
/// # Arguments
///
/// * `current_block_header_proof` - A proof for header for the current block.
/// * `msg_to_sign` - The data that was signed by validators. It is used when proving signatues.
/// * `next_block_approvals_bytes` - A list of signatures for the current block that is extracted from the next block.
/// * `validators` - A list of validators that contains public keys & stakes.
/// * `proofs` - A set of proofs that is used to ensure Doomslug/BFT finality.
///              It should contain proofs in the following order: [Proof_Block_n-1(Epochi-2), Proof_Block_0(Epochi-1), Proof_Block_i+1(Epochi), Proof_Block_i+2(Epochi)]
///              Max length is 4 to prove BFT finality, or 3 to prove Doomslug finality.
/// * `consecutive_heights` - A proof for consecutive heights for blocks Bi+2, Bi+1, Bi (or B0 & Bn-1) generated optionally.
///
/// # Returns
///
/// Returns a result containing the computed circuit data and the proof with public inputs.
///
pub fn prove_block_finality<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    current_block_header_proof: (
        &CommonCircuitData<F, D>,
        &VerifierOnlyCircuitData<C, D>,
        &ProofWithPublicInputs<F, C, D>,
    ),
    msg_to_sign: Option<Vec<u8>>,
    next_block_approvals_bytes: Option<Vec<Vec<u8>>>,
    validators: Option<Vec<Vec<u8>>>,
    proofs: Vec<(
        CommonCircuitData<F, D>,
        VerifierOnlyCircuitData<C, D>,
        ProofWithPublicInputs<F, C, D>,
    )>,
    consecutive_heights: Option<(
        CommonCircuitData<F, D>,
        VerifierOnlyCircuitData<C, D>,
        ProofWithPublicInputs<F, C, D>,
    )>,
    client: Option<nats::Connection>,
    timing_tree: &mut TimingTree,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    // Aggregation of the obtained proofs.
    let mut aggregation: Option<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> = None;
    // Current block hash extracted from PI of the proof.
    let current_block_hash_bytes: Vec<u8> = current_block_header_proof.2.public_inputs[0..32]
        .iter()
        .map(|x| x.to_canonical_u64() as u8)
        .collect();
    // Current block epoch_id extracted from PI of the proof.
    let current_block_epoch_id_bytes: Vec<u8> = current_block_header_proof.2.public_inputs[40..72]
        .iter()
        .map(|x| x.to_canonical_u64() as u8)
        .collect();
    // Prove current_block signatures. Prove keys & stakes.
    aggregation = match msg_to_sign {
        Some(msg) => {
            let approvals = next_block_approvals_bytes.expect("List of signatures is empty.");
            let validators = validators.clone().expect("List of validators is empty.");
            // Prove sig-s.
            let ((cb_sig_data, cb_sig_proof), valid_keys) = match client {
                None => {
                    timed!(
                        timing_tree,
                        "prove signatures",
                        prove_approvals::<F, C, D>(&msg, approvals, validators.clone())?
                    )
                }
                Some(client_connection) => {
                    timed!(
                        timing_tree,
                        "prove signatures using nats client",
                        prove_approvals_with_client::<F, C, D>(
                            &msg,
                            approvals,
                            validators.clone(),
                            client_connection
                        )?
                    )
                }
            };
            info!(
                "Size of proof for aggregated signatures: {} bytes",
                cb_sig_proof.to_bytes().len()
            );
            let valid_keys_hash: Vec<u8> = cb_sig_proof
                .public_inputs
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            // Prove keys used to verify valid signatures.
            // Prove 2/3 of stakes.
            let (cb_keys_23stakes_data, cb_keys_23stakes_proof) = timed!(
                timing_tree,
                "prove keys used to verify valid signatures",
                prove_valid_keys_stakes_in_valiators_list::<F, C, D>(
                    valid_keys.clone(),
                    valid_keys_hash,
                    validators.clone(),
                )?
            );
            info!(
                "Size of proof for aggregated keys: {} bytes",
                cb_keys_23stakes_proof.to_bytes().len()
            );
            // Aggregate proofs & set list of valid keys and sum as PI.
            let (agg_data, agg_proof) = timed!(
                timing_tree,
                "aggregate signatures and valid keys proof",
                recursive_proof::<F, C, C, D>(
                    (
                        &cb_sig_data.common,
                        &cb_sig_data.verifier_only,
                        &cb_sig_proof,
                    ),
                    Some((
                        &cb_keys_23stakes_data.common,
                        &cb_keys_23stakes_data.verifier_only,
                        &cb_keys_23stakes_proof,
                    )),
                    Some(&cb_keys_23stakes_proof.public_inputs),
                )?
            );
            Some((agg_data, agg_proof))
        }
        None => None,
    };
    assert!(proofs.len() >= 3);
    assert!(proofs.len() <= 4);
    // Check epoch proofs: B_n-1 (Epoch_i-2) & B_0 (Epoch_i-1).
    let (agg_data, agg_proof) = {
        // Verify proof of Block_n-1(Epoch_i-2). This proof stores the hash of the block (PI are 32 bytes).
        let epoch_hash: Vec<u8> = proofs[0].2.public_inputs[0..32]
            .iter()
            .map(|x| x.to_canonical_u64() as u8)
            .collect();
        // Prove epoch_id.
        let (epoch_id_data, epoch_id_proof) = timed!(
            timing_tree,
            "prove epoch_id",
            prove_eq_array::<F, C, D>(&current_block_epoch_id_bytes, &epoch_hash)?
        );
        info!(
            "Epoch_id proof size: {} bytes",
            epoch_id_proof.to_bytes().len()
        );
        let (block_n_1_data, block_n_1_proof) = timed!(
            timing_tree,
            "verify proof of Block_n-1(Epochi-2)",
            recursive_proof::<F, C, C, D>(
                (&proofs[0].0, &proofs[0].1, &proofs[0].2,),
                Some((
                    &epoch_id_data.common,
                    &epoch_id_data.verifier_only,
                    &epoch_id_proof
                )),
                Some(&proofs[0].2.public_inputs[0..32]),
            )?
        );
        // Verify Block_0(Epochi-1). Prove bp_hash optionally.
        let (block_0_data, block_0_proof) = match validators {
            Some(validators) => {
                // This proof stores its hash (32 bytes) & bp_hash (32 bytes), next_epoch_id (32 bytes).
                let next_bp_hash: Vec<u8> = proofs[1].2.public_inputs[32..64]
                    .iter()
                    .map(|x| x.to_canonical_u64() as u8)
                    .collect();
                let (bp_d, bp_p) = timed!(
                    timing_tree,
                    "prove next_bp_hash",
                    prove_bp_hash::<F, C, D>(&next_bp_hash, validators)?
                );
                info!("Bp_hash proof size: {} bytes", bp_p.to_bytes().len());
                timed!(
                    timing_tree,
                    "verify proof of Block_0(Epochi-1)",
                    recursive_proof::<F, C, C, D>(
                        (&proofs[1].0, &proofs[1].1, &proofs[1].2,),
                        Some((&bp_d.common, &bp_d.verifier_only, &bp_p)),
                        Some(&proofs[1].2.public_inputs[0..32]),
                    )?
                )
            }
            None => {
                timed!(
                    timing_tree,
                    "verify proof of Block_0(Epochi-1)",
                    recursive_proof::<F, C, C, D>(
                        (&proofs[1].0, &proofs[1].1, &proofs[1].2,),
                        None,
                        Some(&proofs[1].2.public_inputs[0..32]),
                    )?
                )
            }
        };
        // Aggregate obtained proofs.
        timed!(
            timing_tree,
            "aggregate proofs: Block_n-1(Epochi-1) & Block_0(Epochi-1)",
            recursive_proof::<F, C, C, D>(
                (
                    &block_n_1_data.common,
                    &block_n_1_data.verifier_only,
                    &block_n_1_proof.clone()
                ),
                Some((
                    &block_0_data.common,
                    &block_0_data.verifier_only,
                    &block_0_proof.clone()
                )),
                Some(&[block_n_1_proof.public_inputs, block_0_proof.public_inputs].concat()),
            )?
        )
    };
    // Aggregate proofs for Bn-1/B0 and signatures.
    // Make an aggregation of proofs: Block_n-1(Epochi-1) & Block_0(Epochi-1) as the initial one, otherwise.
    aggregation = match aggregation {
        Some((agg_sig_data, agg_sig_proof)) => {
            // Aggregate obtained proofs.
            let (agg_d, agg_p) = timed!(
                timing_tree,
                "aggregate proofs: Block_n-1(Epochi-1) & Block_0(Epochi-1)",
                recursive_proof::<F, C, C, D>(
                    (
                        &agg_sig_data.common,
                        &agg_sig_data.verifier_only,
                        &agg_sig_proof
                    ),
                    Some((&agg_data.common, &agg_data.verifier_only, &agg_proof)),
                    Some(&agg_proof.public_inputs),
                )?
            );
            Some((agg_d, agg_p))
        }
        None => Some((agg_data, agg_proof.clone())),
    };
    // Prove block finality.
    aggregation = match proofs.len() {
        // Prove Doomslug finality.
        3 => {
            // This proof stores its hash (32 bytes), height (8 bytes), epoch_id (32 bytes),
            // prev_hash (32 bytes), last_ds_final_hash_bytes (32 bytes) & last_final_hash_bytes (32 bytes).
            let prev_hash: Vec<u8> = proofs[2].2.public_inputs[72..104]
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            let (prev_hash_data, prev_hash_proof) = timed!(
                timing_tree,
                "prove prev_hash",
                prove_eq_array::<F, C, D>(&prev_hash, &current_block_hash_bytes)?
            );
            info!(
                "Prev_hash proof size (Doomslug): {} bytes",
                prev_hash_proof.to_bytes().len()
            );
            // If true, prove last_ds_final_hash_bytes & aggreagte with consecutive_heights.
            let (inner_data, inner_proof) = match consecutive_heights.clone() {
                Some(consecutive_heights) => {
                    let len = proofs[2].2.public_inputs.len();
                    let ds_hash: Vec<u8> = proofs[2].2.public_inputs[(len - 64)..(len - 32)]
                        .iter()
                        .map(|x| x.to_canonical_u64() as u8)
                        .collect();
                    let (ds_data, ds_proof) = timed!(
                        timing_tree,
                        "prove last_ds_final_hash_bytes",
                        prove_eq_array::<F, C, D>(&ds_hash, &current_block_hash_bytes)?
                    );
                    info!(
                        "Last_ds_final_hash_bytes proof size: {} bytes",
                        ds_proof.to_bytes().len()
                    );
                    let (rec_data, rec_proof) = timed!(
                        timing_tree,
                        "aggregate ds & consecutive_heights",
                        recursive_proof::<F, C, C, D>(
                            (&ds_data.common, &ds_data.verifier_only, &ds_proof),
                            Some((
                                &consecutive_heights.0,
                                &consecutive_heights.1,
                                &consecutive_heights.2
                            )),
                            None,
                        )?
                    );
                    timed!(
                        timing_tree,
                        "aggregate prev_hash & ds",
                        recursive_proof::<F, C, C, D>(
                            (
                                &prev_hash_data.common,
                                &prev_hash_data.verifier_only,
                                &prev_hash_proof
                            ),
                            Some((&rec_data.common, &rec_data.verifier_only, &rec_proof)),
                            None,
                        )?
                    )
                }
                None => {
                    timed!(
                        timing_tree,
                        "aggregate prev_hash & ds",
                        recursive_proof::<F, C, C, D>(
                            (
                                &prev_hash_data.common,
                                &prev_hash_data.verifier_only,
                                &prev_hash_proof
                            ),
                            None,
                            None,
                        )?
                    )
                }
            };
            // Aggregate obtained proofs.
            let (block_i_1_data, block_i_1_proof) = timed!(
                timing_tree,
                "verify proof of Block_i+1(Epochi)",
                recursive_proof::<F, C, C, D>(
                    (&proofs[2].0, &proofs[2].1, &proofs[2].2,),
                    Some((&inner_data.common, &inner_data.verifier_only, &inner_proof)),
                    None,
                )?
            );
            // Aggregate with other proofs.
            let (agg_data, agg_proof) = timed!(
                timing_tree,
                "aggreagtion",
                recursive_proof::<F, C, C, D>(
                    (
                        &aggregation.clone().expect("No common data.").0.common,
                        &aggregation
                            .clone()
                            .expect("No verifier data.")
                            .0
                            .verifier_only,
                        &aggregation.clone().expect("No proof.").1,
                    ),
                    Some((
                        &block_i_1_data.common,
                        &block_i_1_data.verifier_only,
                        &block_i_1_proof
                    )),
                    Some(&aggregation.clone().expect("No proof.").1.public_inputs),
                )?
            );
            Some((agg_data, agg_proof))
        }
        // Prove BFT finality.
        4 => {
            // Prove Doomslug finality with Block_i+1.
            // This proof stores its hash (32 bytes), height (8 bytes), epoch_id (32 bytes),
            // prev_hash (32 bytes), last_ds_final_hash_bytes (32 bytes).
            let prev_hash: Vec<u8> = proofs[2].2.public_inputs[72..104]
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            let (prev_hash_data, prev_hash_proof) = timed!(
                timing_tree,
                "prove prev_hash",
                prove_eq_array::<F, C, D>(&prev_hash, &current_block_hash_bytes)?
            );
            info!(
                "Prev_hash proof size (Doomslug): {} bytes",
                prev_hash_proof.to_bytes().len()
            );
            // If true, prove last_ds_final_hash_bytes & aggreagte with consecutive_heights.
            // Aggregate obtained proofs.
            let (inner_data, inner_proof) = match consecutive_heights.clone() {
                Some(consecutive_heights) => {
                    let len = proofs[2].2.public_inputs.len();
                    let ds_hash: Vec<u8> = proofs[2].2.public_inputs[(len - 64)..(len - 32)]
                        .iter()
                        .map(|x| x.to_canonical_u64() as u8)
                        .collect();
                    let (ds_data, ds_proof) = timed!(
                        timing_tree,
                        "prove last_ds_final_hash_bytes",
                        prove_eq_array::<F, C, D>(&ds_hash, &current_block_hash_bytes)?
                    );
                    info!(
                        "Last_ds_final_hash_bytes proof size: {} bytes",
                        ds_proof.to_bytes().len()
                    );
                    let (rec_data, rec_proof) = timed!(
                        timing_tree,
                        "aggregate ds & consecutive_heights",
                        recursive_proof::<F, C, C, D>(
                            (&ds_data.common, &ds_data.verifier_only, &ds_proof),
                            Some((
                                &consecutive_heights.0,
                                &consecutive_heights.1,
                                &consecutive_heights.2
                            )),
                            None,
                        )?
                    );
                    timed!(
                        timing_tree,
                        "aggregate prev_hash & ds",
                        recursive_proof::<F, C, C, D>(
                            (
                                &prev_hash_data.common,
                                &prev_hash_data.verifier_only,
                                &prev_hash_proof
                            ),
                            Some((&rec_data.common, &rec_data.verifier_only, &rec_proof)),
                            None,
                        )?
                    )
                }
                None => {
                    timed!(
                        timing_tree,
                        "aggregate prev_hash & ds",
                        recursive_proof::<F, C, C, D>(
                            (
                                &prev_hash_data.common,
                                &prev_hash_data.verifier_only,
                                &prev_hash_proof
                            ),
                            None,
                            None,
                        )?
                    )
                }
            };
            // Aggregate obtained proofs.
            let (block_i_1_data, block_i_1_proof) = timed!(
                timing_tree,
                "verify proof of Block_i+1(Epochi)",
                recursive_proof::<F, C, C, D>(
                    (&proofs[2].0, &proofs[2].1, &proofs[2].2,),
                    Some((&inner_data.common, &inner_data.verifier_only, &inner_proof)),
                    None,
                )?
            );
            // Prove BFT finality with Block_i+2.
            // This proof stores its hash (32 bytes), height (8 bytes), prev_hash (32 bytes),
            // epoch_id (32 bytes), last_ds_final_hash_bytes (32 bytes) and last_final_hash_bytes (32 bytes).
            // If true, prove last_final_hash_bytes.
            // Aggregate obtained proofs.
            let (block_i_2_data, block_i_2_proof) = match consecutive_heights.clone() {
                Some(_) => {
                    let len = proofs[3].2.public_inputs.len();
                    let bft: Vec<u8> = proofs[3].2.public_inputs[(len - 32)..]
                        .iter()
                        .map(|x| x.to_canonical_u64() as u8)
                        .collect();
                    let (bft_data, bft_proof) = timed!(
                        timing_tree,
                        "prove Last_final_hash_bytes",
                        prove_eq_array::<F, C, D>(&bft, &current_block_hash_bytes)?
                    );
                    info!(
                        "Last_final_hash_bytes proof size: {} bytes",
                        bft_proof.to_bytes().len()
                    );
                    timed!(
                        timing_tree,
                        "verify proof of Block_i+2(Epochi)",
                        recursive_proof::<F, C, C, D>(
                            (&proofs[3].0, &proofs[3].1, &proofs[3].2,),
                            Some((&bft_data.common, &bft_data.verifier_only, &bft_proof)),
                            None,
                        )?
                    )
                }
                None => {
                    timed!(
                        timing_tree,
                        "verify proof of Block_i+2(Epochi)",
                        recursive_proof::<F, C, C, D>(
                            (&proofs[3].0, &proofs[3].1, &proofs[3].2,),
                            None,
                            None,
                        )?
                    )
                }
            };
            // Aggregate proofs for Block_i+1(Epochi) & Block_i+2(Epochi).
            let (agg_data, agg_proof) = timed!(
                timing_tree,
                "aggregate proofs: Block_i+1(Epochi) & Block_i+2(Epochi)",
                recursive_proof::<F, C, C, D>(
                    (
                        &block_i_1_data.common,
                        &block_i_1_data.verifier_only,
                        &block_i_1_proof,
                    ),
                    Some((
                        &block_i_2_data.common,
                        &block_i_2_data.verifier_only,
                        &block_i_2_proof
                    )),
                    None,
                )?
            );
            // Aggregate with other proofs.
            let (agg_data, agg_proof) = timed!(
                timing_tree,
                "aggreagtion",
                recursive_proof::<F, C, C, D>(
                    (
                        &aggregation.clone().expect("No common data.").0.common,
                        &aggregation
                            .clone()
                            .expect("No verifier data.")
                            .0
                            .verifier_only,
                        &aggregation.clone().expect("No proof.").1,
                    ),
                    Some((&agg_data.common, &agg_data.verifier_only, &agg_proof)),
                    Some(&aggregation.clone().expect("No proof.").1.public_inputs),
                )?
            );
            Some((agg_data, agg_proof))
        }
        _ => {
            panic!("Invalid proofs.len() {}", proofs.len());
        }
    };
    // Aggregate PI of the proofs for the header of the current block and blocks Bn-1 & B0.
    let mut public_inputs = current_block_header_proof.2.public_inputs.clone();
    public_inputs.append(&mut aggregation.clone().expect("No proof.").1.public_inputs);
    aggregation = {
        Some(timed!(
            timing_tree,
            "aggreagtion with proof for header",
            recursive_proof::<F, C, C, D>(
                (
                    &aggregation.clone().expect("No common data.").0.common,
                    &aggregation
                        .clone()
                        .expect("No verifier data.")
                        .0
                        .verifier_only,
                    &aggregation.clone().expect("No proof.").1,
                ),
                Some(current_block_header_proof),
                Some(&public_inputs),
            )?
        ))
    };
    Ok((
        aggregation.clone().expect("No circuit data.").0,
        aggregation.clone().expect("No proof.").1,
    ))
}

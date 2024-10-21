use crate::prove_bft::block_finality::*;
use crate::prove_block_data::{signatures::generate_signed_message, primitives::prove_eq_array};
use crate::prove_crypto::recursion::recursive_proof;
use crate::types::*;
use anyhow::Result;
use near_primitives::hash::CryptoHash;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::Hasher;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;

/// Prove BFT finality of the block. The function may be used for both epoch & randomly selected blocks.
///
/// # Arguments
///
/// * `ep2_last_block_bytes` - The header data of Block_n-1(Epochi-2) containing inner_lite, inner_rest, and prev_hash.
/// * `ep2_last_block_hash_bytes` - A byte slice representing the header hash.
/// * `ep1_first_block_bytes` - The header data of Block_0(Epochi-1) containing inner_lite, inner_rest, and prev_hash.
/// * `ep1_first_block_hash_bytes` - A byte slice representing the header hash.
/// * `ep3_last_block_bytes` - The header data of Block_n-1(Epochi-3) containing inner_lite, inner_rest, and prev_hash.
/// * `ep3_last_block_hash_bytes` - A byte slice representing the header hash.
/// * `blocks` - A set of blocks udes to prove BFT finality.
///              It is in the following form: [Block_i+4, Block_i+3, Block_i+2, Block_i+1, Block_i], when proving randomly secected blocks.
///              It is in the following form: [Block_4, Block_3, Block_2, Block_1, Block_0, Block_n-1], when proving epoch blocks.
/// * `validators` - A list of validators that contains public keys & stakes for Epochi.
/// * `validators_n_1` - A list of validators that contains public keys & stakes for Epochi-1.
///
/// # Returns
///
/// Returns a result containing:
/// * one proof when proving ramdomly selected block.
/// * two proofs when proving epoch blocks Block_0 & Block_n-1.
///
pub fn prove_block_bft<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    // Block_n-1(Epochi-2) from RPC.
    ep2_last_block_bytes: &[u8],
    // Extracted from contract.
    ep2_last_block_hash_bytes: &[u8],
    // Block_0(Epochi-1) from RPC.
    ep1_first_block_bytes: &[u8],
    // Extracted from contract.
    ep1_first_block_hash_bytes: &[u8],
    // Block_n-1(Epochi-3) from RPC. To prove Block_n-1 when proving epoch blocks.
    ep3_last_block_bytes: Option<Vec<u8>>,
    // Extracted from contract.
    ep3_last_block_hash_bytes: Option<Vec<u8>>,
    // Blocks_i...i+4 representing some block data used to prove block finality & CI of a block.
    blocks: Vec<(HeaderDataFields, Vec<u8>)>,
    validators: Option<Vec<Vec<u8>>>,
    // List of validators for Block_n-1 (when proving epoch blocks).
    validators_n_1: Option<Vec<Vec<u8>>>,
    client: Option<nats::Connection>,
    timing_tree: &mut TimingTree,
) -> Result<(
    (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>),
    Option<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>,
)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    // Prove Block_n-1(Epochi-2). Set its hash & bp_hash as PI. 
    // Hash is used to prove epoch_id of the current block.
    // If this function proves epoch blocks {Bn-1, B0}, then this proof proves epoch_id for B0 and bp_hash (list of validators) for Bn-1.
    let (ep2_lb_data, ep2_lb_proof) = prove_block_header::<F, C, D>(
        ep2_last_block_hash_bytes,
        ep2_last_block_bytes,
        None,
        None,
        None,
        None,
        None,
        Some(
            ep2_last_block_bytes[(TYPE_BYTE + PK_HASH_BYTES + INNER_LITE_BYTES
                - PK_HASH_BYTES
                - PK_HASH_BYTES)
                ..(TYPE_BYTE + PK_HASH_BYTES + INNER_LITE_BYTES - PK_HASH_BYTES)]
                .to_vec(),
        ),
        None,
        timing_tree,
    )?;
    // Prove Block_0(Epochi-1). Set its hash & bp_hash as PI. 
    // Its bp_hash tehe list of validators for Bi or B0, if this function proves epoch blocks {Bn-1, B0}.
    let (mut ep1_fb_data, mut ep1_fb_proof) = prove_block_header::<F, C, D>(
        ep1_first_block_hash_bytes,
        ep1_first_block_bytes,
        None,
        None,
        None,
        None,
        None,
        Some(
            ep1_first_block_bytes[(TYPE_BYTE + PK_HASH_BYTES + INNER_LITE_BYTES
                - PK_HASH_BYTES
                - PK_HASH_BYTES)
                ..(TYPE_BYTE + PK_HASH_BYTES + INNER_LITE_BYTES - PK_HASH_BYTES)]
                .to_vec(),
        ),
	Some(
            ep1_first_block_bytes[(TYPE_BYTE + PK_HASH_BYTES + BLOCK_HEIGHT_BYTES + PK_HASH_BYTES)
                ..(TYPE_BYTE + PK_HASH_BYTES + BLOCK_HEIGHT_BYTES + PK_HASH_BYTES + PK_HASH_BYTES)]
                .to_vec(),
        ),
        timing_tree,
    )?;
    // Prove next_epoch_id of Block_0(Epochi-1) and hash of Block_n-1(Epochi-2).
    let ep2_lb_hash: Vec<u8> = ep2_lb_proof.public_inputs[0..32]
        .iter()
        .map(|x| x.to_canonical_u64() as u8)
        .collect();
    let ep1_fb_neph_bytes: Vec<u8> = ep1_fb_proof.public_inputs[(ep1_fb_proof.public_inputs.len() - 32)..]
	.iter()
        .map(|x| x.to_canonical_u64() as u8)
        .collect();
    let ep1_fb_neph = CryptoHash(ep1_fb_neph_bytes.clone().try_into().unwrap());
    let (neph_data, neph_proof) = timed!(
        timing_tree,
        "prove next_epoch_id",
        prove_eq_array::<F, C, D>(&ep2_lb_hash, &ep1_fb_neph_bytes)?
    );
    (ep1_fb_data, ep1_fb_proof) = timed!(
        timing_tree,
        "verify proof of Block_n-1(Epochi-2)",
        recursive_proof::<F, C, C, D>(
            (&ep1_fb_data.common, &ep1_fb_data.verifier_only, &ep1_fb_proof),
            Some((
                &neph_data.common,
                &neph_data.verifier_only,
                &neph_proof
            )),
            Some(&ep1_fb_proof.public_inputs),
        )?
    );
    
    assert!(blocks.len() > 0);
    // Prove Block_i+4.
    let (b4_data, b4_proof) = prove_block_header::<F, C, D>(
        &blocks[0].0.hash,
        &blocks[0].1,
        blocks[0].0.height.clone(),
        blocks[0].0.epoch_id.clone(),
        blocks[0].0.prev_hash.clone(),
        None,
        None,
        None,
        None,
        timing_tree,
    )?;
    // Prove Block_i+3.
    let (b3_data, b3_proof) = prove_block_header::<F, C, D>(
        &blocks[1].0.hash,
        &blocks[1].1,
        blocks[1].0.height.clone(),
        blocks[1].0.epoch_id.clone(),
        blocks[1].0.prev_hash.clone(),
        None,
        None,
        None,
        None,
        timing_tree,
    )?;
    // Prove Block_i+2.
    let (mut b2_data, mut b2_proof) = prove_block_header::<F, C, D>(
        &blocks[2].0.hash,
        &blocks[2].1,
        blocks[2].0.height.clone(),
        blocks[2].0.epoch_id.clone(),
        blocks[2].0.prev_hash.clone(),
        blocks[2].0.last_ds_final_hash.clone(),
        blocks[2].0.last_final_hash.clone(),
        None,
        None,
        timing_tree,
    )?;
    // Prove consecutive heights for Block_i+2, Block_i+3, Block_i+4.
    let (ch_data, ch_proof) = prove_consecutive_heights_proofs::<F, C, D>([
        (b4_data.common, b4_data.verifier_only, b4_proof),
        (b3_data.common, b3_data.verifier_only, b3_proof),
        (b2_data.common.clone(), b2_data.verifier_only.clone(), b2_proof.clone()),
    ].to_vec())?;
    // Aggregate proofs for heights & Bi+2.
    (b2_data, b2_proof) = recursive_proof::<F, C, C, D>(
        (&b2_data.common, &b2_data.verifier_only, &b2_proof),
        Some((&ch_data.common, &ch_data.verifier_only, &ch_proof)),
        Some(&b2_proof.public_inputs),
    )?;
    // Prove header for Block_i+1.
    let (b1_data, b1_proof) = prove_block_header::<F, C, D>(
        &blocks[3].0.hash,
        &blocks[3].1,
        blocks[3].0.height.clone(),
        blocks[3].0.epoch_id.clone(),
        blocks[3].0.prev_hash.clone(),
        blocks[3].0.last_ds_final_hash.clone(),
        blocks[3].0.last_final_hash.clone(),
        None,
        None,
        timing_tree,
    )?;
    // Prove header(s) for Block_i/{Block_0 & Block_n-1} to check their heights before proving their finality.
    let ((bi0_header_data, bi0_header_proof), bn_1_header_data_proof) = match blocks.len() {
        // Prove ramdomly selected block.
        5 => {
            let (bi_header_data, bi_header_proof) = prove_block_header::<F, C, D>(
                &blocks[4].0.hash,
                &blocks[4].1,
                blocks[4].0.height.clone(),
                blocks[4].0.epoch_id.clone(),
                None,
                None,
                None,
                None,
                None,
                timing_tree,
            )?;
            ((bi_header_data, bi_header_proof), None)
        }
        // Prove epoch blocks.
        6 => {
            let (b0_header_data, b0_header_proof) = prove_block_header::<F, C, D>(
                &blocks[4].0.hash,
                &blocks[4].1,
                blocks[4].0.height.clone(),
                blocks[4].0.epoch_id.clone(),
                blocks[4].0.prev_hash.clone(),
                blocks[4].0.last_ds_final_hash.clone(),
                None,
                None,
                None,
                timing_tree,
            )?;
            let (bn_1_header_data, bn_1_header_proof) = prove_block_header::<F, C, D>(
                &blocks[5].0.hash,
                &blocks[5].1,
                blocks[5].0.height.clone(),
                blocks[5].0.epoch_id.clone(),
                None,
                None,
                None,
                None,
                None,
                timing_tree,
            )?;
            (
                (b0_header_data, b0_header_proof),
                Some((bn_1_header_data, bn_1_header_proof)),
            )
        }
        _ => {
            panic!("Invalid blocks.len() {}", blocks.len());
        }
    };
    // Prove heights Block_i+2, Block_i+1, Block_i/{Block_0 & Block_n-1}.
    // This proof is optional, since its absence does not affect the proof of block finality. 
    // It is an additional check of finality, in the case when the heights are consecutive. 
    let h1_bytes: Vec<u8> = b2_proof.public_inputs[32..40]
        .iter()
        .map(|x| x.to_canonical_u64() as u8)
        .collect();
    let h2_bytes: Vec<u8> = b1_proof.public_inputs[32..40]
        .iter()
        .map(|x| x.to_canonical_u64() as u8)
        .collect();
    let h3_bytes: Vec<u8> = bi0_header_proof.public_inputs[32..40]
        .iter()
        .map(|x| x.to_canonical_u64() as u8)
        .collect();
    let h1 = u64::from_le_bytes(h1_bytes.try_into().unwrap());
    let h2 = u64::from_le_bytes(h2_bytes.try_into().unwrap());
    let h3 = u64::from_le_bytes(h3_bytes.try_into().unwrap());
    let consecutive_heights = match bn_1_header_data_proof.clone() {
        Some((b_n_1_data, b_n_1_proof)) => {
            let h4_bytes: Vec<u8> = b_n_1_proof.public_inputs[32..40]
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            let h4 = u64::from_le_bytes(h4_bytes.try_into().unwrap());
            if (h1 + 1) == h2 && (h2 + 1) == h3 && (h3 + 1) == h4 {
                let (data, proof) = prove_consecutive_heights_proofs(
                    [
                        (b2_data.common.clone(), b2_data.verifier_only.clone(), b2_proof.clone()),
                        (b1_data.common.clone(), b1_data.verifier_only.clone(), b1_proof.clone()),
                        (bi0_header_data.common.clone(), bi0_header_data.verifier_only.clone(), bi0_header_proof.clone()),
                        (b_n_1_data.common.clone(), b_n_1_data.verifier_only.clone(), b_n_1_proof.clone()),
                    ]
                    .to_vec(),
                )?;
		Some((data.common, data.verifier_only, proof))
            }
            else {
                None
            }
        }
        None => {
            if (h1 + 1) == h2 && (h2 + 1) == h3 {
                let (data, proof) = prove_consecutive_heights_proofs(
                    [
                        (b2_data.common.clone(), b2_data.verifier_only.clone(), b2_proof.clone()),
                        (b1_data.common.clone(), b1_data.verifier_only.clone(), b1_proof.clone()),
                        (bi0_header_data.common.clone(), bi0_header_data.verifier_only.clone(), bi0_header_proof.clone()),
                    ]
                    .to_vec(),
                )?;
		Some((data.common, data.verifier_only, proof))
            }
            else {
                None
            }
        }
    };
    // Prove BFT. Since this function proves both epoch and randomly selected blocks, b_n_1_data_proof is optional, i.e. it is used for epoch blocks.
    let ((b_i_0_data, b_i_0_proof), b_n_1_data_proof) = match blocks.len() {
        // Prove ramdomly selected block.
        5 => {
            // Next block prev_hash.
            let nb_prev_hash: Vec<u8> = b1_proof.public_inputs[72..104]
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            let nb_prev_hash = CryptoHash(nb_prev_hash.try_into().unwrap());
            // Next block height.
            let nb_height_bytes: Vec<u8> = b1_proof.public_inputs[32..40]
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            let nb_height = u64::from_le_bytes(nb_height_bytes.try_into().unwrap());
            // Current block height.
            let cb_height_bytes: Vec<u8> = bi0_header_proof.public_inputs[32..40]
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            let cb_height = u64::from_le_bytes(cb_height_bytes.try_into().unwrap());
            // Message to sign.
            let msg_to_sign = generate_signed_message(cb_height, nb_height, nb_prev_hash);
            let (bi_data, bi_proof) = prove_block_finality::<F, C, D>(
                (
                    &bi0_header_data.common,
                    &bi0_header_data.verifier_only,
                    &bi0_header_proof,
                ),
                Some(msg_to_sign),
                blocks[3].0.approvals.clone(),
                validators.clone(),
                [
                    (
                        ep2_lb_data.common.clone(),
                        ep2_lb_data.verifier_only.clone(),
                        ep2_lb_proof.clone(),
                    ),
                    (
                        ep1_fb_data.common.clone(),
                        ep1_fb_data.verifier_only.clone(),
                        ep1_fb_proof.clone(),
                    ),
                    (
                        b1_data.common.clone(),
                        b1_data.verifier_only.clone(),
                        b1_proof.clone(),
                    ),
                    (
                        b2_data.common.clone(),
                        b2_data.verifier_only.clone(),
                        b2_proof.clone(),
                    ),
                ]
                .to_vec(),
                consecutive_heights.clone(),
                client.clone(),
                timing_tree,
            )?;
            // Set three hashes: of the current block, Bn-1 and B0, as PI in Block_i.
            let len = bi_proof.public_inputs.len();
            let mut pi = vec![];
            pi.push(F::ZERO);
            pi.append(&mut bi_proof.public_inputs[0..32].to_vec().clone());
            pi.append(&mut bi_proof.public_inputs[(len - 64)..].to_vec().clone());
            let (bi_data, bi_proof) = timed!(
                timing_tree,
                "recursion for Block_0 to set three hashes as PI",
                recursive_proof::<F, C, C, D>(
                    (&bi_data.common, &bi_data.verifier_only, &bi_proof),
                    None,
                    Some(&pi),
                )?
            );
            ((bi_data, bi_proof), None)
        }
        // Prove epoch blocks.
        6 => {
            // Next block prev_hash.
            let nb_prev_hash: Vec<u8> = b1_proof.public_inputs[72..104]
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            let nb_prev_hash = CryptoHash(nb_prev_hash.try_into().unwrap());
            // Next block height.
            let nb_height_bytes: Vec<u8> = b1_proof.public_inputs[32..40]
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            let nb_height = u64::from_le_bytes(nb_height_bytes.try_into().unwrap());
            // Current block height.
            let cb_height_bytes: Vec<u8> = bi0_header_proof.public_inputs[32..40]
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            let cb_height = u64::from_le_bytes(cb_height_bytes.try_into().unwrap());
            // Message to sign.
            let msg_to_sign = generate_signed_message(cb_height, nb_height, nb_prev_hash);
            // Prove Block_0.
            let (b0_data, b0_proof) = prove_block_finality::<F, C, D>(
                (
                    &bi0_header_data.common,
                    &bi0_header_data.verifier_only,
                    &bi0_header_proof,
                ),
                Some(msg_to_sign),
                blocks[3].0.approvals.clone(),
                validators.clone(),
                [
                    (
                        ep2_lb_data.common.clone(),
                        ep2_lb_data.verifier_only.clone(),
                        ep2_lb_proof.clone(),
                    ),
                    (
                        ep1_fb_data.common.clone(),
                        ep1_fb_data.verifier_only.clone(),
                        ep1_fb_proof.clone(),
                    ),
                    (
                        b1_data.common.clone(),
                        b1_data.verifier_only.clone(),
                        b1_proof.clone(),
                    ),
                    (
                        b2_data.common.clone(),
                        b2_data.verifier_only.clone(),
                        b2_proof.clone(),
                    ),
                ]
                .to_vec(),
                consecutive_heights.clone(),
                client.clone(),
                timing_tree,
            )?;
            // Prove epoch_id block for Block_n-1.
            let ep3_last_block_hash_bytes = ep3_last_block_hash_bytes.expect(
                "No hash for Block_n-1(Epochi-3) to prove epoch_id of Block_n-1(Epochi-1).",
            );
            let ep3_last_block_bytes = ep3_last_block_bytes.expect(
                "No hash for Block_n-1(Epochi-3) to prove epoch_id of Block_n-1(Epochi-1).",
            );
            let (ep3_lb_data, ep3_lb_proof) = prove_block_header::<F, C, D>(
                &ep3_last_block_hash_bytes,
                &ep3_last_block_bytes,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                timing_tree,
            )?;
            // Next block prev_hash.
            let nb_prev_hash: Vec<u8> = b0_proof.public_inputs[72..104]
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            let nb_prev_hash = CryptoHash(nb_prev_hash.try_into().unwrap());
            // Next block height.
            let nb_height_bytes: Vec<u8> = b0_proof.public_inputs[32..40]
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            let nb_height = u64::from_le_bytes(nb_height_bytes.try_into().unwrap());
            // Current block height.  
            let cb_height_bytes: Vec<u8> = bn_1_header_data_proof.clone().expect("No Bn-1 header proof.").1.public_inputs[32..40]
                .iter()
                .map(|x| x.to_canonical_u64() as u8)
                .collect();
            let cb_height = u64::from_le_bytes(cb_height_bytes.try_into().unwrap());
            // Message to sing.
            let msg_to_sign = generate_signed_message(cb_height, nb_height, nb_prev_hash);
            // Prove Block_n-1.
            let (b_n_1_data, b_n_1_proof) = prove_block_finality::<F, C, D>(
                ( 
                    &bn_1_header_data_proof.clone().expect("No Bn-1 header proof.").0.common,
                    &bn_1_header_data_proof.clone().expect("No Bn-1 header proof.").0.verifier_only,
                    &bn_1_header_data_proof.clone().expect("No Bn-1 header proof.").1,
                ),
                Some(msg_to_sign),
                blocks[4].0.approvals.clone(),
                validators_n_1.clone(),
                [
                    (
                        ep3_lb_data.common.clone(),
                        ep3_lb_data.verifier_only.clone(),
                        ep3_lb_proof.clone(),
                    ),
                    (
                        ep2_lb_data.common.clone(),
                        ep2_lb_data.verifier_only.clone(),
                        ep2_lb_proof.clone(),
                    ),
                    (
                        b0_data.common.clone(),
                        b0_data.verifier_only.clone(),
                        b0_proof.clone(),
                    ),
                    (
                        b1_data.common.clone(),
                        b1_data.verifier_only.clone(),
                        b1_proof.clone(),
                    ),
                ]
                .to_vec(),
                consecutive_heights.clone(),
                client.clone(),
                timing_tree,
            )?;
            // Set three hashes: of the current block, Bn-1 and B0, as PI in Block_0.
            let len = b0_proof.public_inputs.len();
            let mut pi = vec![];
            pi.push(F::ONE);
            pi.append(&mut b0_proof.public_inputs[0..32].to_vec().clone());
            pi.append(&mut b0_proof.public_inputs[(len - 64)..].to_vec().clone());
            let (b0_data, b0_proof) = timed!(
                timing_tree,
                "recursion for Block_0 to set three hashes as PI",
                recursive_proof::<F, C, C, D>(
                    (&b0_data.common, &b0_data.verifier_only, &b0_proof),
                    None,
                    Some(&pi),
                )?
            );
            // Set three hashes: of the current block, Bn-1 and B0, as PI in Block_n-1.
            let len = b_n_1_proof.public_inputs.len();
            let mut pi = vec![];
            pi.push(F::ONE);
            pi.append(&mut b_n_1_proof.public_inputs[0..32].to_vec().clone());
            pi.append(&mut b_n_1_proof.public_inputs[(len - 64)..].to_vec().clone());
            let (b_n_1_data, b_n_1_proof) = timed!(
                timing_tree,
                "recursion for Block_0 to set three hashes as PI",
                recursive_proof::<F, C, C, D>(
                    (&b_n_1_data.common, &b_n_1_data.verifier_only, &b_n_1_proof),
                    None,
                    Some(&pi),
                )?
            );
	    ((b0_data, b0_proof), Some((b_n_1_data, b_n_1_proof)))
        }
        _ => {
            panic!("Invalid blocks.len() {}", blocks.len());
        }
    };
    Ok(((b_i_0_data, b_i_0_proof), b_n_1_data_proof))
}

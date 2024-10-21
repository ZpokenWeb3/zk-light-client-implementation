use anyhow::Result;
use log::info;
use near_crypto::{PublicKey, Signature};
use near_primitives::block_header::{Approval, ApprovalInner};
use near_primitives::borsh::BorshDeserialize;
use near_primitives::hash::{hash, CryptoHash};
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::{CircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_ed25519::gadgets::eddsa::EDDSATargets;
use plonky2_field::extension::Extendable;
use serde_json::json;
use std::collections::HashMap;

use crate::prove_crypto::{
    ed25519::{ed25519_proof_reuse_circuit, get_ed25519_targets},
    recursion::recursive_proof,
};
use crate::types::*;

/// Generate a message to be signed by validators.
pub fn generate_signed_message(
    ch_height: u64,
    nb_height: u64,
    nb_prev_hash: CryptoHash,
) -> Vec<u8> {
    Approval::get_data_for_sig(
        &if ch_height + 1 == nb_height {
            // If the next block exists, the validators sign the hash of the previous one.
            ApprovalInner::Endorsement(nb_prev_hash)
        } else {
            // If the next block is missed, the validators sign only the missed height.
            ApprovalInner::Skip(ch_height)
        },
        nb_height,
    )
}

/// Prove signatures (approvals) from the next block using public keys (validators) from the previous epoch block
/// for the message (hash or height depends on the existance of the next block) from the current block.
pub fn prove_approvals<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    msg: &[u8],
    approvals: Vec<Vec<u8>>,
    validators: Vec<Vec<u8>>,
) -> Result<(
    (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>),
    Vec<u8>,
)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    assert_eq!(approvals.len(), validators.len());
    let mut ed25519_circuits: HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)> = HashMap::new();
    let mut agg_data_proof: Vec<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> = vec![];
    let mut valid_keys: Vec<u8> = vec![];
    let stakes_sum: u128 = validators
        .iter()
        .map(|item| {
            let item_len = item.len();
            let item_bytes = &item[item_len - STAKE_BYTES..];
            let mut item_const = [0u8; 16];
            item_const[..16].copy_from_slice(item_bytes);
            u128::from_le_bytes(item_const)
        })
        .sum();
    let mut valid_stakes_sum = 0;
    for (pos, approval) in approvals.iter().enumerate() {
        // Signature length is 64 bytes, plus Option type (byte), plus signature type (byte).
        if approval.len() == SIG_BYTES + (TYPE_BYTE + TYPE_BYTE) {
            let validator_len = validators[pos].len();
            let sig = Signature::try_from_slice(&approval[1..])?;
            let pk = PublicKey::try_from_slice(
                &validators[pos][(validator_len - STAKE_BYTES - PK_HASH_BYTES - TYPE_BYTE)
                    ..(validator_len - STAKE_BYTES)],
            )?;
            let verify: bool = sig.verify(msg, &pk);
            if verify {
                if agg_data_proof.is_empty() {
                    agg_data_proof.push(ed25519_proof_reuse_circuit(
                        msg,
                        &approval[2..],
                        &validators[pos][(validator_len - STAKE_BYTES - PK_HASH_BYTES)
                            ..(validator_len - STAKE_BYTES)],
                        &mut ed25519_circuits,
                    )?);
                } else {
                    let (sig_d, sig_p) = ed25519_proof_reuse_circuit(
                        msg,
                        &approval[2..],
                        &validators[pos][(validator_len - STAKE_BYTES - PK_HASH_BYTES)
                            ..(validator_len - STAKE_BYTES)],
                        &mut ed25519_circuits,
                    )?;
                    agg_data_proof[0] = recursive_proof::<F, C, C, D>(
                        (
                            &agg_data_proof[0].0.common,
                            &agg_data_proof[0].0.verifier_only,
                            &agg_data_proof[0].1,
                        ),
                        Some((&sig_d.common, &sig_d.verifier_only, &sig_p)),
                        None,
                    )?;
                }
                valid_keys.push(pos as u8);
                valid_keys.append(
                    &mut validators[pos]
                        [(validator_len - STAKE_BYTES - PK_HASH_BYTES)..(validator_len - STAKE_BYTES)]
                        .to_vec(),
                );

                let mut stake_vec = [0u8; 16];
                stake_vec[..16].copy_from_slice(&validators[pos][(validator_len - STAKE_BYTES)..]);
                let stake = u128::from_le_bytes(stake_vec);
                valid_stakes_sum += stake;
            }
            else {
                panic!("Invalid signature or public key.");
            }
        }
    }
    // Set hash of valid keys as PI.
    let valid_keys_hash = hash(&valid_keys);
    let valid_keys_hash_vec: Vec<F> = valid_keys_hash
        .0
        .iter()
        .map(|x| F::from_canonical_u8(*x))
        .collect();
    let (aggregated_circuit_data, aggregated_proof) = recursive_proof::<F, C, C, D>(
        (
            &agg_data_proof[0].0.common,
            &agg_data_proof[0].0.verifier_only,
            &agg_data_proof[0].1,
        ),
        None,
        Some(&valid_keys_hash_vec),
    )?;
    Ok(((aggregated_circuit_data, aggregated_proof), valid_keys))
}

/// Prove signatures (approvals) using nats client, assume that nats consumers are started.
pub fn prove_approvals_with_client<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    msg: &[u8],
    approvals: Vec<Vec<u8>>,
    validators: Vec<Vec<u8>>,
    client: nats::Connection,
) -> Result<(
    (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>),
    Vec<u8>,
)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    assert_eq!(approvals.len(), validators.len());
    let mut signature_circuit_data: Vec<CircuitData<F, C, D>> = Vec::with_capacity(1);
    let mut valid_keys: Vec<u8> = vec![];
    let result_subscriber = client.subscribe("PROCESS_SIGNATURE_RESULT")?;
    let mut main_counter = 0;
    let stakes_sum: u128 = validators
        .iter()
        .map(|item| {
            let item_len = item.len();
            let item_bytes = &item[item_len - STAKE_BYTES..];
            let mut item_const = [0u8; 16];
            item_const[..16].copy_from_slice(item_bytes);
            u128::from_le_bytes(item_const)
        })
        .sum();
    let mut valid_stakes_sum = 0;
    for (pos, approval) in approvals.iter().enumerate() {
        // Signature length is 64 bytes, plus Option type (byte), plus signature type (byte).
        if approval.len() == SIG_BYTES + (TYPE_BYTE + TYPE_BYTE) {
            let validator_len = validators[pos].len();
            let sig = Signature::try_from_slice(&approval[1..])?;
            let pk = PublicKey::try_from_slice(
                &validators[pos][(validator_len - STAKE_BYTES - PK_HASH_BYTES - TYPE_BYTE)
                    ..(validator_len - STAKE_BYTES)],
            )?;
            let verify: bool = sig.verify(msg, &pk);
            if verify {
                let input_task = InputTask {
                    message: msg.to_vec(),
                    approval: approval[2..].to_vec(),
                    validator: validators[pos]
                        [(validator_len - STAKE_BYTES - PK_HASH_BYTES)..(validator_len - STAKE_BYTES)]
                        .to_vec(),
                    signature_index: pos,
                };
                let input_bytes = serde_json::to_vec(&json!(input_task))?;
                client
                    .publish("PROVE_SIGNATURE", input_bytes)
                    .expect("Error publishing proving task");
                main_counter += 1;
                let mut stake_vec = [0u8; 16];
                stake_vec[..16].copy_from_slice(&validators[pos][(validator_len - STAKE_BYTES)..]);
                let stake = u128::from_le_bytes(stake_vec);
                valid_stakes_sum += stake;
            }
            else {
                panic!("Invalid signature or public key.");
            }
        }
    }
    let msg_len_in_bits = msg.len() * 8;
    let (circuit_data, _) = get_ed25519_targets(msg_len_in_bits).unwrap();
    signature_circuit_data.push(circuit_data);

    let mut agg_data = signature_circuit_data[0].clone();
    let mut agg_proofs = Vec::with_capacity(1);
    let mut aux_counter = 0;
    loop {
        if aux_counter == main_counter {
            break;
        }
        if let Some(message) = result_subscriber.iter().next() {
            if let Ok(payload) = serde_json::from_slice::<OutputTask>(&message.data) {
                info!("Processing signature: {}", payload.signature_index);
                let serialized_proof = ProofWithPublicInputs::<F, C, D>::from_bytes(
                    payload.proof,
                    &signature_circuit_data[0].common,
                )?;
                let verifier_only_data =
                    VerifierOnlyCircuitData::from_bytes(payload.verifier_data).unwrap();
                if agg_proofs.is_empty() {
                    agg_proofs.push(serialized_proof);
                    agg_data = CircuitData {
                        prover_only: agg_data.prover_only,
                        verifier_only: verifier_only_data,
                        common: agg_data.common,
                    }
                } else {
                    (agg_data, agg_proofs[0]) = recursive_proof::<F, C, C, D>(
                        (&agg_data.common, &agg_data.verifier_only, &agg_proofs[0]),
                        Some((
                            &signature_circuit_data[0].common,
                            &verifier_only_data,
                            &serialized_proof,
                        )),
                        None,
                    )?;
                }
                let signature_index = payload.signature_index;
                valid_keys.push(signature_index as u8);
                let validator_len = validators[signature_index].len();
                valid_keys.append(
                    &mut validators[signature_index]
                        [(validator_len - STAKE_BYTES - PK_HASH_BYTES)..(validator_len - STAKE_BYTES)]
                        .to_vec(),
                );
                aux_counter += 1;
            }
        }
    }
    // Set hash of valid keys as PI.
    let valid_keys_hash = hash(&valid_keys);
    let valid_keys_hash_vec: Vec<F> = valid_keys_hash
        .0
        .iter()
        .map(|x| F::from_canonical_u8(*x))
        .collect();
    (agg_data, agg_proofs[0]) = recursive_proof::<F, C, C, D>(
        (&agg_data.common, &agg_data.verifier_only, &agg_proofs[0]),
        None,
        Some(&valid_keys_hash_vec),
    )?;
    Ok(((agg_data, agg_proofs[0].clone()), valid_keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{load_block_header, load_validators};
    use anyhow::Result;
    use log::info;
    use near_crypto::{KeyType, SecretKey};
    use near_primitives::borsh::BorshSerialize;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use sha2::Digest;

    #[test]
    fn test_generate_signed_message_for_validators() -> Result<()> {
        let path = "../data/block_header_small.json".to_string();
        let (block_hash, block_header) = load_block_header(&path)?;
        let path = "../data/next_block_header_small.json".to_string();
        let (_, next_block_header) = load_block_header(&path)?;
        // for this test msg_to_sign containes a block_hash & next_block_header.height()
        let msg_to_sign = generate_signed_message(
            block_header.height(),
            next_block_header.height(),
            *next_block_header.prev_hash(),
        );
        let hash = ApprovalInner::Endorsement(block_hash);
        let msg_to_sign_vec = [
            borsh::to_vec(&hash).unwrap().as_ref(),
            next_block_header.height().to_le_bytes().as_ref(),
        ]
        .concat();
        assert_eq!(msg_to_sign, msg_to_sign_vec);
        Ok(())
    }

    #[test]
    fn test_generate_signed_message_with_missed_next_block() -> Result<()> {
        let path = "../data/block_header_small.json".to_string();
        let (block_hash, block_header) = load_block_header(&path)?;
        let path = "../data/next_block_header_small_skip.json".to_string();
        let (_, next_block_header) = load_block_header(&path)?;
        // for this test msg_to_sign containes a block_height & next_block_header.height()
        let msg_to_sign = generate_signed_message(
            block_header.height(),
            next_block_header.height(),
            *next_block_header.prev_hash(),
        );
        let height = ApprovalInner::Skip(block_header.height());
        let msg_to_sign_vec = [
            borsh::to_vec(&height).unwrap().as_ref(),
            next_block_header.height().to_le_bytes().as_ref(),
        ]
        .concat();
        assert_eq!(msg_to_sign, msg_to_sign_vec);
        Ok(())
    }

    #[test]
    fn test_prove_block_prove_approvals_from_next_block_by_public_keys() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let path = "../data/block_header_small.json".to_string();
        let (_block_hash, block_header) = load_block_header(&path)?;
        let path = "../data/next_block_header_small.json".to_string();
        let (_, next_block_header) = load_block_header(&path)?;
        let approvals_bytes: Vec<Vec<u8>> = next_block_header
            .approvals()
            .iter()
            .map(|approval| borsh::to_vec(approval).unwrap())
            .collect();

        // for this test msg_to_sign containes a block_hash & next_block_header.height()
        let msg_to_sign = generate_signed_message(
            block_header.height(),
            next_block_header.height(),
            *next_block_header.prev_hash(),
        );
        let path = "../data/validators_ordered_small.json".to_string();
        let validators = load_validators(&path)?;
        let validators_bytes: Vec<Vec<u8>> = validators
            .iter()
            .map(|value| borsh::to_vec(value).unwrap())
            .collect();

        let ((_data, proof), _valid_keys) =
            prove_approvals::<F, C, D>(&msg_to_sign, approvals_bytes, validators_bytes)?;
        info!(
            "Size of proof for aggregated signatures: {} bytes",
            proof.to_bytes().len()
        );
        Ok(())
    }
}

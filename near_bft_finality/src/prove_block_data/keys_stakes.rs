use anyhow::Result;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::extension::Extendable;

use crate::prove_crypto::{recursion::recursive_proof, sha256::sha256_proof_u32};
use crate::types::*;

/// Prove the existence of chosen keys while proving signatures in the validators list.
/// Prove that the list of valid keys gives 2/3 of the total sum of all stakes.
/// Public inputs: a set of valid keys with their indices & 2/3 of the total sum of all stakes.
pub fn prove_valid_keys_stakes_in_valiators_list<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    valid_keys: Vec<u8>,
    valid_keys_hash: Vec<u8>,
    validators: Vec<Vec<u8>>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let zero = builder.zero();
    let neg_one = builder.neg_one();
    // Set values of validators.
    let mut all_validators_values: Vec<Vec<F>> = vec![];
    for i in validators.iter() {
        let a: Vec<F> = i.iter().map(|x| F::from_canonical_u8(*x)).collect();
        all_validators_values.push(a);
    }
    // Set values of valid_keys.
    let valid_keys_values: Vec<F> = valid_keys
        .iter()
        .map(|x| F::from_canonical_u8(*x))
        .collect();
    // Set tergtes for validators.
    let mut all_validators_targets: Vec<Vec<Target>> = vec![];
    let mut valid_keys_targets: Vec<Target> = vec![];
    let mut pw = PartialWitness::new();
    for validator in all_validators_values.iter() {
        let a = builder.add_virtual_targets(validator.len());
        for j in 0..validator.len() {
            pw.set_target(a[j], validator[j]);
        }
        all_validators_targets.push(a);
    }
    // Set tergtes for valid_keys.
    for i in 0..valid_keys_values.len() {
        valid_keys_targets.push(builder.add_virtual_target());
        pw.set_target(valid_keys_targets[i], valid_keys_values[i]);
    }
    // The result array length should be 17 to store Near stakes (16 bytes) and carry bits.
    const STAKE_SUM_LEN: usize = STAKE_BYTES + 1;
    let mut valid_stake_sum: Vec<Target> = [builder.zero(); STAKE_SUM_LEN].to_vec();
    // Count a sum of stakes for a list of valid keys & check whether a list of validators contains these valid keys.
    for i in (0..valid_keys_values.len()).step_by(PK_HASH_BYTES + 1) {
        let pos = valid_keys_values[i].to_noncanonical_u64() as usize;
        let len = all_validators_targets[pos].len();
        // Check key.
        for j in 0..PK_HASH_BYTES {
            builder.connect(
                all_validators_targets[pos][(len - STAKE_BYTES - PK_HASH_BYTES) + j],
                valid_keys_targets[(i + 1) + j],
            );
        }
        // Compute sum of valid stakes.
        let mut crr = builder.zero();
        for j in 0..STAKE_BYTES {
            let sum = builder.add_many([
                &valid_stake_sum[j],
                &all_validators_targets[pos][(len - STAKE_BYTES) + j],
                &crr,
            ]);
            let sum_bits = builder.split_le(sum, 64);
            let s = builder.le_sum(sum_bits[0..8].iter());
            crr = builder.le_sum(sum_bits[8..16].iter());
            valid_stake_sum[j] = s;
        }
        valid_stake_sum[STAKE_SUM_LEN - 1] = builder.add(valid_stake_sum[STAKE_SUM_LEN - 1], crr);
    }
    // Compute sum of all stakes.
    let mut all_stake_sum: Vec<Target> = [builder.zero(); STAKE_SUM_LEN].to_vec();
    for validator in all_validators_targets.iter() {
        let len = validator.len();
        let mut crr = builder.zero();
        for j in 0..STAKE_BYTES {
            let sum =
                builder.add_many([&all_stake_sum[j], &validator[(len - STAKE_BYTES) + j], &crr]);
            let sum_bits = builder.split_le(sum, 64);
            let s = builder.le_sum(sum_bits[0..8].iter());
            crr = builder.le_sum(sum_bits[8..16].iter());
            all_stake_sum[j] = s;
        }
        all_stake_sum[STAKE_SUM_LEN - 1] = builder.add(all_stake_sum[STAKE_SUM_LEN - 1], crr);
    }
    // Check that MSB is less than 100 (max number of validators) for both values.
    // Set values that indicates a negative difference.
    // Negative difference could be in two forms: -1 and {-2, -255}.
    let constant1 = builder.constant(F::from_canonical_u64(0xFFFFFFFEFFFFFF00));
    let constant2 = builder.constant(F::from_canonical_u64(0xFFFFFFFF00000000));
    let seven = builder.constant(F::from_canonical_u8(7));
    let h = builder.constant(F::from_canonical_u8(100));
    // Check MSB for valid_stake_sum.
    {
        // The difference should be negative.
        let sub = builder.sub(valid_stake_sum[STAKE_SUM_LEN - 1], h);
        // If the difference is -1, then we use constant2, and constant1 otherwise.
        let sub_eq = builder.is_equal(sub, neg_one);
        let chs_constant = builder.select(sub_eq, constant2, constant1);
        let chs_constant_bits = builder.split_le(chs_constant, 64);
        let sub_bits = builder.split_le(sub, 64);
        let mut s = zero;
        // Check the values of bytes [0xFF 0xFF 0xFF 0xFF/0xFE 0x00/0xFF 0x00/0xFF 0x00/0xFF 0xXX], except the last one with the value 0xXX.
        for j in (8..sub_bits.len()).step_by(8) {
            let n1 = builder.le_sum(chs_constant_bits[j..(j + 8)].iter());
            let n2 = builder.le_sum(sub_bits[j..(j + 8)].iter());
            let q = builder.is_equal(n1, n2);
            s = builder.add(s, q.target);
        }
        builder.connect(s, seven);
    }
    // Check MSB for all_stake_sum.
    {
        // The difference should be negative.
        let sub = builder.sub(all_stake_sum[STAKE_SUM_LEN - 1], h);
        // If the difference is -1, then we use constant2, and constant1 otherwise.
        let sub_eq = builder.is_equal(sub, neg_one);
        let chs_constant = builder.select(sub_eq, constant2, constant1);
        let chs_constant_bits = builder.split_le(chs_constant, 64);
        let sub_bits = builder.split_le(sub, 64);
        let mut s = zero;
        // Check the values of bytes [0xFF 0xFF 0xFF 0xFF/0xFE 0x00/0xFF 0x00/0xFF 0x00/0xFF 0xXX], except the last one with the value 0xXX.
        for j in (8..sub_bits.len()).step_by(8) {
            let n1 = builder.le_sum(chs_constant_bits[j..(j + 8)].iter());
            let n2 = builder.le_sum(sub_bits[j..(j + 8)].iter());
            let q = builder.is_equal(n1, n2);
            s = builder.add(s, q.target);
        }
        builder.connect(s, seven);
    }
    // Compute (3 * valid_stake_sum).
    let three = builder.constant(F::from_canonical_u8(3));
    let mut three_times_valid_stake_sum: Vec<Target> =
        builder.add_virtual_targets(valid_stake_sum.len());
    let mut crr = builder.zero();
    for i in 0..valid_stake_sum.len() {
        let t = builder.mul_add(valid_stake_sum[i], three, crr);
        let bits = builder.split_le(t, 64);
        three_times_valid_stake_sum[i] = builder.le_sum(bits[0..8].iter());
        crr = builder.le_sum(bits[8..16].iter());
    }
    three_times_valid_stake_sum.push(crr);
    // Compute (2 * all_stake_sum).
    let two = builder.two();
    let mut crr = builder.zero();
    for stake in &mut all_stake_sum {
        let t = builder.mul_add(*stake, two, crr);
        let bits = builder.split_le(t, 64);
        *stake = builder.le_sum(bits[0..8].iter());
        crr = builder.le_sum(bits[8..16].iter());
    }
    all_stake_sum.push(crr);
    // Comparison: three_times_valid_stake_sum >= all_stake_sum.
    let mut res: Vec<Target> = builder.add_virtual_targets(three_times_valid_stake_sum.len());
    let mut i = (three_times_valid_stake_sum.len() - 1) as isize;
    let mut prev = (BoolTarget::new_unsafe(zero), BoolTarget::new_unsafe(zero));
    // Since stakes are stored in little-endian format, check starts from the last element.
    while i >= 0 {
        // Сheck the equality of elements of two arrays.
        let is_equal = builder.is_equal(
            three_times_valid_stake_sum[i as usize],
            all_stake_sum[i as usize],
        );
        // Сheck if the difference is positive or negative.
        // In the case of positive difference if_negative is zero, and seven otherwise.
        let is_negative = {
            // Note, we operate with 64-bit elements in the field.
            // In the case of negative difference we get a positive value of the form: order() - all_stake_sum[i].
            let sub = builder.sub(
                three_times_valid_stake_sum[i as usize],
                all_stake_sum[i as usize],
            );
            let sub_eq = builder.is_equal(sub, neg_one);
            let chs_constant = builder.select(sub_eq, constant2, constant1);
            let chs_constant_bits = builder.split_le(chs_constant, 64);
            let sub_bits = builder.split_le(sub, 64);
            let mut s = zero;
            // Check the values of bytes [0xFF 0xFF 0xFF 0xFF/0xFE 0x00/0xFF 0x00/0xFF 0x00/0xFF 0xXX], except the last one with the value 0xXX.
            for j in (8..sub_bits.len()).step_by(8) {
                let n1 = builder.le_sum(chs_constant_bits[j..(j + 8)].iter());
                let n2 = builder.le_sum(sub_bits[j..(j + 8)].iter());
                let q = builder.is_equal(n1, n2);
                s = builder.add(s, q.target);
            }
            let s_eq = builder.is_equal(s, seven);
            let chs_s = builder.select(s_eq, seven, zero);
            builder.connect(s, chs_s);
            s_eq
        };
        if (i as usize) == three_times_valid_stake_sum.len() - 1 {
            res[i as usize] = builder.select(
                is_negative,
                all_stake_sum[i as usize],
                three_times_valid_stake_sum[i as usize],
            );
            // Store if_equal and if_negative flags.
            prev = (is_equal, is_negative);
        } else {
            // If prev=(false, false), res[i] is set to v1_three_targets[i].
            // If prev=(true, false) or (false, true), then prev is set according to new if_equal and if_negative.
            // res[i] is set to according to the if_negative flag.
            prev = {
                let q = builder.is_equal(prev.0.target, prev.1.target);
                let tmp1 = builder.select(q, prev.0.target, is_equal.target);
                let tmp2 = builder.select(q, prev.1.target, is_negative.target);
                (BoolTarget::new_unsafe(tmp1), BoolTarget::new_unsafe(tmp2))
            };
            res[i as usize] = builder.select(
                prev.1,
                all_stake_sum[i as usize],
                three_times_valid_stake_sum[i as usize],
            );
        };
        i -= 1;
    }
    // Compare the selected byted during "Comparison: three_times_valid_stake_sum >= all_stake_sum"
    // with bytes of three_times_valid_stake_sum. They should be equal if 2/3 is satisfied.
    for i in 0..three_times_valid_stake_sum.len() {
        builder.connect(three_times_valid_stake_sum[i], res[i]);
    }
    // Set keys & stakes as PI.
    builder.register_public_inputs(&valid_keys_targets);
    builder.register_public_inputs(&valid_stake_sum);
    let keys_stakes_data = builder.build();
    let keys_stakes_proof = keys_stakes_data.prove(pw)?;
    // Check if valid_keys correnpond to valid_keys_hash that was set during signature verification.
    let len = keys_stakes_proof.public_inputs.len() - valid_stake_sum.len();
    let keys: Vec<u8> = keys_stakes_proof.public_inputs[0..len]
        .iter()
        .map(|x| x.to_canonical_u64() as u8)
        .collect();
    let (keys_hash_data, keys_hash_proof) = sha256_proof_u32::<F, C, D>(&keys, &valid_keys_hash)?;
    let (agg_data, agg_proof) = recursive_proof::<F, C, C, D>(
        (
            &keys_stakes_data.common,
            &keys_stakes_data.verifier_only,
            &keys_stakes_proof,
        ),
        Some((
            &keys_hash_data.common,
            &keys_hash_data.verifier_only,
            &keys_hash_proof,
        )),
        Some(&keys_stakes_proof.public_inputs),
    )?;
    Ok((agg_data, agg_proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        prove_block_data::signatures::generate_signed_message,
        utils::{load_block_header, load_validators},
    };
    use anyhow::Result;
    use log::info;
    use near_crypto::{KeyType, SecretKey};
    use near_primitives::borsh::BorshSerialize;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    #[test]
    fn test_prove_block_prove_valid_keys_stakes_in_validators_list() -> Result<()> {
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

        // valid keys
        let mut valid_keys: Vec<u8> = vec![];
        for (pos, approval) in approvals_bytes.iter().enumerate() {
            // signature length (64 bytes) plus Option type (byte), plus signature type (byte)
            if approval.len() == SIG_BYTES + (TYPE_BYTE + TYPE_BYTE) {
                let validator_len = validators_bytes[pos].len();
                let sig = Signature::try_from_slice(&approval[1..])?;
                let pk = PublicKey::try_from_slice(
                    &validators_bytes[pos][(validator_len - STAKE_BYTES - PK_HASH_BYTES - TYPE_BYTE)
                        ..(validator_len - STAKE_BYTES)],
                )?;
                let verify: bool = sig.verify(&msg_to_sign, &pk);
                if verify {
                    valid_keys.push(pos as u8);
                    valid_keys.append(
                        &mut validators_bytes[pos][(validator_len - STAKE_BYTES - PK_HASH_BYTES)
                            ..(validator_len - STAKE_BYTES)]
                            .to_vec(),
                    );
                }
            }
        }
        let valid_keys_hash = hash(&valid_keys).0.to_vec();
        let (_data, proof) = prove_valid_keys_stakes_in_valiators_list::<F, C, D>(
            valid_keys,
            valid_keys_hash,
            validators_bytes,
        )?;
        info!(
            "Size of proof for keys & stakes: {} bytes",
            proof.to_bytes().len()
        );
        Ok(())
    }
}

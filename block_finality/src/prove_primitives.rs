use anyhow::Result;
use itertools::Itertools;
use log::Level;
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
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::config::Hasher;
use plonky2_field::extension::Extendable;

use plonky2_sha256_u32::sha256::{CircuitBuilderHashSha2, WitnessHashSha2};
use plonky2_sha256_u32::types::CircuitBuilderHash;

/// Proves that two arrays are equal.
/// # Arguments
///
/// * `array1` - A slice of bytes representing the first array of bytes.
/// * `array2` - A slice of bytes representing the second array of bytes.
///
/// # Returns
///
/// Returns a result containing the computed circuit data and the proof with public inputs.
/// - `CircuitData<F, C, D>`: The circuit data generated during the proof generation process.
/// - `ProofWithPublicInputs<F, C, D>`: The proof along with an array of bytes as public inputs.
///
pub fn prove_eq_array<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize>(
    array1: &[u8],
    array2: &[u8],
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    assert_eq!(array1.len(), array2.len());
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let array1_values: Vec<F> = array1.iter().map(|x| F::from_canonical_u8(*x)).collect();
    let array2_values: Vec<F> = array2.iter().map(|x| F::from_canonical_u8(*x)).collect();
    let mut array1_targets = vec![];
    let mut array2_targets = vec![];
    let mut pw = PartialWitness::new();
    for i in 0..array1_values.len() {
        array1_targets.push(builder.add_virtual_target());
        pw.set_target(array1_targets[i], array1_values[i]);
    }
    for i in 0..array2_values.len() {
        array2_targets.push(builder.add_virtual_target());
        pw.set_target(array2_targets[i], array2_values[i]);
    }
    let len1 = builder.add_virtual_target();
    let len2 = builder.add_virtual_target();
    pw.set_target(len1, F::from_canonical_usize(array1_values.len()));
    pw.set_target(len2, F::from_canonical_usize(array2_values.len()));
    builder.connect(len1, len2);
    for (d, s) in array1_targets.iter().zip(array2_targets) {
        builder.connect(*d, s);
    }
    builder.register_public_inputs(&array1_targets);
    let timing = TimingTree::new("build", Level::Info);
    let data = builder.build();
    timing.print();
    let timing = TimingTree::new("prove", Level::Info);
    let proof = data.prove(pw)?;
    timing.print();
    data.verify(proof.clone())?;
    Ok((data, proof))
}

/// Proves that the computed stakes value is greater than or equal to two-thirds of all stakes value.
/// # Arguments
///
/// * `stake1` - A slice of bytes representing the computed stake value.
/// * `stake2` - A slice of bytes representing the all stake value.
///
/// # Returns
///
/// Returns a result containing the computed circuit data and the proof with public inputs.
/// - `CircuitData<F, C, D>`: The circuit data generated during the proof generation process.
/// - `ProofWithPublicInputs<F, C, D>`: The proof along with computed stake value as public inputs.
///
pub fn two_thirds<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize>(
    stake1: &[u8],
    stake2: &[u8],
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
    where
        C::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let stake1_values: Vec<F> = stake1.iter().map(|x| F::from_canonical_u8(*x)).collect();
    let stake2_values: Vec<F> = stake2.iter().map(|x| F::from_canonical_u8(*x)).collect();
    let stake1_targets: Vec<Target> = builder.add_virtual_targets(stake1_values.len());
    let mut stake2_targets: Vec<Target> = builder.add_virtual_targets(stake2_values.len());
    let mut pw = PartialWitness::new();
    for (t, v) in stake1_targets.iter().zip_eq(stake1_values) {
        pw.set_target(*t, v);
    }
    for (t, v) in stake2_targets.iter().zip_eq(stake2_values) {
        pw.set_target(*t, v);
    }
    /// compute 3 * stake1
    let mut stake1_3_targets: Vec<Target> = builder.add_virtual_targets(stake1_targets.len());
    let three = builder.constant(F::from_canonical_u8(3));
    let mut c = builder.zero();
    for i in 0..stake1_targets.len() {
        let t = builder.mul_add(stake1_targets[i], three, c);
        let bits = builder.split_le(t, 10);
        stake1_3_targets[i] = builder.le_sum(bits[0..8].iter());
        c = builder.le_sum(bits[8..10].iter());
    }
    stake1_3_targets.push(c);
    /// compute 2 * stake2
    let two = builder.two();
    let mut c = builder.zero();
    for i in 0..stake2_targets.len() {
        let t = builder.mul_add(stake2_targets[i], two, c);
        let bits = builder.split_le(t, 9);
        stake2_targets[i] = builder.le_sum(bits[0..8].iter());
        c = builder.le_sum(bits[8..9].iter());
    }
    stake2_targets.push(c);
    // if stake2 array is bigger and there are non zero elements
    // then stake1 is not 2/3 of stake2
    let zero = builder.zero();
    for i in stake1_3_targets.len()..stake2_targets.len() {
        builder.connect(stake2_targets[i], zero);
    }
    /// compare: stake1 is more than 2/3 of stake2
    let mut res: Vec<Target> = builder.add_virtual_targets(stake1_3_targets.len());
    let mut i = (stake1_3_targets.len() - 1) as isize;
    let mut prev = (BoolTarget::new_unsafe(zero), zero);
    while i >= 0 {
        let if_equal = builder.is_equal(stake1_3_targets[i as usize], stake2_targets[i as usize]);
        // check if the difference is negative,
        // then the result is order() - stake2_targets[i]
        // in bytes [0xFF 0xFF 0xFF 0xFE 0xFF 0xFF 0xFF 0xXX]
        let if_positive = {
            let sub = builder.sub(stake1_3_targets[i as usize], stake2_targets[i as usize]);
            let sub_bits = builder.split_le(sub, 64);
            let a1 = builder.constant(F::from_canonical_u8(0xFF));
            let a2 = builder.constant(F::from_canonical_u8(0xFE));
            let mut s = zero;
            for j in (8..sub_bits.len()).step_by(8) {
                let number = builder.le_sum(sub_bits[j..(j + 8)].iter());
                match j {
                    32 => {
                        let q = builder.is_equal(number, a2);
                        s = builder.add(s, q.target);
                    }
                    _ => {
                        let q = builder.is_equal(number, a1);
                        s = builder.add(s, q.target);
                    }
                }
            }
            s
        };
        if (i as usize) == stake1_3_targets.len() - 1 {
            res[i as usize] = builder.select(
                BoolTarget::new_unsafe(if_positive),
                stake2_targets[i as usize],
                stake1_3_targets[i as usize],
            );
            prev = (if_equal, if_positive);
        } else {
            prev = {
                let q = builder.is_equal(prev.0.target, prev.1);
                let tmp1 = builder.select(q, prev.0.target, if_equal.target);
                let tmp2 = builder.select(q, prev.1, if_positive);
                (BoolTarget::new_unsafe(tmp1), tmp2)
            };
            res[i as usize] = builder.select(
                BoolTarget::new_unsafe(prev.1),
                stake2_targets[i as usize],
                stake1_3_targets[i as usize],
            );
        };
        i -= 1;
    }
    for i in 0..stake1_3_targets.len() {
        builder.connect(stake1_3_targets[i], res[i]);
    }
    builder.register_public_inputs(&stake1_targets);
    let timing = TimingTree::new("build", Level::Info);
    let data = builder.build();
    timing.print();
    let timing = TimingTree::new("prove", Level::Info);
    let proof = data.prove(pw)?;
    timing.print();
    Ok((data, proof))
}


#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::prove_primitives::prove_eq_array;
    use crate::prove_primitives::two_thirds;

    #[test]
    fn test_two_thirds() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let v: u32 = 1526391;
        let v1: u32 = (1526391 / 3) + 5;
        let v2: u32 = (1526391 / 3) - 5;
        let v3: u32 = 1526391 / 3;

        let v_bits = v.to_be_bytes();
        let v_i_bits = v1.to_be_bytes();
        let (data, proof) = two_thirds::<F, C, D>(&v_bits, &v_i_bits)?;
        data.verify(proof)
    }

    #[test]
    fn test_equal() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let s1 = "hello".to_string();
        let (data, proof) = prove_eq_array::<F, C, D>(s1.as_bytes(), s1.as_bytes())?;
        data.verify(proof)
    }
}


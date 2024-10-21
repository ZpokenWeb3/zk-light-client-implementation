use anyhow::Result;
use itertools::Itertools;
use log::Level;
use plonky2::iop::target::{BoolTarget, Target};
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
use plonky2_field::extension::Extendable;

use crate::types::{BLOCK_HEIGHT_BYTES, STAKE_BYTES};

/// Proves that the difference of numbers, height1 and height2, is equal to one, i.e. height1 is bigger.
/// # Arguments
///
/// * `height1` - A slice of bytes representing the first value.
/// * `height2` - A slice of bytes representing the second value.
///
/// # Returns
///
/// Returns a result containing the computed circuit data and the proof with public inputs.
/// - `CircuitData<F, C, D>`: The circuit data generated during the proof generation process.
/// - `ProofWithPublicInputs<F, C, D>`: The proof along with an array of bytes as public inputs.
///
pub fn prove_consecutive_heights<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    height1: &[u8], // little-endian byte order
    height2: &[u8], // little-endian byte order
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    assert_eq!(height1.len(), BLOCK_HEIGHT_BYTES);
    assert_eq!(height2.len(), BLOCK_HEIGHT_BYTES);
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let height1_values: Vec<F> = height1.iter().map(|x| F::from_canonical_u8(*x)).collect();
    let height2_values: Vec<F> = height2.iter().map(|x| F::from_canonical_u8(*x)).collect();
    let mut height1_targets = vec![];
    let mut height2_targets = vec![];
    let mut pw = PartialWitness::new();
    for i in 0..BLOCK_HEIGHT_BYTES {
        height1_targets.push(builder.add_virtual_target());
        height2_targets.push(builder.add_virtual_target());
        pw.set_target(height1_targets[i], height1_values[i]);
        pw.set_target(height2_targets[i], height2_values[i]);
    }
    // Check lengths.
    let const_len = builder.constant(F::from_canonical_usize(BLOCK_HEIGHT_BYTES));
    let len1 = builder.add_virtual_target();
    let len2 = builder.add_virtual_target();
    pw.set_target(len1, F::from_canonical_usize(height1_values.len()));
    pw.set_target(len2, F::from_canonical_usize(height2_values.len()));
    builder.connect(const_len, len1);
    builder.connect(const_len, len2);
    let zero = builder.zero();
    let one = builder.one();
    let tff = builder.constant(F::from_canonical_u8(255));
    let mut dif: Vec<Target> = builder.add_virtual_targets(BLOCK_HEIGHT_BYTES);
    let mut sum = zero;
    let mut prev = zero;
    let mut i: isize = (BLOCK_HEIGHT_BYTES - 1) as isize;
    while i >= 0 {
        dif[i as usize] = zero;
        if (i as usize) == (BLOCK_HEIGHT_BYTES - 1) {
            // If sub is equal to 1, then dif[i] = 1, 0 otherwise.
            let sub = builder.sub(height1_targets[i as usize], height2_targets[i as usize]);
            let eq = builder.is_equal(sub, one);
            dif[i as usize] = builder.select(eq, one, zero);
            prev = dif[i as usize];
        } else {
            // Check previous values. If they give sub = 1, then current values have to be h1[i]=0 and h2[i]=255.
            let h1_const = builder.select(
                BoolTarget::new_unsafe(prev),
                zero,
                height1_targets[i as usize],
            );
            let h2_const = builder.select(
                BoolTarget::new_unsafe(prev),
                tff,
                height2_targets[i as usize],
            );
            let s1 = builder.sub(height1_targets[i as usize], h1_const);
            let s2 = builder.sub(height2_targets[i as usize], h2_const);
            builder.connect(s1, zero);
            builder.connect(s2, zero);
            // If sub is equal to 1, then dif[i] = 1, 0 otherwise.
            let sub = builder.sub(height1_targets[i as usize], height2_targets[i as usize]);
            let eq = builder.is_equal(sub, one);
            dif[i as usize] = builder.select(eq, one, zero);
            prev = dif[i as usize];
        }
        sum = builder.add(sum, dif[i as usize]);
        i -= 1;
    }
    builder.connect(sum, one);
    builder.register_public_inputs(&[height1_targets, height2_targets].concat());
    let timing = TimingTree::new("build", Level::Info);
    let data = builder.build();
    timing.print();
    let timing = TimingTree::new("prove", Level::Info);
    let proof = data.prove(pw)?;
    timing.print();
    data.verify(proof.clone())?;
    Ok((data, proof))
}

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
pub fn prove_eq_array<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
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

/// Proves that value1 is greater than or equal to two-thirds of value2 value.
/// # Arguments
///
/// * `value1` - A slice of bytes representing the first value (little-endian). For testing Near stakes it is the sum of valid stakes.
/// * `value2` - A slice of bytes representing the second value (little-endian). For testing Near stakes it is the sum of all stakes.
///
/// # Returns
///
/// Returns a result containing the computed circuit data and the proof with public inputs.
/// - `CircuitData<F, C, D>`: The circuit data generated during the proof generation process.
/// - `ProofWithPublicInputs<F, C, D>`: The proof along with value1 as public inputs.
///
pub fn two_thirds<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    value1: &[u8], // little-endian byte order
    value2: &[u8], // little-endian byte order
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let zero = builder.zero();
    let neg_one = builder.neg_one();
    // Set values (array elements) of both values.
    let v1_values: Vec<F> = value1.iter().map(|x| F::from_canonical_u8(*x)).collect();
    let v2_values: Vec<F> = value2.iter().map(|x| F::from_canonical_u8(*x)).collect();
    // Register targets for both arrays.
    let v1_targets: Vec<Target> = builder.add_virtual_targets(v1_values.len());
    let mut v2_targets: Vec<Target> = builder.add_virtual_targets(v2_values.len());
    let mut pw = PartialWitness::new();
    for (t, v) in v1_targets.iter().zip_eq(v1_values) {
        pw.set_target(*t, v);
    }
    for (t, v) in v2_targets.iter().zip_eq(v2_values) {
        pw.set_target(*t, v);
    }
    // The result array length should be 17 to store carry bits.
    const LEN: usize = STAKE_BYTES + 1;
    // Length of both arrays should be 17, since Near stakes are 16 bytes length (u128 type)
    // plus one byte to store carry bits.
    let v1_length = builder.add_virtual_target();
    let v2_length = builder.add_virtual_target();
    pw.set_target(v1_length, F::from_canonical_usize(v1_targets.len()));
    pw.set_target(v2_length, F::from_canonical_usize(v2_targets.len()));
    let length = builder.constant(F::from_canonical_usize(LEN));
    builder.connect(v1_length, length);
    builder.connect(v2_length, length);
    // Check that MSB is less than 100 for both values.
    // Set values that indicates a negative difference.
    // Negative difference could be in two forms: -1 and {-2, -255}.
    let constant1 = builder.constant(F::from_canonical_u64(0xFFFFFFFEFFFFFF00));
    let constant2 = builder.constant(F::from_canonical_u64(0xFFFFFFFF00000000));
    let seven = builder.constant(F::from_canonical_u8(7));
    let h = builder.constant(F::from_canonical_u8(100));
    // Check MSB for v1_targets.
    {
        // The difference should be negative.
        let sub = builder.sub(v1_targets[LEN - 1], h);
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
    // Check MSB for v2_targets.
    {
        // The difference should be negative.
        let sub = builder.sub(v2_targets[LEN - 1], h);
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
    // Compute 3 * value1.
    let mut v1_three_targets: Vec<Target> = builder.add_virtual_targets(v1_targets.len());
    let three = builder.constant(F::from_canonical_u8(3));
    let mut c = builder.zero();
    for i in 0..LEN {
        let t = builder.mul_add(v1_targets[i as usize], three, c);
        let bits = builder.split_le(t, 64);
        v1_three_targets[i as usize] = builder.le_sum(bits[0..8].iter());
        c = builder.le_sum(bits[8..16].iter());
    }
    v1_three_targets.push(c);
    // Compute 2 * value2.
    let mut v2_two_targets: Vec<Target> = builder.add_virtual_targets(v2_targets.len());
    let two = builder.two();
    let mut c = builder.zero();
    for i in 0..LEN {
        let t = builder.mul_add(v2_targets[i as usize], two, c);
        let bits = builder.split_le(t, 64);
        v2_two_targets[i as usize] = builder.le_sum(bits[0..8].iter());
        c = builder.le_sum(bits[8..16].iter());
    }
    v2_two_targets.push(c);
    // Comparison: 3*value1 >= 2*value2.
    let mut prev = (BoolTarget::new_unsafe(zero), BoolTarget::new_unsafe(zero));
    let mut res: Vec<Target> = builder.add_virtual_targets(LEN);
    let mut i: isize = (LEN - 1) as isize;
    while i >= 0 {
        // Сheck the equality of elements of two arrays.
        let if_equal = builder.is_equal(v1_three_targets[i as usize], v2_two_targets[i as usize]);
        // Сheck if the difference is positive or negative.
        // In the case of positive difference if_negative is zero, and seven otherwise.
        let if_negative = {
            // Note, we operate with 64-bit elements in the field.
            // In the case of negative difference we get a positive value of the form: order() - v2_two_targets[i].
            let sub = builder.sub(v1_three_targets[i as usize], v2_two_targets[i as usize]);
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
        // The first element is set according to the if_negative flag.
        if (i as usize) == LEN - 1 {
            res[i as usize] = builder.select(
                if_negative,
                v2_two_targets[i as usize],
                v1_three_targets[i as usize],
            );
            // Store if_equal and if_negative flags.
            prev = (if_equal, if_negative);
        } else {
            // If prev=(false, false), res[i] is set to v1_three_targets[i].
            // If prev=(true, false) or (false, true), then prev is set according to new if_equal and if_negative.
            // res[i] is set to according to the if_negative flag.
            prev = {
                let q = builder.is_equal(prev.0.target, prev.1.target);
                let tmp1 = builder.select(q, prev.0.target, if_equal.target);
                let tmp2 = builder.select(q, prev.1.target, if_negative.target);
                (BoolTarget::new_unsafe(tmp1), BoolTarget::new_unsafe(tmp2))
            };
            res[i as usize] = builder.select(
                prev.1,
                v2_two_targets[i as usize],
                v1_three_targets[i as usize],
            );
        };
        i -= 1;
    }
    // Check if res containes the values from v1_three_targets.
    for i in 0..LEN {
        builder.connect(v1_three_targets[i], res[i]);
    }
    builder.register_public_inputs(&v1_targets);
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
    use super::*;
    use anyhow::Result;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use rand::random;

    #[test]
    fn test_two_thirds() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        // choose 1/3 to check whether func works with 2/3 of the value
        let v1_3: u128 = random::<u64>() as u128;
        let v: u128 = v1_3 * 3;
        // more then 2/3
        let v1: u128 = ((v / 3) * 2) + 5;
        let mut v_bytes = v.to_le_bytes().to_vec();
        let mut v_i_bytes = v1.to_le_bytes().to_vec();
        v_bytes.push(0);
        v_i_bytes.push(0);

        let (data, proof) = two_thirds::<F, C, D>(&v_i_bytes, &v_bytes)?;
        data.verify(proof)
    }

    #[test]
    #[should_panic]
    fn test_two_thirds_when_stake2_targets_is_bigger_stake1_targets() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        // choose 1/3 to check whether func works with 2/3 of the value
        let v1_3: u128 = random::<u64>() as u128;
        let v: u128 = v1_3 * 3;
        // less then 2/3
        let v1: u128 = ((v / 3) * 2) - 5;

        let mut v_bytes = v.to_le_bytes().to_vec();
        let mut v_i_bytes = v1.to_le_bytes().to_vec();
        v_bytes.push(0);
        v_i_bytes.push(0);

        let (data, proof) = two_thirds::<F, C, D>(&v_i_bytes, &v_bytes).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_two_thirds_when_stake1_targets_is_equal_to_stake2_targets() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        // choose 1/3 to check whether func works with 2/3 of the value
        let v1_3: u128 = random::<u64>() as u128;
        let v: u128 = v1_3 * 3;
        // 2/3
        let v1: u128 = (v / 3) * 2;

        let mut v_bytes = v.to_le_bytes().to_vec();
        let mut v_i_bytes = v1.to_le_bytes().to_vec();
        v_bytes.push(0);
        v_i_bytes.push(0);

        let (data, proof) = two_thirds::<F, C, D>(&v_i_bytes, &v_bytes)?;
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

    #[test]
    #[should_panic]
    fn test_not_equal() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let s1 = "hello".to_string();
        let s2 = "olleh".to_string();
        let (data, proof) = prove_eq_array::<F, C, D>(s1.as_bytes(), s2.as_bytes()).unwrap();
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_heights() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let a: u64 = random::<u64>();
        let b: u64 = a - 1;
        let a_bytes = a.to_le_bytes().to_vec();
        let b_bytes = b.to_le_bytes().to_vec();

        println!("a: {:#?}", a_bytes);
        println!("b: {:#?}", b_bytes);

        let (data, proof) = prove_consecutive_heights::<F, C, D>(&a_bytes, &b_bytes)?;
        data.verify(proof)
    }
}

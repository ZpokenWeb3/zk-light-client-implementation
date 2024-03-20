use num::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};
use plonky2_u32::witness::WitnessU32;

#[derive(Clone, Copy, Debug)]
pub struct U64Target {
    pub hi: U32Target,
    pub lo: U32Target,
}

pub type Hash512Target = [U64Target; 8];

#[derive(Clone, Debug)]
pub struct HashTarget {
    pub input_bits: usize,
    pub input: Vec<U64Target>,
    pub output: Vec<U64Target>,
    pub blocks: Vec<BoolTarget>,
}

#[derive(Clone, Debug)]
pub struct HashInputTarget {
    pub input: Vec<U64Target>,
    pub input_bits: usize,
    pub blocks: Vec<BoolTarget>,
}

pub type HashOutputTarget = Vec<U64Target>;

fn read_u32_be_at(array: &[u8], index: usize) -> u32 {
    ((array[index] as u32) << 24)
        + ((array[index + 1] as u32) << 16)
        + ((array[index + 2] as u32) << 8)
        + (array[index + 3] as u32)
}

fn read_u64_be_at(array: &[u8], index: usize) -> (u32, u32) {
    let hi = read_u32_be_at(array, index);
    let lo = read_u32_be_at(array, index + 4);
    (hi, lo)
}

pub trait WitnessHash<F: PrimeField64>: Witness<F> {
    fn set_biguint64_target(&mut self, target: &[U64Target], value: &BigUint);

    fn set_hash_input_target(&mut self, target: &HashInputTarget, value: &BigUint);
    fn set_hash_output_target(&mut self, target: &HashOutputTarget, value: &BigUint);

    fn set_hash512_target(&mut self, target: &Hash512Target, value: &[u8; 64]);
}

impl<T: Witness<F>, F: PrimeField64> WitnessHash<F> for T {
    fn set_biguint64_target(&mut self, target: &[U64Target], value: &BigUint) {
        let mut elem = value.to_u64_digits();
        elem.reverse();
        elem.resize(target.len(), 0);
        for i in 0..elem.len() {
            self.set_u32_target(target[i].lo, (elem[i] & 0xFFFFFFFF) as u32);
            self.set_u32_target(target[i].hi, (elem[i] >> 32) as u32);
        }
    }

    fn set_hash_input_target(&mut self, target: &HashInputTarget, value: &BigUint) {
        self.set_biguint64_target(&target.input, value);
    }

    fn set_hash_output_target(&mut self, target: &HashOutputTarget, value: &BigUint) {
        self.set_biguint64_target(target, value);
    }

    fn set_hash512_target(&mut self, target: &Hash512Target, value: &[u8; 64]) {
        let (mut hi, mut lo) = read_u64_be_at(value, 0);
        self.set_u32_target(target[0].hi, hi);
        self.set_u32_target(target[0].lo, lo);
        (hi, lo) = read_u64_be_at(value, 8);
        self.set_u32_target(target[1].hi, hi);
        self.set_u32_target(target[1].lo, lo);
        (hi, lo) = read_u64_be_at(value, 16);
        self.set_u32_target(target[2].hi, hi);
        self.set_u32_target(target[2].lo, lo);
        (hi, lo) = read_u64_be_at(value, 24);
        self.set_u32_target(target[3].hi, hi);
        self.set_u32_target(target[3].lo, lo);
        (hi, lo) = read_u64_be_at(value, 32);
        self.set_u32_target(target[4].hi, hi);
        self.set_u32_target(target[4].lo, lo);
        (hi, lo) = read_u64_be_at(value, 40);
        self.set_u32_target(target[5].hi, hi);
        self.set_u32_target(target[5].lo, lo);
        (hi, lo) = read_u64_be_at(value, 48);
        self.set_u32_target(target[6].hi, hi);
        self.set_u32_target(target[6].lo, lo);
        (hi, lo) = read_u64_be_at(value, 56);
        self.set_u32_target(target[7].hi, hi);
        self.set_u32_target(target[7].lo, lo);
    }
}

pub trait CircuitBuilderHash<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_hash_input_target(
        &mut self,
        blocks_num: usize,
        blocks_input_bits: usize,
    ) -> HashInputTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHash<F, D>
for CircuitBuilder<F, D>
{
    fn add_virtual_hash_input_target(
        &mut self,
        blocks_num: usize,
        blocks_input_bits: usize,
    ) -> HashInputTarget {
        let input_bits = blocks_input_bits * blocks_num;
        let mut input: Vec<U64Target> = vec![];
        for _ in 0..(input_bits / 64) {
            input.push(U64Target { hi: self.add_virtual_u32_target(), lo: self.add_virtual_u32_target() });
        }
        let mut blocks = Vec::new();
        for _ in 0..blocks_num - 1 {
            blocks.push(self.add_virtual_bool_target_unsafe());
        }
        HashInputTarget {
            input_bits,
            input,
            blocks,
        }
    }
}

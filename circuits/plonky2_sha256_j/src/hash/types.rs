use num::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::biguint::{BigUintTarget, CircuitBuilderBiguint, WitnessBigUint};
use crate::u32::arithmetic_u32::CircuitBuilderU32;
use crate::u32::witness::WitnessU32;

#[derive(Clone, Debug)]
pub struct HashTarget {
    pub input_bits: usize,
    pub input: BigUintTarget,
    pub output: BigUintTarget,
    pub blocks: Vec<BoolTarget>,
}

#[derive(Clone, Debug)]
pub struct HashInputTarget {
    pub input: BigUintTarget,
    pub input_bits: usize,
    pub blocks: Vec<BoolTarget>,
}

pub type HashOutputTarget = BigUintTarget;

pub trait WitnessHash<F: PrimeField64>: Witness<F> {
    fn set_biguint_u32_be_target(&mut self, target: &BigUintTarget, value: &BigUint);

    fn set_hash_input_be_target(&mut self, target: &HashInputTarget, value: &BigUint);
    fn set_hash_output_be_target(&mut self, target: &HashOutputTarget, value: &BigUint);

    fn set_hash_input_le_target(&mut self, target: &HashInputTarget, value: &BigUint);
    fn set_hash_output_le_target(&mut self, target: &HashOutputTarget, value: &[u8]);

    fn set_hash_blocks_target(&mut self, target: &HashInputTarget, num_blocks: usize);
}

impl<T: Witness<F>, F: PrimeField64> WitnessHash<F> for T {
    fn set_biguint_u32_be_target(&mut self, target: &BigUintTarget, value: &BigUint) {
        // similar to self.set_biguint_target()
        // but need u32 in big-endian
        let mut limbs = value.to_u32_digits();
        assert!(target.num_limbs() >= limbs.len());
        limbs.resize(target.num_limbs(), 0);
        for (i, item) in limbs.iter().enumerate().take(target.num_limbs()) {
            // set target with u32 in big-endian
            self.set_u32_target(target.limbs[i], item.to_be());
        }
    }

    fn set_hash_input_be_target(&mut self, target: &HashInputTarget, value: &BigUint) {
        self.set_biguint_u32_be_target(&target.input, value);
    }

    fn set_hash_output_be_target(&mut self, target: &HashOutputTarget, value: &BigUint) {
        self.set_biguint_u32_be_target(target, value);
    }

    fn set_hash_input_le_target(&mut self, target: &HashInputTarget, value: &BigUint) {
        self.set_biguint_target(&target.input, value);
    }

    fn set_hash_output_le_target(&mut self, target: &HashOutputTarget, value: &[u8]) {
        let output_biguint = BigUint::from_bytes_le(value);
        self.set_biguint_target(target, &output_biguint);
    }

    fn set_hash_blocks_target(&mut self, target: &HashInputTarget, num_blocks: usize) {
        for (i, t) in target.blocks.iter().enumerate() {
            self.set_bool_target(*t, i < num_blocks - 1);
        }
    }
}

pub trait CircuitBuilderHash<F: RichField + Extendable<D>, const D: usize> {
    // return a BigUintTarget with len limbs, all set to zero
    // note that biguint_zero() returns a single limb
    fn hash_zero(&mut self, len: usize) -> BigUintTarget;

    // connect rhs limb by limb into lhs, starting at a given offset
    // note that connect_biguint() auto extends the number of limbs
    fn connect_hash_input(
        &mut self,
        gadget_input: &HashInputTarget,
        provided_input: &BigUintTarget,
        gadget_offset: usize,
    );

    fn add_virtual_hash_target(
        &mut self,
        blocks_num: usize,
        blocks_input_bits: usize,
        output_bits: usize,
    ) -> HashTarget;

    fn add_virtual_hash_input_target(
        &mut self,
        blocks_num: usize,
        blocks_input_bits: usize,
    ) -> HashInputTarget;

    fn add_virtual_hash_public_input(
        &mut self,
        blocks_num: usize,
        blocks_input_bits: usize,
        output_bits: usize,
    ) -> HashTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHash<F, D>
    for CircuitBuilder<F, D>
{
    fn hash_zero(&mut self, len: usize) -> BigUintTarget {
        let zero_u32 = self.zero_u32();
        let zero = self.add_virtual_biguint_target(len);
        for &limb in zero.limbs.iter() {
            self.connect_u32(limb, zero_u32);
        }
        zero
    }

    fn connect_hash_input(
        &mut self,
        gadget_input: &HashInputTarget,
        provided_input: &BigUintTarget,
        gadget_offset: usize,
    ) {
        for (i, &limb) in provided_input.limbs.iter().enumerate() {
            self.connect_u32(gadget_input.input.limbs[gadget_offset + i], limb);
        }
    }

    fn add_virtual_hash_target(
        &mut self,
        blocks_num: usize,
        blocks_input_bits: usize,
        output_bits: usize,
    ) -> HashTarget {
        let input_bits = blocks_input_bits * blocks_num;
        let input = self.add_virtual_biguint_target(input_bits / 32);
        let output = self.add_virtual_biguint_target(output_bits / 32);
        let mut blocks = Vec::new();
        for _ in 0..blocks_num - 1 {
            blocks.push(self.add_virtual_bool_target_unsafe());
        }

        HashTarget {
            input_bits,
            input,
            output,
            blocks,
        }
    }

    fn add_virtual_hash_input_target(
        &mut self,
        blocks_num: usize,
        blocks_input_bits: usize,
    ) -> HashInputTarget {
        let input_bits = blocks_input_bits * blocks_num;
        let input = self.add_virtual_biguint_target(input_bits / 32);
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

    fn add_virtual_hash_public_input(
        &mut self,
        blocks_num: usize,
        blocks_input_bits: usize,
        output_bits: usize,
    ) -> HashTarget {
        let hash_target = self.add_virtual_hash_target(blocks_num, blocks_input_bits, output_bits);

        for i in 0..hash_target.input.num_limbs() {
            self.register_public_input(hash_target.input.limbs[i].0);
        }

        for i in 0..hash_target.output.num_limbs() {
            self.register_public_input(hash_target.output.limbs[i].0);
        }

        hash_target
    }
}

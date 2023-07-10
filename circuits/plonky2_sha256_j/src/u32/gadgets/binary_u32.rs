extern crate alloc;
use alloc::vec::Vec;

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::u32::gadgets::arithmetic_u32::U32Target;

/// Bin32Target is an inefficient representation of 32x BoolTargets
/// Whenever possible, use interleaved_u32::B32Target instead
#[derive(Clone, Debug)]
pub struct Bin32Target {
    pub bits: Vec<BoolTarget>,
}

pub trait CircuitBuilderBU32<F: RichField + Extendable<D>, const D: usize> {
    // methods on Bin32Target
    fn xor_bin32(&mut self, a: &Bin32Target, b: &Bin32Target) -> Bin32Target;
    fn and_bin32(&mut self, a: &Bin32Target, b: &Bin32Target) -> Bin32Target;

    // conversion methods
    fn convert_u32_bin32(&mut self, a: U32Target) -> Bin32Target;
    fn convert_bin32_u32(&mut self, a: Bin32Target) -> U32Target;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderBU32<F, D>
    for CircuitBuilder<F, D>
{
    fn convert_u32_bin32(&mut self, a: U32Target) -> Bin32Target {
        Bin32Target {
            bits: self.split_le(a.0, 32),
        }
    }

    fn convert_bin32_u32(&mut self, a: Bin32Target) -> U32Target {
        U32Target(self.le_sum(a.bits.iter()))
    }

    fn xor_bin32(&mut self, a: &Bin32Target, b: &Bin32Target) -> Bin32Target {
        Bin32Target {
            bits: a
                .bits
                .iter()
                .zip(b.bits.iter())
                .map(|(a, b)| {
                    // a ^ b := (a - b)^2
                    let s = self.sub(a.target, b.target);
                    BoolTarget::new_unsafe(self.mul(s, s))
                })
                .collect(),
        }
    }

    fn and_bin32(&mut self, a: &Bin32Target, b: &Bin32Target) -> Bin32Target {
        Bin32Target {
            bits: a
                .bits
                .iter()
                .zip(b.bits.iter())
                .map(|(a, b)| {
                    // a & b := a * b
                    BoolTarget::new_unsafe(self.mul(a.target, b.target))
                })
                .collect(),
        }
    }
}

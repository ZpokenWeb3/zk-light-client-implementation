use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::ops::Range;

use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::gates::gate::Gate;
use plonky2::gates::packed_util::PackedEvaluableBase;
use plonky2::gates::util::StridedConstraintConsumer;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator, WitnessGeneratorRef};
use plonky2::iop::target::Target;
use plonky2::iop::wire::Wire;
use plonky2::iop::witness::{PartitionWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData};
use plonky2::plonk::plonk_common::{reduce_with_powers, reduce_with_powers_ext_circuit};
use plonky2::plonk::vars::{
    EvaluationTargets, EvaluationVars, EvaluationVarsBase, EvaluationVarsBaseBatch,
    EvaluationVarsBasePacked,
};
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};

/// TODO: This code is grossly redundant to uninterleave_to_u32.rs, the diff is literally four lines (the calculation of coeff)
/// Just wanted something up quickly, a cleaner more future-proof solution would be to make this one gate with
/// a type-parameterized base to use when calculating the values for the conversion targets. If we ever try to substantially refactor
/// the uninterleave gates we should probably switch to this design before writing a new implementation.
///
/// Note: This gate should not be used for arbitrary targets, its specific use case
/// is to be applied to the sum of two B32Targets.
///
/// Given a Goldilocks field element, treat it as 0bxyxyxy...
/// and split it into two B32Targets, 0b0x0x0x... and 0b0y0y0y...
#[derive(Copy, Clone, Debug)]
pub struct UninterleaveToB32Gate {
    pub num_ops: usize,
}

impl UninterleaveToB32Gate {
    pub fn new_from_config(config: &CircuitConfig) -> Self {
        Self {
            num_ops: Self::num_ops(config),
        }
    }

    pub(crate) fn num_ops(config: &CircuitConfig) -> usize {
        let wires_per_op = Self::wires_per_op();
        (config.num_wires / wires_per_op).min(config.num_routed_wires / Self::routed_wires_per_op())
    }

    pub fn wires_per_op() -> usize {
        Self::NUM_BITS + Self::routed_wires_per_op()
    }

    pub fn routed_wires_per_op() -> usize {
        3
    }

    // These could be consts, but let's make them as functions so we can more easily
    // extend to multiple operations in the gate in an optimized version if needed.
    // This gate uses 67 wires, so we should be able to fit in two of them in the standard config
    pub fn wire_ith_x_interleaved(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        Self::routed_wires_per_op() * i
    }

    pub fn wire_ith_x_evens(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        Self::routed_wires_per_op() * i + 1
    }

    pub fn wire_ith_x_odds(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        Self::routed_wires_per_op() * i + 2
    }

    // A more general solution would be to parameterize NUM_BITS, but we only care
    // about 32 bit operations for sha256, as well as keccak for now
    pub const NUM_BITS: usize = 64;
    pub const B: usize = 2; // If we want we can make this a type parameter, as in https://github.com/mir-protocol/plonky2/blob/main/plonky2/src/gates/base_sum.rs

    /// TODO: Do we need to indicate that these don't have to be wirable, or can the builder figure it out on its own?
    /// I suspect that we might have to figure out how to prevent the builder from placing these in wirable columns.
    /// They shouldn't be constants since we have to supply them in the witness.
    ///
    /// This represents the full binary representation of the interleaved input x
    ///
    /// Make sure the inputs are big-endian — this is out of line with the rest of the plonky2 repo, but we
    /// specifically need our interleaved representation to be big-endian in order to fit in the field, so
    /// it's better to be explicit about this from the beginning when assigning the wire values
    pub fn wires_ith_bit_decomposition(&self, i: usize) -> Range<usize> {
        let start = self.num_ops * Self::routed_wires_per_op();
        (start + Self::NUM_BITS * i)..(start + Self::NUM_BITS * (i + 1))
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Gate<F, D> for UninterleaveToB32Gate {
    fn id(&self) -> String {
        format!("{self:?}")
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_usize(self.num_ops)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let num_ops = src.read_usize()?;
        Ok(Self { num_ops })
    }

    fn eval_unfiltered(&self, vars: EvaluationVars<F, D>) -> Vec<F::Extension> {
        let mut constraints = vec![];

        for i in 0..self.num_ops {
            let x_interleaved = vars.local_wires[self.wire_ith_x_interleaved(i)];
            let bits = vars.local_wires[self.wires_ith_bit_decomposition(i)].to_vec();

            // Check 1: Ensure that the decomposition matches the input
            // Remember that the bits are big-endian. The reduce_with_powers function takes a little-endian representation, so we reverse the input.
            // The function just reverses it back again when it does the computation but it's cleaner to re-use the existing code, this isn't a bottleneck
            let computed_x_interleaved = reduce_with_powers(
                bits.iter().rev(),
                F::Extension::from_canonical_usize(Self::B),
            );
            constraints.push(computed_x_interleaved - x_interleaved);

            // Check 2: Ensure that the even-index bits in the decomposition match the x_evens value
            let x_evens = vars.local_wires[self.wire_ith_x_evens(i)];
            let x_odds = vars.local_wires[self.wire_ith_x_odds(i)];

            let mut computed_x_evens = F::Extension::ZERO;
            let mut computed_x_odds = F::Extension::ZERO;

            for j in 0..Self::NUM_BITS / 2 {
                let jth_even = bits[2 * j];
                let jth_odd = bits[2 * j + 1];

                let coeff =
                    F::Extension::from_canonical_u64(1 << (2 * (Self::NUM_BITS / 2 - j - 1)));
                computed_x_evens += coeff * jth_even;
                computed_x_odds += coeff * jth_odd;
            }

            constraints.push(computed_x_evens - x_evens);
            constraints.push(computed_x_odds - x_odds);

            // Check 3: Range check the targets in the decomposition
            for bit in bits.iter() {
                constraints.push(
                    (0..Self::B)
                        .map(|j| *bit - F::Extension::from_canonical_usize(j))
                        .product(),
                )
            }
        }

        constraints
    }

    fn eval_unfiltered_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: EvaluationTargets<D>,
    ) -> Vec<ExtensionTarget<D>> {
        let base = builder.constant(F::from_canonical_usize(Self::B));
        let mut constraints = vec![];

        for i in 0..self.num_ops {
            let x_interleaved = vars.local_wires[self.wire_ith_x_interleaved(i)];
            let bits = vars.local_wires[self.wires_ith_bit_decomposition(i)].to_vec();
            let bits_reversed: Vec<ExtensionTarget<D>> = bits.clone().into_iter().rev().collect();

            // Check 1: Ensure that the decomposition matches the input
            // Remember that the bits are big-endian. The reduce_with_powers function takes a little-endian representation, so we reverse the input.
            // The function just reverses it back again when it does the computation but it's cleaner to re-use the existing code, this isn't a bottleneck
            let computed_x_interleaved =
                reduce_with_powers_ext_circuit(builder, &bits_reversed, base);
            constraints.push(builder.sub_extension(computed_x_interleaved, x_interleaved));

            // Check 2: Ensure that the even-index bits in the decomposition match the x_evens value, same for odds
            let x_evens = vars.local_wires[self.wire_ith_x_evens(i)];
            let x_odds = vars.local_wires[self.wire_ith_x_odds(i)];

            let mut computed_x_evens = builder.zero_extension();
            let mut computed_x_odds = builder.zero_extension();

            for i in 0..Self::NUM_BITS / 2 {
                let ith_even = bits[2 * i];
                let ith_odd = bits[2 * i + 1];

                let coeff = builder.constant_extension(F::Extension::from_canonical_u64(
                    1 << (2 * (Self::NUM_BITS / 2 - i - 1)),
                ));
                computed_x_evens = builder.mul_add_extension(coeff, ith_even, computed_x_evens);
                computed_x_odds = builder.mul_add_extension(coeff, ith_odd, computed_x_odds);
            }
            constraints.push(builder.sub_extension(computed_x_evens, x_evens));
            constraints.push(builder.sub_extension(computed_x_odds, x_odds));

            // Check 3: Range check the targets in the decomposition
            for bit in bits {
                constraints.push({
                    let mut acc = builder.one_extension();
                    (0..Self::B).for_each(|i| {
                        // We update our accumulator as:
                        // acc' = acc (x - i)
                        //      = acc x + (-i) acc
                        // Since -i is constant, we can do this in one arithmetic_extension call.
                        let neg_i = -F::from_canonical_usize(i);
                        acc = builder.arithmetic_extension(F::ONE, neg_i, acc, bit, acc);
                    });
                    acc
                });
            }
        }

        constraints
    }

    fn eval_unfiltered_base_one(
        &self,
        _vars: EvaluationVarsBase<F>,
        _yield_constr: StridedConstraintConsumer<F>,
    ) {
        panic!("use eval_unfiltered_base_packed instead");
    }

    fn eval_unfiltered_base_batch(&self, vars_base: EvaluationVarsBaseBatch<F>) -> Vec<F> {
        self.eval_unfiltered_base_batch_packed(vars_base)
    }

    fn generators(&self, row: usize, _local_constants: &[F]) -> Vec<WitnessGeneratorRef<F, D>> {
        (0..self.num_ops)
            .map(|i| {
                WitnessGeneratorRef::new(
                    UninterleaveToB32Generator {
                        gate: *self,
                        row,
                        i,
                    }
                    .adapter(),
                )
            })
            .collect()
    }

    fn num_wires(&self) -> usize {
        self.num_ops * Self::wires_per_op()
    }

    fn num_constants(&self) -> usize {
        0
    }

    fn degree(&self) -> usize {
        Self::B
    }

    fn num_constraints(&self) -> usize {
        self.num_ops * (Self::NUM_BITS + 1 + 2)
    }
}

impl<F: RichField + Extendable<D>, const D: usize> PackedEvaluableBase<F, D>
    for UninterleaveToB32Gate
{
    fn eval_unfiltered_base_packed<P: PackedField<Scalar = F>>(
        &self,
        vars: EvaluationVarsBasePacked<P>,
        mut yield_constr: StridedConstraintConsumer<P>,
    ) {
        for i in 0..self.num_ops {
            let x_interleaved = vars.local_wires[self.wire_ith_x_interleaved(i)];
            let bits = vars.local_wires.view(self.wires_ith_bit_decomposition(i));

            // Check 1: Ensure that the decomposition matches the input
            // Remember that the bits are big-endian. The reduce_with_powers function takes a little-endian representation, so we reverse the input.
            // The function just reverses it back again when it does the computation but it's cleaner to re-use the existing code, this isn't a bottleneck
            let computed_x_interleaved =
                reduce_with_powers(bits.iter().rev(), F::from_canonical_usize(Self::B));
            yield_constr.one(computed_x_interleaved - x_interleaved);

            // Check 2: Ensure that the even-index bits in the decomposition match the x_evens value
            let x_evens = vars.local_wires[self.wire_ith_x_evens(i)];
            let x_odds = vars.local_wires[self.wire_ith_x_odds(i)];

            let mut computed_x_evens = P::ZEROS;
            let mut computed_x_odds = P::ZEROS;

            for i in 0..Self::NUM_BITS / 2 {
                let ith_even_bit = bits[2 * i];
                let ith_odd_bit = bits[2 * i + 1];

                let coeff = P::Scalar::from_canonical_u64(1 << (2 * (Self::NUM_BITS / 2 - i - 1)));
                computed_x_evens += ith_even_bit * coeff;
                computed_x_odds += ith_odd_bit * coeff;
            }

            yield_constr.one(computed_x_evens - x_evens);
            yield_constr.one(computed_x_odds - x_odds);

            // Check 3: Range check the targets in the decomposition
            let constraints_iter = bits.iter().map(|&bit| {
                (0..Self::B)
                    .map(|i| bit - F::from_canonical_usize(i))
                    .product::<P>()
            });
            yield_constr.many(constraints_iter);
        }
    }
}

#[derive(Debug, Clone)]
pub struct UninterleaveToB32Generator {
    gate: UninterleaveToB32Gate,
    row: usize,
    i: usize,
}

// Populate the bit wires and the x_interleaved wire, given that the x wire's value has been set
impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for UninterleaveToB32Generator
{
    fn id(&self) -> String {
        "UninterleaveToB32Generator".to_string()
    }

    fn dependencies(&self) -> Vec<Target> {
        let local_target = |column| Target::wire(self.row, column);

        vec![local_target(self.gate.wire_ith_x_interleaved(self.i))]
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let local_wire = |column| Wire {
            row: self.row,
            column,
        };

        let get_local_wire = |column| witness.get_wire(local_wire(column));

        // Reminder: treat x as big-endian
        let x_interleaved =
            get_local_wire(self.gate.wire_ith_x_interleaved(self.i)).to_canonical_u64();
        let mut x_evens = 0u64;
        let mut x_odds = 0u64;

        let num_bits = UninterleaveToB32Gate::NUM_BITS;
        let start_bits = self.gate.num_ops * UninterleaveToB32Gate::routed_wires_per_op();

        for j in 0..num_bits / 2 {
            let shift = 2 * (num_bits / 2 - j - 1);
            let jth_even = (x_interleaved >> (shift + 1)) % 2;
            let jth_odd = (x_interleaved >> shift) % 2;

            // Fill in the wire values for the bits
            let even_bit_wire = local_wire(2 * j + start_bits + num_bits * self.i);
            let odd_bit_wire = local_wire(2 * j + 1 + start_bits + num_bits * self.i);
            out_buffer.set_wire(even_bit_wire, F::from_canonical_u64(jth_even));
            out_buffer.set_wire(odd_bit_wire, F::from_canonical_u64(jth_odd));

            let coeff = 1 << (2 * (num_bits / 2 - j - 1));
            x_evens += jth_even * coeff;
            x_odds += jth_odd * coeff;
        }

        let x_evens_wire = local_wire(self.gate.wire_ith_x_evens(self.i));
        let x_odds_wire = local_wire(self.gate.wire_ith_x_odds(self.i));
        out_buffer.set_wire(x_evens_wire, F::from_canonical_u64(x_evens));
        out_buffer.set_wire(x_odds_wire, F::from_canonical_u64(x_odds));
    }

    fn serialize(&self, dst: &mut Vec<u8>, common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        self.gate.serialize(dst, common_data)?;
        dst.write_usize(self.row)?;
        dst.write_usize(self.i)
    }

    fn deserialize(src: &mut Buffer, common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let gate = UninterleaveToB32Gate::deserialize(src, common_data)?;
        let row = src.read_usize()?;
        let i = src.read_usize()?;
        Ok(Self { gate, row, i })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::gates::gate_testing::{test_eval_fns, test_low_degree};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use super::*;

    #[test]
    fn low_degree() {
        test_low_degree::<GoldilocksField, _, 2>(UninterleaveToB32Gate { num_ops: 2 })
    }

    // TODO: not working. Don't really know what this does, just seems to be a standard test for gates
    #[test]
    fn eval_fns() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        test_eval_fns::<F, C, _, D>(UninterleaveToB32Gate { num_ops: 2 })
    }
}

use core::ops::Range;

use plonky2::field::extension::Extendable;
use plonky2::field::packed::PackedField;
use plonky2::field::types::Field;
use plonky2::gates::gate::Gate;
use plonky2::gates::packed_util::PackedEvaluableBase;
use plonky2::gates::util::StridedConstraintConsumer;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator, WitnessGenerator};
use plonky2::iop::target::Target;
use plonky2::iop::wire::Wire;
use plonky2::iop::witness::{PartitionWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::plonk_common::{reduce_with_powers, reduce_with_powers_ext_circuit};
use plonky2::plonk::vars::{
    EvaluationTargets, EvaluationVars, EvaluationVarsBase, EvaluationVarsBaseBatch,
    EvaluationVarsBasePacked,
};

/// Take a target x, which we assume is constrained to be a U32, and interleave it with zeroes (allows efficient XOR and AND)
///
/// If we're careful to use a big-endian representation, then the first digit of this result
/// will always be 0, so it can safely fit inside a single Goldilocks field element
///
/// An example
///   x:             b0000_0000_0000_0000_1111_0111_0011_1110
///   x_interleaved: b0101_0101_0001_0101_0000_0101_0101_0100
#[derive(Copy, Clone, Debug)]
pub struct U32InterleaveGate {
    pub num_ops: usize,
}

impl U32InterleaveGate {
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
        2
    }

    // These could be consts, but let's make them as functions so we can more easily
    // extend to multiple operations in the gate in an optimized version
    pub fn wire_ith_x(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        Self::routed_wires_per_op() * i
    }

    pub fn wire_ith_x_interleaved(&self, i: usize) -> usize {
        debug_assert!(i < self.num_ops);
        Self::routed_wires_per_op() * i + 1
    }

    pub const START_BITS: usize = 2;
    // A more general solution would be to parameterize NUM_BITS, but we only care
    // about 32 bit operations for sha256, as well as keccak for now
    pub const NUM_BITS: usize = 32;
    pub const B: usize = 2; // If we want we can make this a type parameter, as in https://github.com/mir-protocol/plonky2/blob/main/plonky2/src/gates/base_sum.rs

    /// Make sure the inputs are big-endian — this is out of line with the rest of the plonky2 repo, but we
    /// specifically need our interleaved representation to be big-endian in order to fit in the field, so
    /// it's better to be explicit about this from the beginning when assigning the wire values
    pub fn wires_ith_bit_decomposition(&self, i: usize) -> Range<usize> {
        let start = self.num_ops * Self::routed_wires_per_op();
        (start + Self::NUM_BITS * i)..(start + Self::NUM_BITS * (i + 1))
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Gate<F, D> for U32InterleaveGate {
    fn id(&self) -> String {
        format!("{self:?}")
    }

    fn eval_unfiltered(&self, vars: EvaluationVars<F, D>) -> Vec<F::Extension> {
        let mut constraints = vec![];

        for i in 0..self.num_ops {
            let x = vars.local_wires[self.wire_ith_x(i)];
            let bits = vars.local_wires[self.wires_ith_bit_decomposition(i)].to_vec();

            // Check 1: Ensure that the decomposition matches the input
            // Remember that the bits are big-endian. The reduce_with_powers function takes a little-endian representation, so we reverse the input.
            // The function just reverses it back again when it does the computation but it's cleaner to re-use the existing code, this isn't a bottleneck
            let computed_x = reduce_with_powers(
                bits.iter().rev(),
                F::Extension::from_canonical_usize(Self::B),
            );
            constraints.push(computed_x - x);

            // Check 2: Ensure that the bit decomposition matches the interleaved representation
            let x_interleaved = vars.local_wires[self.wire_ith_x_interleaved(i)];

            // Reduce with powers, but using 4 instead of 2 as the base
            let computed_x_interleaved = reduce_with_powers(
                bits.iter().rev(),
                F::Extension::from_canonical_usize(Self::B * Self::B),
            );
            constraints.push(computed_x_interleaved - x_interleaved);

            // Check 3: Range check the targets in the decomposition
            for bit in bits.iter() {
                constraints.push(
                    (0..Self::B)
                        .map(|i| *bit - F::Extension::from_canonical_usize(i))
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
        let base_sq = builder.constant(F::from_canonical_usize(Self::B).square());
        let mut constraints = vec![];

        for i in 0..self.num_ops {
            let x = vars.local_wires[self.wire_ith_x(i)];
            let x_interleaved = vars.local_wires[self.wire_ith_x_interleaved(i)];
            let bits = vars.local_wires[self.wires_ith_bit_decomposition(i)].to_vec();
            let bits_reversed: Vec<ExtensionTarget<D>> = bits.clone().into_iter().rev().collect();

            // Check 1: Ensure that the decomposition matches the input
            // Remember that the bits are big-endian. The reduce_with_powers function takes a little-endian representation, so we reverse the input.
            // The function just reverses it back again when it does the computation but it's cleaner to re-use the existing code, this isn't a bottleneck
            let computed_x = reduce_with_powers_ext_circuit(builder, &bits_reversed, base);
            constraints.push(builder.sub_extension(computed_x, x));

            // Check 2: Ensure that the bit decomposition matches the interleaved representation
            let computed_x_interleaved =
                reduce_with_powers_ext_circuit(builder, &bits_reversed, base_sq);
            constraints.push(builder.sub_extension(computed_x_interleaved, x_interleaved));

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

    fn generators(&self, row: usize, _local_constants: &[F]) -> Vec<Box<dyn WitnessGenerator<F>>> {
        (0..self.num_ops)
            .map(|i| {
                let g: Box<dyn WitnessGenerator<F>> = Box::new(
                    U32InterleaveGenerator {
                        gate: *self,
                        row,
                        i,
                    }
                    .adapter(),
                );
                g
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
        self.num_ops * (Self::NUM_BITS + 1 + 1)
    }
}

impl<F: RichField + Extendable<D>, const D: usize> PackedEvaluableBase<F, D> for U32InterleaveGate {
    fn eval_unfiltered_base_packed<P: PackedField<Scalar = F>>(
        &self,
        vars: EvaluationVarsBasePacked<P>,
        mut yield_constr: StridedConstraintConsumer<P>,
    ) {
        for i in 0..self.num_ops {
            let x = vars.local_wires[self.wire_ith_x(i)];
            let bits = vars.local_wires.view(self.wires_ith_bit_decomposition(i));

            // Check 1: Ensure that the decomposition matches the input
            let computed_x =
                reduce_with_powers(bits.iter().rev(), F::from_canonical_usize(Self::B));

            yield_constr.one(computed_x - x);

            // Check 2: Ensure that the bit decomposition matches the interleaved representation
            let x_interleaved = vars.local_wires[self.wire_ith_x_interleaved(i)];

            // Reduce with powers, but use 4 instead of 2 as the base
            let computed_x_interleaved = reduce_with_powers(
                bits.iter().rev(),
                F::from_canonical_usize(Self::B * Self::B),
            );

            yield_constr.one(computed_x_interleaved - x_interleaved); // TODO: UNCOMMENT THIS LATER

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
pub struct U32InterleaveGenerator {
    gate: U32InterleaveGate,
    row: usize,
    i: usize,
}

// Populate the bit wires and the x_interleaved wire, given that the x wire's value has been set
impl<F: RichField> SimpleGenerator<F> for U32InterleaveGenerator {
    fn dependencies(&self) -> Vec<Target> {
        let local_target = |column| Target::wire(self.row, column);

        vec![local_target(self.gate.wire_ith_x(self.i))]
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let local_wire = |column| Wire {
            row: self.row,
            column,
        };

        let get_local_wire = |column| witness.get_wire(local_wire(column));

        // Reminder: treat x as big-endian
        let x = get_local_wire(self.gate.wire_ith_x(self.i));

        let mut x_interleaved = 0u64;

        let num_bits = U32InterleaveGate::NUM_BITS;

        for (i, bit_wire_index) in self.gate.wires_ith_bit_decomposition(self.i).enumerate() {
            // Get the i'th bit of x
            let bit = (x.to_canonical_u64() >> (num_bits - i - 1)) % 2;
            assert!(bit == 0 || bit == 1); // Sanity check

            // Fill in the wire value for this bit
            let bit_wire = local_wire(bit_wire_index);
            out_buffer.set_wire(bit_wire, F::from_canonical_u64(bit));

            x_interleaved += bit * (1 << (2 * (num_bits - i - 1)));
        }

        let x_interleaved_wire = local_wire(self.gate.wire_ith_x_interleaved(self.i));
        out_buffer.set_wire(x_interleaved_wire, F::from_canonical_u64(x_interleaved));
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
        test_low_degree::<GoldilocksField, _, 2>(U32InterleaveGate { num_ops: 2 })
    }

    #[test]
    fn eval_fns() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        test_eval_fns::<F, C, _, D>(U32InterleaveGate { num_ops: 2 })
    }
}

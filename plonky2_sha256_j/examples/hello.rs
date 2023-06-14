use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::*;
use plonky2_sha256_j::hash::sha256::CircuitBuilderHashSha2;
use plonky2_sha256_j::hash::sha256::WitnessHashSha2;
use plonky2_sha256_j::hash::{CircuitBuilderHash, HashInputTarget, HashOutputTarget};
use std::time::{Duration, Instant};

pub trait CircuitBuilderHello<F: RichField + Extendable<D>, const D: usize> {
    fn double_sha256(&mut self, input: &HashInputTarget) -> HashOutputTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHello<F, D>
    for CircuitBuilder<F, D>
{
    fn double_sha256(&mut self, input: &HashInputTarget) -> HashOutputTarget {
        // build the circuit for the first sha256
        let output1 = self.hash_sha256(input);

        // add an input target for the second sha256
        let input2 = self.add_virtual_hash_input_target(1, 512);

        // wire output1 to input2
        self.connect_hash_input(&input2, &output1, 0);

        // add a constant padding, since we know that output1 is 256-bit
        self.sha256_input_padding(&input2, 256);

        // build the circuit for the second sha256 and return the output
        self.hash_sha256(&input2)
    }
}

fn main() {
    let tests = [
            [
                // 64 bytes input
                "600D54000000000000000000000000000000000000000000000000000000000077F1040000000000000000000000000000000000000000000000000000000000",
                // sha256(sha256(input))
                "29ee05d175e91556b92d7c17919d42247a53096f5b58250faa3ca6ad5cbcefa7",
            ],
            // [
            //     "...",
            //     "...",
            // ],
        ];

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // 0. create the circuit
    let target_input = builder.add_virtual_hash_input_target(2, 512);
    let target_output = builder.hash_sha256(&target_input);
    let num_gates = builder.num_gates();

    // 1. build circuit once
    let now = Instant::now();
    let data = builder.build::<C>();
    let time_build = now.elapsed();

    // 2. generate multiple ZKPs, one per test
    let mut time_prove = Duration::new(0, 0);
    for t in tests {
        let input = hex::decode(t[0]).unwrap();
        let output = hex::decode(t[1]).unwrap();

        // set input/output
        let mut pw = PartialWitness::new();
        pw.set_sha256_input_target(&target_input, &input);
        pw.set_sha256_output_target(&target_output, &output);

        // generate proof
        let now = Instant::now();
        let proof = data.prove(pw).unwrap();
        time_prove += now.elapsed();

        // verify proof
        assert!(data.verify(proof).is_ok());
    }
    time_prove /= tests.len() as u32;
    println!(
        "double_sha256 num_gates={num_gates} time_build={time_build:?} time_prove={time_prove:?}"
    );
}

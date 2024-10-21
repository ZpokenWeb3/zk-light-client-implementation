#![no_main]

use libfuzzer_sys::fuzz_target;
use plonky2::plonk::config::{PoseidonGoldilocksConfig, GenericConfig};
use near_bft_finality::prove_block_data::primitives::prove_eq_array;

fuzz_target!(|data: &[u8]| {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let (data, proof) = prove_eq_array::<F, C, D>(data, data).expect("Error generating proof.");
    assert!(data.verify(proof).is_ok(), "Proof verification failed.");
});

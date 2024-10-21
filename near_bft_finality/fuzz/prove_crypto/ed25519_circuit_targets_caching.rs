#![no_main]

use libfuzzer_sys::fuzz_target;
use ed25519_compact::*;
use plonky2::plonk::{config::{PoseidonGoldilocksConfig, GenericConfig}, circuit_data::CircuitData};
use plonky2_ed25519::gadgets::eddsa::EDDSATargets;
use std::collections::HashMap;
use near_bft_finality::prove_crypto::ed25519::get_ed25519_circuit_targets;

fuzz_target!(|data: &[u8]| {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let msg1 = data.to_vec();
    let msg2 = if data.len() > 0 {
        data[0..(data.len() - 1)].to_vec()
    } else {
        data.to_vec()
    };

    let mut circuit_data_targets: HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)> = HashMap::new();

    let (_data, _targets) = get_ed25519_circuit_targets::<F, C, D>(msg1.len(), &mut circuit_data_targets);
    assert!(circuit_data_targets.len() == 1);
    let (_data, _targets) = get_ed25519_circuit_targets::<F, C, D>(msg2.len(), &mut circuit_data_targets);
    if data.len() > 0 {
        assert!(circuit_data_targets.len() == 2);
    } else {
        assert!(circuit_data_targets.len() == 1);
    }
});

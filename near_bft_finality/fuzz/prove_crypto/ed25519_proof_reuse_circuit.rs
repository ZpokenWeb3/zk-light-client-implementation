#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use plonky2::plonk::{config::{PoseidonGoldilocksConfig, GenericConfig}, circuit_data::CircuitData};
use plonky2_ed25519::gadgets::eddsa::EDDSATargets;
use ed25519_compact::*;
use near_bft_finality::prove_crypto::ed25519::{ed25519_proof_reuse_circuit, ed25519_proof};

fuzz_target!(|data: &[u8]| {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let data_vec = data.to_vec();

    let keys = KeyPair::generate();
    let pk1 = keys.pk.to_vec();
    let sig1 = keys.sk.sign(data_vec.clone(), None).to_vec();

    let mut circuit_data_targets: HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)> = HashMap::new();

    let (d1, p1) = ed25519_proof_reuse_circuit::<F, C, D>(&data_vec, &sig1, &pk1, &mut circuit_data_targets).expect("Error generating proof.");
    d1.verify(p1).expect("Proof verification failed.");
    assert!(circuit_data_targets.len() == 1);
});

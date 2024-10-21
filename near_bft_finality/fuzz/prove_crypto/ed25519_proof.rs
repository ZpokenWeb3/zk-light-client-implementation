#![no_main]

use libfuzzer_sys::fuzz_target;
use ed25519_compact::*;
use plonky2::plonk::config::{PoseidonGoldilocksConfig, GenericConfig};
use near_bft_finality::prove_crypto::ed25519::{get_ed25519_targets, ed25519_proof};

fuzz_target!(|data: &[u8]| {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let data_vec = data.to_vec();

    let keys = KeyPair::generate();
    let pk = keys.pk.to_vec();
    let sig = keys.sk.sign(data_vec.clone(), None).to_vec();

    let (data, targets) = get_ed25519_targets::<F, C, D>(data_vec.len() * 8).expect("Error getting targets.");
    let proof = ed25519_proof::<F, C, D>(&data_vec, &sig, &pk, (data.clone(), targets)).expect("Error generating proof.");
  
    assert!(data.verify(proof).is_ok());
});

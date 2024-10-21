#![no_main]

use libfuzzer_sys::fuzz_target;
use plonky2::plonk::config::{PoseidonGoldilocksConfig, GenericConfig};
use near_primitives::hash::hash;
use near_bft_finality::prove_crypto::sha256::{sha256_proof_u32, prove_sub_hashes_u32};

fuzz_target!(|data: &[u8]| {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let lim = data.len() / 2;
    let msg1 = data[0..lim].to_vec();
    let msg2 = data[lim..].to_vec();
    let hash1 = hash(&msg1);
    let hash2 = hash(&msg2);
    let msg3 = [hash1.0, hash2.0].concat();
    let hash3 = hash(&msg3);

    let (d1, p1) = sha256_proof_u32::<F, C, D>(&msg1, &hash1.0).expect("Error proving first hash.");
    d1.verify(p1.clone()).expect("First proof verification failed.");
    let (d2, p2) = sha256_proof_u32::<F, C, D>(&msg2, &hash2.0).expect("Error proving second hash.");
    d2.verify(p2.clone()).expect("Second proof verification failed.");
    let (d3, p3) = sha256_proof_u32::<F, C, D>(&msg3, &hash3.0).expect("Error proving concatenated hashes.");
    d3.verify(p3.clone()).expect("Third proof verification failed.");
    let (data, proof) = prove_sub_hashes_u32(
        true,
        true,
        &p1.public_inputs,
        &p2.public_inputs,
        Some(&hash3.0.to_vec()),
        (&d1.common, &d1.verifier_only, &p1),
        Some((&d2.common, &d2.verifier_only, &p2)),
    ).expect("Error proving subhashes."); 
    assert!(data.verify(proof).is_ok(), "Proof verification failed.");
});

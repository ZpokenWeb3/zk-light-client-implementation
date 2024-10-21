#![no_main]

use libfuzzer_sys::fuzz_target;
use plonky2::plonk::config::{PoseidonGoldilocksConfig, GenericConfig};
use near_bft_finality::prove_block_data::primitives::two_thirds;

fuzz_target!(|data: &[u8]| {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    // Near stake length.
    const LEN: usize = 16;
    // Create an u128 value from random bytes.
    let mut value_bytes = if data.len() >= LEN {
        data[0..16].to_vec()
    } else {
        let mut tmp = data.to_vec();
        for _ in data.len()..LEN {
            tmp.push(0);
        }
        tmp
    };
    let value = u128::from_le_bytes(value_bytes.clone().try_into().unwrap());
    // Create a value that it more than 2/3 of the initial value.
    let value13 = if data.len() > 0 {
	let mut tmp = u128::to_le_bytes((value / 3) * 2 + data[0] as u128).to_vec();
	// Array has to contain 17 bytes with zero as MSB.
	tmp.push(0);
	tmp
    } else {
	let mut tmp = u128::to_le_bytes((value / 3) * 2).to_vec();
	// Array has to contain 17 bytes with zero as MSB.
	tmp.push(0);
        tmp
    };
    // Array has to contain 17 bytes with zero as MSB.
    value_bytes.push(0);
    let (data, proof) = two_thirds::<F, C, D>(&value13, &value_bytes).expect("Error genetaring proof."); 
    assert!(data.verify(proof).is_ok(), "Proof verification failed.");
});

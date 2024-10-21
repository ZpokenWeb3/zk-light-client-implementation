#![no_main]

use libfuzzer_sys::fuzz_target;
use plonky2::plonk::config::{PoseidonGoldilocksConfig, GenericConfig};
use near_bft_finality::prove_block_data::primitives::prove_consecutive_heights;

fuzz_target!(|data: &[u8]| {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let data_bytes = if data.len() >= 8 {
	data[0..8].to_vec()
    } else {
	[1, 0, 0, 0, 0, 0, 0, 0].to_vec()
    };	
    let value1 = u64::from_le_bytes(data_bytes.clone().try_into().unwrap());
    let value2 = value1 - 1;
    
    let value1_bytes = value1.to_le_bytes().to_vec();
    let value2_bytes = value2.to_le_bytes().to_vec();

    let (data, proof) = prove_consecutive_heights::<F, C, D>(&value1_bytes, &value2_bytes).expect("Error generating proof.");
 
    assert!(data.verify(proof).is_ok(), "Proof verification failed.");
});

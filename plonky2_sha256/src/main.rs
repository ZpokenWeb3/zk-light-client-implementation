use anyhow::Result;
use log::{Level, LevelFilter};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use plonky2_sha256::circuit::{array_to_bits, sha256_circuit};
use sha2::{Digest, Sha256};

pub fn prove_sha256(msg: &[u8]) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let hash = hasher.finalize();
    // println!("Hash: {:#04X}", hash);

    let msg_bits = array_to_bits(msg);
    let len = msg.len() * 8;
    // println!("block count: {}", (len + 65 + 511) / 512);
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let targets = sha256_circuit(&mut builder, len as u64);
    let mut pw = PartialWitness::new();
    let expected_res = array_to_bits(hash.as_slice());

    for i in 0..len {
        pw.set_bool_target(targets.message[i], msg_bits[i]);
    }

    for i in 0..expected_res.len() {
        pw.set_bool_target(targets.digest[i], expected_res[i]);

        match expected_res[i] {
            true => builder.assert_one(targets.digest[i].target),
            false => builder.assert_zero(targets.digest[i].target),
        }
    }

    //println!(
    //    "Constructing inner proof with {} gates",
    //    builder.num_gates()
    //);
    let data = builder.build::<C>();
    let timing = TimingTree::new("prove", Level::Debug);
    let proof = data.prove(pw).unwrap();
    timing.print();

    let timing = TimingTree::new("verify", Level::Debug);
    let res = data.verify(proof);
    timing.print();

    res
}

fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Debug);
    builder.try_init()?;

    const MSG_SIZE: usize = 256;
    let mut msg = vec![0; MSG_SIZE];
    for i in 0..MSG_SIZE {
        msg[i] = i as u8;
    }
    prove_sha256(&msg)
}

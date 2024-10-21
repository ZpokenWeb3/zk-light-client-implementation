use anyhow::Result;
use log::{info, Level, LevelFilter};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use rand::random;
use sha2::{Digest, Sha512};

use plonky2_sha512::circuit::{array_to_bits, sha512_circuit};

pub fn prove_sha512(msg: &[u8], hash: &[u8]) -> Result<()> {
    let msg_bits = array_to_bits(msg);
    let len = msg.len() * 8;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let targets = sha512_circuit(&mut builder, len as u128);
    let mut pw = PartialWitness::new();

    for i in 0..len {
        pw.set_bool_target(targets.message[i], msg_bits[i]);
    }

    let expected_res = array_to_bits(hash);
    for i in 0..expected_res.len() {
        if expected_res[i] {
            builder.assert_one(targets.digest[i].target);
        } else {
            builder.assert_zero(targets.digest[i].target);
        }
    }

    info!(
        "Constructing inner proof with {} gates",
        builder.num_gates()
    );
    let data = builder.build::<C>();
    let timing = TimingTree::new("prove", Level::Info);
    let proof = data.prove(pw).unwrap();
    timing.print();

    let timing = TimingTree::new("verify", Level::Info);
    let res = data.verify(proof);
    timing.print();

    res
}

fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Info);
    builder.try_init()?;

    const MSG_SIZE: usize = 128;

    let msg: Vec<u8> = (0..MSG_SIZE).map(|_| random::<u8>() as u8).collect();

    let mut hasher = Sha512::new();
    hasher.update(msg.clone());
    let hash = hasher.finalize();

    prove_sha512(&msg, &hash)
}

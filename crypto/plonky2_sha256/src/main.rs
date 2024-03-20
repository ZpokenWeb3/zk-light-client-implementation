use anyhow::Result;
use log::{Level, LevelFilter};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;
use rand::random;
use sha2::{Digest, Sha256};

use plonky2_sha256::circuit::{array_to_bits, sha256_circuit};

pub fn prove_sha256<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    msg: &[u8],
    hash: &[u8],
) -> Result<()> {
    let msg_bits = array_to_bits(msg);
    let hash_bits = array_to_bits(hash);
    let msg_bit_len = msg.len() * 8;

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let targets = sha256_circuit(&mut builder, msg_bit_len);
    let mut pw = PartialWitness::new();

    for i in 0..msg_bit_len {
        pw.set_bool_target(targets.message[i], msg_bits[i]);
    }

    for i in 0..hash_bits.len() {
        pw.set_bool_target(targets.digest[i], hash_bits[i]);

        match hash_bits[i] {
            true => builder.assert_one(targets.digest[i].target),
            false => builder.assert_zero(targets.digest[i].target),
        }
    }

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

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    const MSG_SIZE: usize = 256;

    let mut msg: Vec<u8> = (0..MSG_SIZE).map(|_| random::<u8>() as u8).collect();
    
    let mut hasher = Sha256::new();
    hasher.update(msg.clone());
    let hash = hasher.finalize();

    prove_sha256::<F, C, D>(&msg, &hash)
}

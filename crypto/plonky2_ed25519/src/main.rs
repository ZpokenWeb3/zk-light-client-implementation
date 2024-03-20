#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use anyhow::Result;
use log::{Level, LevelFilter};
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use plonky2::util::timing::TimingTree;

use plonky2_ed25519::gadgets::eddsa::{ed25519_circuit, fill_ecdsa_targets};

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

fn prove_ed25519<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize>(
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
) -> Result<ProofTuple<F, C, D>>
    where
        [(); C::Hasher::HASH_SIZE]:,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());

    let targets = ed25519_circuit(&mut builder, msg.len() * 8);
    let mut pw = PartialWitness::new();
    fill_ecdsa_targets::<F, D>(&mut pw, msg, sigv, pkv, &targets);

    println!(
        "Constructing inner proof with {} gates",
        builder.num_gates()
    );
    let data = builder.build::<C>();

    let timing = TimingTree::new("prove", Level::Info);
    let proof = data.prove(pw).unwrap();
    timing.print();

    let timing = TimingTree::new("verify", Level::Info);
    data.verify(proof.clone()).expect("verify error");
    timing.print();

    // test_serialization(&proof, &data.verifier_only, &data.common)?;
    Ok((proof, data.verifier_only, data.common))
}

fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Info);
    builder.try_init()?;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let sample_msg1 = "test message".to_string();
    let sample_pk1 = [
        59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29,
        226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41,
    ].to_vec();
    let sample_sig1 = [
        104, 196, 204, 44, 176, 120, 225, 128, 47, 67, 245, 210, 247, 65, 201, 66, 34, 159, 217, 32,
        175, 224, 14, 12, 31, 231, 83, 160, 214, 122, 250, 68, 250, 203, 33, 143, 184, 13, 247, 140,
        185, 25, 122, 25, 253, 195, 83, 102, 240, 255, 30, 21, 108, 249, 77, 184, 36, 72, 9, 198, 49,
        12, 68, 8,
    ].to_vec();

    prove_ed25519::<F, C, D>(sample_msg1.as_bytes(), &sample_sig1, &sample_pk1)?;

    Ok(())
}
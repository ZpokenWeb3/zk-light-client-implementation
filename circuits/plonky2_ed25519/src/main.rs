#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use anyhow::Result;
use clap::Parser;
use core::num::ParseIntError;
use log::{info, Level, LevelFilter};
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{CompressedProofWithPublicInputs, ProofWithPublicInputs};
use plonky2::plonk::prover::prove;
use plonky2::recursion::tree_recursion::{
    check_tree_proof_verifier_data, common_data_for_recursion, set_tree_recursion_leaf_data_target,
    TreeRecursionLeafData,
};
use plonky2::util::timing::TimingTree;
use plonky2_ed25519::curve::eddsa::{
    SAMPLE_MSG1, SAMPLE_MSG2, SAMPLE_PK1, SAMPLE_SIG1, SAMPLE_SIG2,
};
use plonky2_ed25519::gadgets::eddsa::{ed25519_circuit, fill_ecdsa_targets};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

fn prove_ed25519<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
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

fn recursive_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    inner1: &ProofTuple<F, InnerC, D>,
    inner2: Option<ProofTuple<F, InnerC, D>>,
    config: &CircuitConfig,
    min_degree_bits: Option<usize>,
) -> Result<ProofTuple<F, C, D>>
where
    InnerC::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();

    {
        let (inner_proof, inner_vd, inner_cd) = inner1;
        let pt = builder.add_virtual_proof_with_pis(inner_cd);
        pw.set_proof_with_pis_target(&pt, inner_proof);

        let inner_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_cap_target(
            &inner_data.constants_sigmas_cap,
            &inner_vd.constants_sigmas_cap,
        );
        pw.set_hash_target(inner_data.circuit_digest, inner_vd.circuit_digest);

        builder.verify_proof::<InnerC>(&pt, &inner_data, inner_cd);
    }

    if inner2.is_some() {
        let (inner_proof, inner_vd, inner_cd) = inner2.unwrap();
        let pt = builder.add_virtual_proof_with_pis(&inner_cd);
        pw.set_proof_with_pis_target(&pt, &inner_proof);

        let inner_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_hash_target(inner_data.circuit_digest, inner_vd.circuit_digest);
        pw.set_cap_target(
            &inner_data.constants_sigmas_cap,
            &inner_vd.constants_sigmas_cap,
        );

        builder.verify_proof::<InnerC>(&pt, &inner_data, &inner_cd);
    }
    builder.print_gate_counts(0);

    if let Some(min_degree_bits) = min_degree_bits {
        // We don't want to pad all the way up to 2^min_degree_bits, as the builder will
        // add a few special gates afterward. So just pad to 2^(min_degree_bits
        // - 1) + 1. Then the builder will pad to the next power of two,
        // 2^min_degree_bits.
        let min_gates = (1 << (min_degree_bits - 1)) + 1;
        for _ in builder.num_gates()..min_gates {
            builder.add_gate(NoopGate, vec![]);
        }
    }

    let data = builder.build::<C>();

    let mut timing = TimingTree::new("prove", Level::Info);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();

    data.verify(proof.clone())?;

    test_serialization(&proof, &data.verifier_only, &data.common)?;
    Ok((proof, data.verifier_only, data.common))
}

fn benchmark() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let config = CircuitConfig::standard_recursion_config();

    let proof1 = prove_ed25519(
        SAMPLE_MSG1.as_bytes(),
        SAMPLE_SIG1.as_slice(),
        SAMPLE_PK1.as_slice(),
    )
    .expect("prove error 1");
    let proof2 = prove_ed25519(
        SAMPLE_MSG2.as_bytes(),
        SAMPLE_SIG2.as_slice(),
        SAMPLE_PK1.as_slice(),
    )
    .expect("prove error 2");

    // Recursively verify the proof
    let middle = recursive_proof::<F, C, C, D>(&proof1, Some(proof2), &config, None)?;
    let (_, _, cd) = &middle;
    info!(
        "Single recursion proof degree {} = 2^{}",
        cd.degree(),
        cd.degree_bits()
    );

    // Add a second layer of recursion to shrink the proof size further
    let outer = recursive_proof::<F, C, C, D>(&middle, None, &config, None)?;
    let (_, _, cd) = &outer;
    info!(
        "Double recursion proof degree {} = 2^{}",
        cd.degree(),
        cd.degree_bits()
    );

    Ok(())
}

/// Test serialization and print some size info.
fn test_serialization<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    proof: &ProofWithPublicInputs<F, C, D>,
    vd: &VerifierOnlyCircuitData<C, D>,
    cd: &CommonCircuitData<F, D>,
) -> Result<()>
where
    [(); C::Hasher::HASH_SIZE]:,
{
    let proof_bytes = proof.to_bytes();
    info!("Proof length: {} bytes", proof_bytes.len());
    let proof_from_bytes = ProofWithPublicInputs::from_bytes(proof_bytes, cd)?;
    assert_eq!(proof, &proof_from_bytes);

    let now = std::time::Instant::now();
    let compressed_proof = proof.clone().compress(&vd.circuit_digest, cd)?;
    let decompressed_compressed_proof = compressed_proof
        .clone()
        .decompress(&vd.circuit_digest, cd)?;
    info!("{:.4}s to compress proof", now.elapsed().as_secs_f64());
    assert_eq!(proof, &decompressed_compressed_proof);

    let compressed_proof_bytes = compressed_proof.to_bytes();
    info!(
        "Compressed proof length: {} bytes",
        compressed_proof_bytes.len()
    );
    let compressed_proof_from_bytes =
        CompressedProofWithPublicInputs::from_bytes(compressed_proof_bytes, cd)?;
    assert_eq!(compressed_proof, compressed_proof_from_bytes);

    Ok(())
}

#[derive(Parser)]
struct Cli {
    #[arg(short, long, default_value_t = 0)]
    benchmark: u8,
    #[arg(short, long, default_value = "./ed25519.proof")]
    output_path: PathBuf,
    #[arg(short, long, default_value = "0123456789ABCDEF")]
    msg: String,
    #[arg(
        short,
        long,
        default_value = "9DBB279277D4EFE2E5F114A9AAB25C83FC9509D3B3D3B90929854F5A243AEBCD"
    )]
    pk: String,
    #[arg(
        short,
        long,
        default_value = "2EF7A1AA2FC58D40691236664418ADC903C153ABC0C95D02AC45B436C02081C2B93891B37B17F57C7CDE97B52BBB8F1865C14A92ADA4DC34ED0DE7935346E40E"
    )]
    sig: String,
}

pub fn decode_hex(s: &String) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn main() -> Result<()> {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Info);
    builder.try_init()?;

    let args = Cli::parse();
    if args.benchmark == 1 {
        // Run the benchmark
        benchmark()
    } else {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let (inner_proof, inner_vd, inner_cd) = prove_ed25519::<F, C, D>(
            decode_hex(&args.msg)?.as_slice(),
            decode_hex(&args.sig)?.as_slice(),
            decode_hex(&args.pk)?.as_slice(),
        )?;

        // recursively prove in a leaf
        let standard_config = CircuitConfig::standard_recursion_config();
        let mut common_data = common_data_for_recursion::<GoldilocksField, C, D>();
        let mut builder = CircuitBuilder::<F, D>::new(standard_config.clone());
        let leaf_targets = builder.tree_recursion_leaf::<C>(inner_cd, &mut common_data)?;
        let data = builder.build::<C>();
        let leaf_vd = &data.verifier_only;
        let mut pw = PartialWitness::new();
        let leaf_data = TreeRecursionLeafData {
            inner_proof: &inner_proof,
            inner_verifier_data: &inner_vd,
            verifier_data: leaf_vd,
        };
        set_tree_recursion_leaf_data_target(&mut pw, &leaf_targets, &leaf_data)?;
        let leaf_proof = data.prove(pw)?;
        check_tree_proof_verifier_data(&leaf_proof, leaf_vd, &common_data)
            .expect("Leaf public inputs do not match its verifier data");

        let proof_bytes = leaf_proof.to_bytes();
        info!("Export proof: {} bytes", proof_bytes.len());

        println!(
            "Exporting root proof: {}",
            args.output_path
                .clone()
                .into_os_string()
                .into_string()
                .unwrap()
        );
        let mut file = File::create(args.output_path)?;
        file.write_all(&*proof_bytes)
            .expect("Root proof file write err");

        Ok(())
    }
}

use anyhow::Result;
use core::num::ParseIntError;
use log::Level;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;
use sha2::{Digest, Sha256};

use plonky2_ed25519::gadgets::eddsa::{ed25519_circuit, fill_circuits};
use plonky2_sha256::circuit::{array_to_bits, sha256_circuit};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub fn decode_hex(s: &String) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}
/*
Generate hash as vector
Input
msg is message as u8 vector
Output:
hash is a hash as u8 vector
*/
pub fn make_hash(msg: &[u8]) -> String {
    // create a Sha256 object
    let mut hasher = Sha256::new();
    // write input message
    hasher.update(msg);
    // read hash digest and consume hasher
    let hash = hasher.finalize();
    format!("{:x}", hash)
}
/*
Input:
msg is a message
hash is a hash from message msg
Output:
(data, proof):
    data is a circuit,
    proof is a proof of hash (sha256)
*/
pub fn hash_circuit_proof(
    msg: &[u8],
    hash: &[u8],
) -> (CircuitData<F, C, 2>, ProofWithPublicInputs<F, C, D>) {
    let msg_bits = array_to_bits(msg);
    let len = msg.len() * 8;
    println!("block count: {}", (len + 65 + 511) / 512);

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let targets = sha256_circuit(&mut builder, len as u64);

    let mut pw = PartialWitness::new();

    for i in 0..len {
        pw.set_bool_target(targets.message[i], msg_bits[i]);
        builder.register_public_input(targets.message[i].target);
    }

    let expected_res = array_to_bits(hash);
    for i in 0..expected_res.len() {
        if expected_res[i] {
            builder.assert_one(targets.digest[i].target);
        } else {
            builder.assert_zero(targets.digest[i].target);
        }
    }
    println!("Constructing proof with {} gates", builder.num_gates());

    let data = builder.build::<C>();

    let timing = TimingTree::new("prove", Level::Debug);
    let proof = data.prove(pw).unwrap();
    timing.print();

    (data, proof)
}

pub fn sig_circuit_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
) -> (CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>) {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
    let targets = ed25519_circuit(&mut builder, msg.len());
    let mut pw = PartialWitness::new();
    fill_circuits::<F, D>(&mut pw, msg, sigv, pkv, &targets);

    println!(
        "Constructing inner proof with {} gates",
        builder.num_gates()
    );
    let data = builder.build::<C>();

    let timing = TimingTree::new("prove", Level::Info);
    let proof = data.prove(pw).unwrap();
    timing.print();
    (data, proof)
}
/*
Input:
(data, proof):
    data is a circuit,
    proof is a proof of hash (sha256)
Output:
result of verification
*/
pub fn verification(
    (data, proof): (&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>),
) -> Result<()> {
    let timing = TimingTree::new("verify", Level::Debug);
    let res = data.verify(proof.to_owned());
    timing.print();
    res
}
pub fn verification_proofs(
    (data1, proof1): (&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>),
    (data2, proof2): (&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>),
) -> Result<()> {
    let timing = TimingTree::new("verify two proofs", Level::Debug);
    let res1 = verification((data1, proof1));
    let res2 = verification((data2, proof2));
    let res3 = res1.and(res2);
    timing.print();
    res3
}
/*
Aggregation of two proofs
*/
pub fn aggregation_two(
    (data1, proof1): (&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>),
    data_proof_2: Option<(&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>)>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    verification((data1, proof1))?;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let proof_with_pis_target_1 = builder.add_virtual_proof_with_pis(&data1.common);
    // dynamic setup for verifier
    let verifier_circuit_target_1 = VerifierCircuitTarget {
        // data.common is static setup for verifier
        constants_sigmas_cap: builder.add_virtual_cap(data1.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&proof_with_pis_target_1, proof1);
    pw.set_cap_target(
        &verifier_circuit_target_1.constants_sigmas_cap,
        &data1.verifier_only.constants_sigmas_cap,
    );
    pw.set_hash_target(
        verifier_circuit_target_1.circuit_digest,
        data1.verifier_only.circuit_digest,
    );
    builder.verify_proof::<C>(
        &proof_with_pis_target_1,
        &verifier_circuit_target_1,
        &data1.common,
    );
    if data_proof_2.is_some() {
        verification((data_proof_2.unwrap().0, data_proof_2.unwrap().1))?;
        let proof_with_pis_target_2 =
            builder.add_virtual_proof_with_pis(&data_proof_2.unwrap().0.common);
        let verifier_circuit_target_2 = VerifierCircuitTarget {
            constants_sigmas_cap: builder
                .add_virtual_cap(data_proof_2.unwrap().0.common.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_proof_with_pis_target(&proof_with_pis_target_2, data_proof_2.unwrap().1);
        pw.set_cap_target(
            &verifier_circuit_target_2.constants_sigmas_cap,
            &data_proof_2.unwrap().0.verifier_only.constants_sigmas_cap,
        );
        pw.set_hash_target(
            verifier_circuit_target_2.circuit_digest,
            data_proof_2.unwrap().0.verifier_only.circuit_digest,
        );
        builder.verify_proof::<C>(
            &proof_with_pis_target_2,
            &verifier_circuit_target_2,
            &data_proof_2.unwrap().0.common,
        );
    }
    // create common circuit for two proofs
    let data_new = builder.build::<C>();
    let timing = TimingTree::new("prove", Level::Debug);
    let proof_new = data_new.prove(pw)?;
    timing.print();
    Ok((data_new, proof_new))
}
/*
Aggregation of three proofs
*/
pub fn aggregation_three(
    (data1, proof1): (&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>),
    (data2, proof2): (&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>),
    (data3, proof3): (&CircuitData<F, C, 2>, &ProofWithPublicInputs<F, C, D>),
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    verification((data1, proof1))?;
    verification((data2, proof2))?;
    verification((data3, proof3))?;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let proof_with_pis_target_1 = builder.add_virtual_proof_with_pis(&data1.common);
    let proof_with_pis_target_2 = builder.add_virtual_proof_with_pis(&data2.common);
    let proof_with_pis_target_3 = builder.add_virtual_proof_with_pis(&data3.common);
    // dynamic setup for verifier
    let verifier_circuit_target_1 = VerifierCircuitTarget {
        // data.common is static setup for verifier
        constants_sigmas_cap: builder.add_virtual_cap(data1.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let verifier_circuit_target_2 = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data2.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let verifier_circuit_target_3 = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data3.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&proof_with_pis_target_1, proof1);
    pw.set_proof_with_pis_target(&proof_with_pis_target_2, proof2);
    pw.set_proof_with_pis_target(&proof_with_pis_target_3, proof3);
    pw.set_cap_target(
        &verifier_circuit_target_1.constants_sigmas_cap,
        &data1.verifier_only.constants_sigmas_cap,
    );
    pw.set_cap_target(
        &verifier_circuit_target_2.constants_sigmas_cap,
        &data2.verifier_only.constants_sigmas_cap,
    );
    pw.set_cap_target(
        &verifier_circuit_target_3.constants_sigmas_cap,
        &data3.verifier_only.constants_sigmas_cap,
    );
    pw.set_hash_target(
        verifier_circuit_target_1.circuit_digest,
        data1.verifier_only.circuit_digest,
    );
    pw.set_hash_target(
        verifier_circuit_target_2.circuit_digest,
        data2.verifier_only.circuit_digest,
    );
    pw.set_hash_target(
        verifier_circuit_target_3.circuit_digest,
        data3.verifier_only.circuit_digest,
    );
    builder.verify_proof::<C>(
        &proof_with_pis_target_1,
        &verifier_circuit_target_1,
        &data1.common,
    );
    builder.verify_proof::<C>(
        &proof_with_pis_target_2,
        &verifier_circuit_target_2,
        &data2.common,
    );
    builder.verify_proof::<C>(
        &proof_with_pis_target_3,
        &verifier_circuit_target_3,
        &data3.common,
    );
    // create common circuit for two proofs
    let data_new = builder.build::<C>();
    let timing = TimingTree::new("prove", Level::Debug);
    let proof_new = data_new.prove(pw).unwrap();
    timing.print();
    Ok((data_new, proof_new))
}

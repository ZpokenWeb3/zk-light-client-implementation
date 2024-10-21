use anyhow::Result;
use log::Level;
use plonky2::{
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::GenericConfig,
        proof::ProofWithPublicInputs,
    },
    util::timing::TimingTree,
};
use plonky2_ed25519::gadgets::eddsa::{ed25519_circuit, fill_ecdsa_targets, EDDSATargets};
use plonky2_field::extension::Extendable;
use std::collections::HashMap;

pub fn get_ed25519_circuit_targets<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    msg_len_in_bits: usize,
    cached_circuits: &mut HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)>,
) -> (CircuitData<F, C, D>, EDDSATargets) {
    match cached_circuits.get(&msg_len_in_bits) {
        Some(cache) => cache.clone(),
        None => {
            let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
            let targets = ed25519_circuit(&mut builder, msg_len_in_bits);

            let timing = TimingTree::new("build", Level::Info);
            let circuit_data = builder.build::<C>();
            timing.print();

            cached_circuits.insert(msg_len_in_bits, (circuit_data.clone(), targets.clone()));

            (circuit_data, targets)
        }
    }
}

/// Creating ED25519 proof reusing proving schema and targets
pub fn ed25519_proof_reuse_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
    ed25519_circuits: &mut HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)> {
    let len_in_bits = msg.len() * 8;
    let (circuit_data, targets): (CircuitData<F, C, D>, EDDSATargets) =
        get_ed25519_circuit_targets(len_in_bits, ed25519_circuits);
    let mut pw: PartialWitness<F> = PartialWitness::new();
    fill_ecdsa_targets::<F, D>(&mut pw, msg, sigv, pkv, &targets);
    let timing = TimingTree::new("prove", Level::Info);
    let proof = circuit_data.prove(pw)?;
    timing.print();
    Ok((circuit_data, proof))
}

/// Computes EDD5519 targets and proving schema depending on specific message length in bits.
pub fn get_ed25519_targets<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    msg_len_in_bits: usize,
) -> anyhow::Result<(CircuitData<F, C, D>, EDDSATargets)> {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
    let targets = ed25519_circuit(&mut builder, msg_len_in_bits);
    let circuit_data = builder.build::<C>();
    Ok((circuit_data, targets))
}

/// Computes an Ed25519 proof for a given message, signature, and public key.
///
/// # Arguments
///
/// * `msg` - A slice of bytes representing the message for which the proof is to be computed.
/// * `sigv` - A slice of bytes representing the Ed25519 signature.
/// * `pkv` - A slice of bytes representing the Ed25519 public key.
/// * `circuit_data` - A tuple containing the existing proving schema and targets.
///
/// # Returns
///
/// Returns a result containing the computed Ed25519 proof with public inputs.
pub fn ed25519_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    msg: &[u8],
    sigv: &[u8],
    pkv: &[u8],
    circuit_data: (CircuitData<F, C, D>, EDDSATargets),
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw: PartialWitness<F> = PartialWitness::new();
    fill_ecdsa_targets::<F, D>(&mut pw, msg, sigv, pkv, &circuit_data.1);
    let timing = TimingTree::new("Prove signature", Level::Info);
    let proof = circuit_data.0.prove(pw)?;
    timing.print();
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::*;
    use plonky2::plonk::{circuit_data, config::PoseidonGoldilocksConfig};
    use plonky2_field::types::Field;
    use rand::random;

    #[test]
    fn test_get_ed25519_circuit_targets_caching() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        const MSGLEN1: usize = 100;
        const MSGLEN2: usize = 1000;

        let msg1: Vec<u8> = (0..MSGLEN1).map(|_| random::<u8>() as u8).collect();
        let msg2: Vec<u8> = (0..MSGLEN2).map(|_| random::<u8>() as u8).collect();
        let msg3: Vec<u8> = (0..MSGLEN1).map(|_| random::<u8>() as u8).collect();

        assert_eq!(msg1.len(), msg3.len());

        let mut circuit_data_targets: HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)> =
            HashMap::new();

        let (_data, _targets) =
            get_ed25519_circuit_targets::<F, C, D>(msg1.len(), &mut circuit_data_targets);
        assert!(circuit_data_targets.len() == 1);
        let (_data, _targets) =
            get_ed25519_circuit_targets::<F, C, D>(msg2.len(), &mut circuit_data_targets);
        assert!(circuit_data_targets.len() == 2);
        let (_data, _targets) =
            get_ed25519_circuit_targets::<F, C, D>(msg3.len(), &mut circuit_data_targets);
        assert!(circuit_data_targets.len() == 2);

        Ok(())
    }

    #[test]
    fn test_ed25519_proof_reuse_circuit_reusability() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        const MSGLEN1: usize = 100;
        const MSGLEN2: usize = 1000;

        let msg1: Vec<u8> = (0..MSGLEN1).map(|_| random::<u8>() as u8).collect();
        let keys1 = KeyPair::generate();
        let pk1 = keys1.pk.to_vec();
        let sig1 = keys1.sk.sign(msg1.clone(), None).to_vec();

        let msg2: Vec<u8> = (0..MSGLEN2).map(|_| random::<u8>() as u8).collect();
        let keys2 = KeyPair::generate();
        let pk2 = keys2.pk.to_vec();
        let sig2 = keys2.sk.sign(msg2.clone(), None).to_vec();

        let msg3: Vec<u8> = (0..MSGLEN1).map(|_| random::<u8>() as u8).collect();
        let keys3 = KeyPair::generate();
        let pk3 = keys3.pk.to_vec();
        let sig3 = keys3.sk.sign(msg3.clone(), None).to_vec();

        assert_eq!(msg1.len(), msg3.len());

        let mut circuit_data_targets: HashMap<usize, (CircuitData<F, C, D>, EDDSATargets)> =
            HashMap::new();

        let (d1, p1) =
            ed25519_proof_reuse_circuit::<F, C, D>(&msg1, &sig1, &pk1, &mut circuit_data_targets)?;
        d1.verify(p1)?;
        assert!(circuit_data_targets.len() == 1);
        let (d2, p2) =
            ed25519_proof_reuse_circuit::<F, C, D>(&msg2, &sig2, &pk2, &mut circuit_data_targets)?;
        d2.verify(p2)?;
        assert!(circuit_data_targets.len() == 2);
        let (d3, p3) =
            ed25519_proof_reuse_circuit::<F, C, D>(&msg3, &sig3, &pk3, &mut circuit_data_targets)?;
        assert!(circuit_data_targets.len() == 2);
        d3.verify(p3)
    }

    #[test]
    fn test_ed25519_proof_without_reusing_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        const MSGLEN: usize = 100;

        let msg: Vec<u8> = (0..MSGLEN).map(|_| random::<u8>() as u8).collect();
        let keys = KeyPair::generate();
        let pk = keys.pk.to_vec();
        let sig = keys.sk.sign(msg.clone(), None).to_vec();

        let (data, targets) = get_ed25519_targets::<F, C, D>(msg.len() * 8)?;
        let proof = ed25519_proof::<F, C, D>(&msg, &sig, &pk, (data.clone(), targets))?;
        data.verify(proof)
    }
}

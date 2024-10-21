use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use plonky2_sha512::circuit::{array_to_bits, bits_to_biguint_target, sha512_circuit};

use crate::curve::curve_types::Curve;
use crate::curve::ed25519::Ed25519;
use crate::gadgets::curve::CircuitBuilderCurve;
use crate::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use crate::gadgets::curve_windowed_mul::CircuitBuilderWindowedMul;
use crate::gadgets::nonnative::CircuitBuilderNonNative;

#[derive(Debug, Clone)]
pub struct EDDSATargets {
    pub msg: Vec<BoolTarget>,
    pub sig: Vec<BoolTarget>,
    pub pk: Vec<BoolTarget>,
}

fn bits_in_le(input_vec: Vec<BoolTarget>) -> Vec<BoolTarget> {
    let mut bits = Vec::new();
    for i in 0..input_vec.len() / 8 {
        for j in 0..8 {
            bits.push(input_vec[i * 8 + 7 - j]);
        }
    }
    bits.reverse();
    bits
}

pub fn ed25519_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg_len: usize,
) -> EDDSATargets {
    let msg_len_in_bits = msg_len;
    let sha512_msg_len = msg_len_in_bits + 512;
    let sha512 = sha512_circuit(builder, sha512_msg_len as u128);

    let mut msg = Vec::new();
    let mut sig = Vec::new();
    let mut pk = Vec::new();
    for i in 0..msg_len_in_bits {
        builder.register_public_input(sha512.message[512 + i].target);
        msg.push(sha512.message[512 + i]);
    }
    for _ in 0..512 {
        sig.push(builder.add_virtual_bool_target_unsafe());
    }
    for _ in 0..256 {
        let t = builder.add_virtual_bool_target_unsafe();
        builder.register_public_input(t.target);
        pk.push(t);
    }
    for i in 0..256 {
        builder.connect(sha512.message[i].target, sig[i].target);
    }
    for i in 0..256 {
        builder.connect(sha512.message[256 + i].target, pk[i].target);
    }

    let digest_bits = bits_in_le(sha512.digest.clone());
    let hash = bits_to_biguint_target(builder, digest_bits);
    let h = builder.reduce(&hash);

    let s_bits = bits_in_le(sig[256..512].to_vec());
    let s_biguint = bits_to_biguint_target(builder, s_bits);
    let s = builder.biguint_to_nonnative(&s_biguint);

    let pk_bits = bits_in_le(pk.clone());
    let a = builder.point_decompress(&pk_bits);

    let ha = builder.curve_scalar_mul_windowed(&a, &h);

    let r_bits = bits_in_le(sig[..256].to_vec());
    let r = builder.point_decompress(&r_bits);

    let sb = fixed_base_curve_mul_circuit(builder, Ed25519::GENERATOR_AFFINE, &s);
    let rhs = builder.curve_add(&r, &ha);
    builder.connect_affine_point(&sb, &rhs);

    EDDSATargets { msg, sig, pk }
}

pub fn fill_ecdsa_targets<F: RichField + Extendable<D>, const D: usize>(
    pw: &mut PartialWitness<F>,
    msg: &[u8],
    sig: &[u8],
    pk: &[u8],
    targets: &EDDSATargets,
) {
    assert_eq!(sig.len(), 64);
    assert_eq!(pk.len(), 32);

    let EDDSATargets {
        msg: msg_targets,
        sig: sig_targets,
        pk: pk_targets,
    } = targets;
    assert_eq!(msg.len() * 8, msg_targets.len());

    let sig_bits = array_to_bits(sig);
    let pk_bits = array_to_bits(pk);
    let msg_bits = array_to_bits(msg);

    for i in 0..msg_bits.len() {
        pw.set_bool_target(msg_targets[i], msg_bits[i]);
    }
    for i in 0..512 {
        pw.set_bool_target(sig_targets[i], sig_bits[i]);
    }
    for i in 0..256 {
        pw.set_bool_target(pk_targets[i], pk_bits[i]);
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use rand::Rng;
    use ed25519_compact::KeyPair;
    use rand::random;
    use crate::gadgets::eddsa::{ed25519_circuit, fill_ecdsa_targets};

    fn test_eddsa_circuit_with_config(config: CircuitConfig) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

	const MSGLEN1: usize = 100;

        let msg1: Vec<u8> = (0..MSGLEN1).map(|_| random::<u8>() as u8).collect();
        let keys1 = KeyPair::generate();
        let pk1 = keys1.pk.to_vec();
        let sig1 = keys1.sk.sign(msg1.clone(), None).to_vec();

        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let targets = ed25519_circuit(&mut builder, msg1.len() * 8);

        fill_ecdsa_targets::<F, D>(
            &mut pw,
            &msg1,
            &sig1,
            &pk1,
            &targets,
        );

        dbg!(builder.num_gates());
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    fn test_eddsa_circuit_with_config_failure(config: CircuitConfig) {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

	const MSGLEN1: usize = 100;

        let msg1: Vec<u8> = (0..MSGLEN1).map(|_| random::<u8>() as u8).collect();
        let msg2: Vec<u8> = (0..MSGLEN1).map(|_| random::<u8>() as u8).collect();
        let keys1 = KeyPair::generate();
        let pk1 = keys1.pk.to_vec();
        let sig1 = keys1.sk.sign(msg2.clone(), None).to_vec();

        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let targets = ed25519_circuit(&mut builder, msg1.len() * 8);

        fill_ecdsa_targets::<F, D>(
            &mut pw,
            &msg1,
            &sig1,
            &pk1,
            &targets,
        );

        dbg!(builder.num_gates());
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).expect("verify error");
    }

    #[test]
    fn test_eddsa_circuit_narrow() -> Result<()> {
        test_eddsa_circuit_with_config(CircuitConfig::standard_ecc_config())
    }

    #[test]
    fn test_eddsa_circuit_wide() -> Result<()> {
        test_eddsa_circuit_with_config(CircuitConfig::wide_ecc_config())
    }

    #[test]
    #[should_panic]
    fn test_eddsa_circuit_failure() {
        test_eddsa_circuit_with_config_failure(CircuitConfig::wide_ecc_config());
    }
}

use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::Hasher;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

/// Recursively aggregates two proofs to one, verifies inner proofs and optionally set public inputs.
pub fn recursive_proof<F, C, InnerC, const D: usize>(
    (first_inner_common, first_inner_verifier, first_inner_proof): (
        &CommonCircuitData<F, D>,
        &VerifierOnlyCircuitData<InnerC, D>,
        &ProofWithPublicInputs<F, InnerC, D>,
    ),
    second_inner_data_proof: Option<(
        &CommonCircuitData<F, D>,
        &VerifierOnlyCircuitData<InnerC, D>,
        &ProofWithPublicInputs<F, InnerC, D>,
    )>,
    public_inputs: Option<&[F]>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    InnerC::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let proof_with_pis_target_1 = builder.add_virtual_proof_with_pis(first_inner_common);
    let verifier_circuit_target_1 = VerifierCircuitTarget {
        constants_sigmas_cap: builder
            .add_virtual_cap(first_inner_common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&proof_with_pis_target_1, first_inner_proof);
    pw.set_cap_target(
        &verifier_circuit_target_1.constants_sigmas_cap,
        &first_inner_verifier.constants_sigmas_cap,
    );
    pw.set_hash_target(
        verifier_circuit_target_1.circuit_digest,
        first_inner_verifier.circuit_digest,
    );
    builder.verify_proof::<InnerC>(
        &proof_with_pis_target_1,
        &verifier_circuit_target_1,
        first_inner_common,
    );
    if second_inner_data_proof.is_some() {
        let proof_with_pis_target_2 =
            builder.add_virtual_proof_with_pis(second_inner_data_proof.unwrap().0);
        let verifier_circuit_target_2 = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(
                second_inner_data_proof
                    .unwrap()
                    .0
                    .config
                    .fri_config
                    .cap_height,
            ),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_proof_with_pis_target(&proof_with_pis_target_2, second_inner_data_proof.unwrap().2);
        pw.set_cap_target(
            &verifier_circuit_target_2.constants_sigmas_cap,
            &second_inner_data_proof.unwrap().1.constants_sigmas_cap,
        );
        pw.set_hash_target(
            verifier_circuit_target_2.circuit_digest,
            second_inner_data_proof.unwrap().1.circuit_digest,
        );
        builder.verify_proof::<InnerC>(
            &proof_with_pis_target_2,
            &verifier_circuit_target_2,
            second_inner_data_proof.unwrap().0,
        );
    }
    if let Some(pi) = public_inputs {
        let pi_targets: Vec<Target> = builder.add_virtual_targets(pi.len());
        for i in 0..pi.len() {
            pw.set_target(pi_targets[i], pi[i]);
            builder.register_public_input(pi_targets[i]);
        }
    }
    let data_new = builder.build::<C>();
    let proof_new = data_new.prove(pw)?;
    Ok((data_new, proof_new))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prove_block_data::primitives::two_thirds;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2_field::types::Field;
    use rand::random;

    #[test]
    fn test_recursive_proof_valid() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        // choose 1/3 to check whether func works with 2/3 of the value
        let v1_3: u128 = random::<u128>();
        let v: u128 = v1_3 * 3;
        // more then 2/3
        let v1: u128 = ((v / 3) * 2) + 5;

        let mut v_bits = v.to_le_bytes().to_vec();
        let mut v_i_bits = v1.to_le_bytes().to_vec();
        v_bits.push(0);
        v_i_bits.push(0);

        let (cd, proof) = two_thirds::<F, C, D>(&v_i_bits, &v_bits)?;
        cd.verify(proof.clone())?;

        let recursive_data =
            recursive_proof::<F, C, C, D>((&cd.common, &cd.verifier_only, &proof), None, None);
        assert!(recursive_data.is_ok());
        let (recursive_cd, recursive_proof) = recursive_data?;
        assert!(recursive_cd.verify(recursive_proof).is_ok());
        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_recursive_proof_invalid() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        // choose 1/3 to check whether func works with 2/3 of the value
        let v1_3: u128 = random::<u128>();
        let v: u128 = v1_3 * 3;
        // more then 2/3
        let v1: u128 = ((v / 3) * 2) + 5;

        let mut v_bits = v.to_le_bytes().to_vec();
        let mut v_i_bits = v1.to_le_bytes().to_vec();
        v_bits.push(0);
        v_i_bits.push(0);

        let (cd, proof) = two_thirds::<F, C, D>(&v_i_bits, &v_bits).unwrap();
        cd.verify(proof.clone()).unwrap();
        let mut modified_proof = proof.clone();

        modified_proof.public_inputs[proof.public_inputs.len() - 1] = F::from_canonical_u64(10000);

        let recursive_data = recursive_proof::<F, C, C, D>(
            (&cd.common, &cd.verifier_only, &modified_proof),
            None,
            None,
        )
        .unwrap();
    }
}

use crate::sha256::{CircuitBuilderHashSha2, WitnessHashSha2};
use crate::types::{CircuitBuilderHash, Hash256Target, WitnessHash};
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_u32::gadgets::arithmetic_u32::U32Target;

fn select_hash256<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bit: BoolTarget,
    left: &Hash256Target,
    right: &Hash256Target,
) -> Hash256Target {
    let a = U32Target(builder.select(bit, left[0].0, right[0].0));
    let b = U32Target(builder.select(bit, left[1].0, right[1].0));
    let c = U32Target(builder.select(bit, left[2].0, right[2].0));
    let d = U32Target(builder.select(bit, left[3].0, right[3].0));
    let e = U32Target(builder.select(bit, left[4].0, right[4].0));
    let f = U32Target(builder.select(bit, left[5].0, right[5].0));
    let g = U32Target(builder.select(bit, left[6].0, right[6].0));
    let h = U32Target(builder.select(bit, left[7].0, right[7].0));

    [a, b, c, d, e, f, g, h]
}

pub fn compute_merkle_root<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    index_bits: &Vec<BoolTarget>,
    value: Hash256Target,
    siblings: &Vec<Hash256Target>,
) -> Hash256Target {
    let mut current = value;
    for (i, sibling) in siblings.iter().enumerate() {
        let bit = index_bits[i];

        let left = select_hash256(builder, bit, sibling, &current);
        let right = select_hash256(builder, bit, &current, sibling);
        current = builder.two_to_one_sha256(left, right);
    }
    current
}

pub struct MerkleProofSha256Gadget {
    pub root: Hash256Target,
    pub value: Hash256Target,
    pub siblings: Vec<Hash256Target>,
    pub index: Target,
}

impl MerkleProofSha256Gadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let siblings: Vec<Hash256Target> = (0..height)
            .map(|_| builder.add_virtual_hash256_target())
            .collect();

        let value = builder.add_virtual_hash256_target();
        let index = builder.add_virtual_target();
        let index_bits = builder.split_le(index, height);
        let root = compute_merkle_root(builder, &index_bits, value, &siblings);

        Self {
            root,
            value,
            siblings,
            index,
        }
    }

    pub fn set_witness<F: RichField, W: WitnessHashSha2<F>>(
        &self,
        witness: &mut W,
        index: u64,
        value: &[u8; 32],
        siblings: &Vec<[u8; 32]>,
    ) {
        witness.set_hash256_target(&self.value, value);
        witness.set_target(self.index, F::from_noncanonical_u64(index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash256_target(sibling, &siblings[i]);
        }
    }
}

pub struct DeltaMerkleProofSha256Gadget {
    pub old_root: Hash256Target,
    pub old_value: Hash256Target,

    pub new_root: Hash256Target,
    pub new_value: Hash256Target,

    pub siblings: Vec<Hash256Target>,
    pub index: Target,
}

impl DeltaMerkleProofSha256Gadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let siblings: Vec<Hash256Target> = (0..height)
            .map(|_| builder.add_virtual_hash256_target())
            .collect();

        let old_value = builder.add_virtual_hash256_target();
        let new_value = builder.add_virtual_hash256_target();
        let index = builder.add_virtual_target();
        let index_bits = builder.split_le(index, height);
        let old_root = compute_merkle_root(builder, &index_bits, old_value, &siblings);
        let new_root = compute_merkle_root(builder, &index_bits, new_value, &siblings);

        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            siblings,
            index,
        }
    }

    pub fn set_witness<F: RichField, W: WitnessHashSha2<F>>(
        &self,
        witness: &mut W,
        index: u64,
        old_value: &[u8; 32],
        new_value: &[u8; 32],
        siblings: &Vec<[u8; 32]>,
    ) {
        witness.set_hash256_target(&self.old_value, old_value);
        witness.set_hash256_target(&self.new_value, new_value);
        witness.set_target(self.index, F::from_noncanonical_u64(index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash256_target(sibling, &siblings[i]);
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::merkle_utils::{DeltaMerkleProof256, MerkleProof256};
    use crate::sha256_merkle::{DeltaMerkleProofSha256Gadget, MerkleProofSha256Gadget};
    use crate::types::{CircuitBuilderHash, WitnessHash};
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    #[test]
    fn test_verify_small_merkle_proof() {
        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let merkle_proof_gadget = MerkleProofSha256Gadget::add_virtual_to(&mut builder, 3);
        let expected_root_target = builder.add_virtual_hash256_target();
        builder.connect_hash256(expected_root_target, merkle_proof_gadget.root);
        let num_gates = builder.num_gates();
        let data = builder.build::<C>();
        println!(
            "circuit num_gates={}, quotient_degree_factor={}",
            num_gates, data.common.quotient_degree_factor
        );

        let mut pw = PartialWitness::new();
        let proof_serialized = r#"
        {
          "root": "7e286a6721a66675ea033a4dcdec5abbdc7d3c81580e2d6ded7433ed113b7737",
          "siblings": [
            "0000000000000000000000000000000000000000000000000000000000000007",
            "ce44a8ee02db1a76906b0e9fd753893971c4db9a2341b0049d61f7fcd2a60adf",
            "81b1e323f0e91a785dfd155817e09949a7d66fe8fdc4f31f39530845e88ab63c"
          ],
          "index": 2,
          "value": "0000000000000000000000000000000000000000000000000000000000000003"
        }
        "#;
        let proof: MerkleProof256 =
            serde_json::from_str::<MerkleProof256>(proof_serialized).unwrap();
        merkle_proof_gadget.set_witness_from_proof(&mut pw, &proof);
        pw.set_hash256_target(&expected_root_target, &proof.root.0);

        let start_time = std::time::Instant::now();

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_verify_small_delta_merkle_proof() {
        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let merkle_proof_gadget = DeltaMerkleProofSha256Gadget::add_virtual_to(&mut builder, 3);
        let expected_old_root_target = builder.add_virtual_hash256_target();
        let expected_new_root_target = builder.add_virtual_hash256_target();
        builder.connect_hash256(expected_old_root_target, merkle_proof_gadget.old_root);
        builder.connect_hash256(expected_new_root_target, merkle_proof_gadget.new_root);

        let num_gates = builder.num_gates();
        // let copy_constraints = builder.copy_constraints.len();
        let data = builder.build::<C>();
        println!(
            "circuit num_gates={}, quotient_degree_factor={}",
            num_gates, data.common.quotient_degree_factor
        );

        let mut pw = PartialWitness::new();
        let proof_serialized = r#"
      {
        "index": 5,
        "siblings": [
          "0000000000000000000000000000000000000000000000000000000000000004",
          "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
          "2f4d3e941b602c50347af3f5c809a28737c27c7ce460e77b10739875ef957aa7"
        ],
        "old_root": "a5a22d441141c6bfdeaa816a93cdcc879e893e47d4e450c47f65f0cfa65e237c",
        "old_value": "0000000000000000000000000000000000000000000000000000000000000000",
        "new_value": "0000000000000000000000000000000000000000000000000000000000000002",
        "new_root": "c7d129a209e40611a4cc44632f38c6fd577b4329c27dae5a651d2f67c715a618"
      }
      "#;
        let proof = serde_json::from_str::<DeltaMerkleProof256>(proof_serialized).unwrap();
        merkle_proof_gadget.set_witness_from_proof(&mut pw, &proof);
        pw.set_hash256_target(&expected_old_root_target, &proof.old_root.0);
        pw.set_hash256_target(&expected_new_root_target, &proof.new_root.0);

        let start_time = std::time::Instant::now();

        let proof = data.prove(pw).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }
}

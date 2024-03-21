use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    sha256::WitnessHashSha2,
    sha256_merkle::{DeltaMerkleProofSha256Gadget, MerkleProofSha256Gadget},
    types::WitnessHash,
};

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy)]
pub struct Hash256(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 32]);

impl Hash256 {
    pub fn from_str(s: &str) -> Result<Self, ()> {
        let bytes = hex::decode(s).unwrap();
        assert_eq!(bytes.len(), 32);
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct MerkleProof<Hash: PartialEq> {
    pub root: Hash,
    pub value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct DeltaMerkleProof<Hash: PartialEq> {
    pub old_root: Hash,
    pub old_value: Hash,

    pub new_root: Hash,
    pub new_value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}

pub trait MerkleHasher<Hash: PartialEq> {
    fn two_to_one(&self, left: &Hash, right: &Hash) -> Hash;
}

pub fn verify_merkle_proof<Hash: PartialEq, Hasher: MerkleHasher<Hash>>(
    hasher: &Hasher,
    proof: MerkleProof<Hash>,
) -> bool {
    let mut current = proof.value;
    for (_, sibling) in proof.siblings.iter().enumerate() {
        current = hasher.two_to_one(sibling, &current);
    }
    current == proof.root
}

pub fn verify_delta_merkle_proof<Hash: PartialEq, Hasher: MerkleHasher<Hash>>(
    hasher: &Hasher,
    proof: DeltaMerkleProof<Hash>,
) -> bool {
    let mut current = proof.old_value;
    for (_, sibling) in proof.siblings.iter().enumerate() {
        current = hasher.two_to_one(sibling, &current);
    }
    if current != proof.old_root {
        return false;
    }
    current = proof.new_value;
    for (_, sibling) in proof.siblings.iter().enumerate() {
        current = hasher.two_to_one(sibling, &current);
    }
    current == proof.new_root
}

pub type MerkleProof256 = MerkleProof<Hash256>;
pub type DeltaMerkleProof256 = DeltaMerkleProof<Hash256>;

impl MerkleProofSha256Gadget {
    pub fn set_witness_from_proof<F: RichField, W: WitnessHashSha2<F>>(
        &self,
        witness: &mut W,
        merkle_proof: &MerkleProof256,
    ) {
        witness.set_hash256_target(&self.value, &merkle_proof.value.0);
        witness.set_target(self.index, F::from_noncanonical_u64(merkle_proof.index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash256_target(sibling, &merkle_proof.siblings[i].0);
        }
    }
}

impl DeltaMerkleProofSha256Gadget {
    pub fn set_witness_from_proof<F: RichField, W: WitnessHashSha2<F>>(
        &self,
        witness: &mut W,
        merkle_proof: &DeltaMerkleProof256,
    ) {
        witness.set_hash256_target(&self.old_value, &merkle_proof.old_value.0);
        witness.set_hash256_target(&self.new_value, &merkle_proof.new_value.0);
        witness.set_target(self.index, F::from_noncanonical_u64(merkle_proof.index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash256_target(sibling, &merkle_proof.siblings[i].0);
        }
    }
}

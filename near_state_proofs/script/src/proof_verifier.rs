use borsh::BorshDeserialize;
use std::{collections::HashMap, io, sync::Arc};

use crate::nibble_slice::NibbleSlice;
use crate::raw_node::{RawTrieNode, RawTrieNodeWithSize};
use near_primitives::{
    hash::CryptoHash,
    trie_key::trie_key_parsers,
    types::{AccountId, StateRoot},
};

pub(crate) struct ProofVerifier {
    nodes: HashMap<CryptoHash, RawTrieNodeWithSize>,
}

impl ProofVerifier {
    pub(crate) fn new(proof: Vec<Arc<[u8]>>) -> Result<Self, io::Error> {
        let nodes = proof
            .into_iter()
            .map(|bytes| {
                let hash = CryptoHash::hash_bytes(&bytes);
                let node = RawTrieNodeWithSize::try_from_slice(&bytes)?;
                Ok((hash, node))
            })
            .collect::<Result<HashMap<_, _>, io::Error>>()?;
        Ok(Self { nodes })
    }

    pub(crate) fn get_nodes(&self) -> Vec<(CryptoHash, RawTrieNodeWithSize)> {
        self.nodes
            .iter()
            .map(|(crypto_hash, raw_trie_node_with_size)| {
                (*crypto_hash, raw_trie_node_with_size.clone())
            })
            .collect()
    }

    pub(crate) fn get_nodes_hashes(&self) -> Vec<CryptoHash> {
        self.nodes
            .iter()
            .map(|(crypto_hash, _)| *crypto_hash)
            .collect()
    }

    pub(crate) fn verify(
        &self,
        state_root: &StateRoot,
        account_id: &AccountId,
        key: &[u8],
        expected: Option<&[u8]>,
    ) -> bool {
        let query = trie_key_parsers::get_raw_prefix_for_contract_data(account_id, key);
        let mut key = NibbleSlice::new(&query);

        let mut expected_hash = state_root;
        while let Some(node) = self.nodes.get(expected_hash) {
            match &node.node {
                RawTrieNode::Leaf(node_key, value) => {
                    let nib = &NibbleSlice::from_encoded(&node_key).0;
                    return if &key != nib {
                        expected.is_none()
                    } else {
                        expected.map_or(false, |expected| value == expected)
                    };
                }
                RawTrieNode::Extension(node_key, child_hash) => {
                    expected_hash = child_hash;

                    // To avoid unnecessary copy
                    let nib = NibbleSlice::from_encoded(&node_key).0;
                    if !key.starts_with(&nib) {
                        return expected.is_none();
                    }
                    key = key.mid(nib.len());
                }
                RawTrieNode::BranchNoValue(children) => {
                    if key.is_empty() {
                        return expected.is_none();
                    }
                    match children[key.at(0)] {
                        Some(ref child_hash) => {
                            key = key.mid(1);
                            expected_hash = child_hash;
                        }
                        None => return expected.is_none(),
                    }
                }
                RawTrieNode::BranchWithValue(value, children) => {
                    if key.is_empty() {
                        return expected.map_or(false, |exp| value == exp);
                    }
                    match children[key.at(0)] {
                        Some(ref child_hash) => {
                            key = key.mid(1);
                            expected_hash = child_hash;
                        }
                        None => return expected.is_none(),
                    }
                }
            }
        }
        false
    }
}

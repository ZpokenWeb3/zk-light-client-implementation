use crate::types::signature::*;
use crate::types::validators::*;
use near_primitives_core::borsh;
use near_primitives_core::borsh::{BorshDeserialize, BorshSerialize};
use near_primitives_core::hash::CryptoHash;
use near_primitives_core::types::{AccountId, BlockHeight};
use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};

#[cfg(feature = "non-zkvm")]
use {
    crate::types::errors::ConversionError,
    crate::types::errors::ConversionError::BorshSerializationError,
    near_primitives::block_header::BlockHeader,
};

/// Represents the type for signature & public key in bytes.
pub const TYPE_BYTE: usize = 1;
/// Represents the size of protocol version in bytes.
pub const PROTOCOL_VERSION_BYTES: usize = 4;
/// Represents the size of block height in bytes.
pub const BLOCK_HEIGHT_BYTES: usize = 8;
/// Represents the size of stake in bytes.
pub const STAKE_BYTES: usize = 16;
/// Represents the size of a public key or hash in bytes.
pub const PK_HASH_BYTES: usize = 32;
/// Represents the size of a signature in bytes.
pub const SIG_BYTES: usize = 64;
/// Represents the size of a inner lite part of a block in bytes.
pub const INNER_LITE_BYTES: usize = 208;
/// Represents the lenght of one epoch.
pub const EPOCH_DURATION: u64 = 43200;

/// Represents the data of a block header.
///
/// # Fields
///
/// * `hash` - Represents the hash of the current block.
/// * `height` - Represents the height of the current block.
/// * `prev_hash` - Represents the hash of the previous block.
/// * `bp_hash` - Represents the next_bp_hash field of the current block, i.e. the hash of the list of validators.
/// * `epoch_id` - Represents the hash of the epoch of the current block.
/// * `next_epoch_id` - Represents the hash of the next epoch.
/// * `last_ds_final_hash` - Represents the last_ds_final_hash field of the current block.
/// * `last_final_hash` - Represents the last_final_hash field of the current block.
/// * `approvals` - Represents the signatures exracted from the current block, that were created for the previous block.
///
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct HeaderDataFields {
    pub hash: CryptoHash,
    pub height: Option<u64>,
    pub prev_hash: Option<CryptoHash>,
    pub bp_hash: Option<CryptoHash>,
    pub epoch_id: Option<CryptoHash>,
    pub next_epoch_id: Option<CryptoHash>,
    pub last_ds_final_hash: Option<CryptoHash>,
    pub last_final_hash: Option<CryptoHash>,
    pub approvals: Option<Vec<Option<Box<Signature>>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Validators {
    pub validators_n: Vec<ValidatorStake>,
    pub validators_n_1: Option<Vec<ValidatorStake>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Block {
    pub header: HeaderDataFields,
    pub data: Vec<u8>,
    pub block_type: BlockType,
}

impl Block {
    pub fn new(header: HeaderDataFields, data: Vec<u8>, block_type: BlockType) -> Self {
        Block {
            header,
            data,
            block_type,
        }
    }
}

#[cfg(feature = "non-zkvm")]
fn convert_signature(sig: &near_crypto::Signature) -> Option<Box<Signature>> {
    match sig {
        near_crypto::Signature::ED25519(ed25519_sig) => {
            Some(Box::new(Signature::ED25519(ed25519_sig.clone())))
        }
        near_crypto::Signature::SECP256K1(_) => None,
    }
}

#[cfg(feature = "non-zkvm")]
impl TryFrom<(CryptoHash, BlockHeader, BlockType)> for Block {
    type Error = ConversionError;

    fn try_from(value: (CryptoHash, BlockHeader, BlockType)) -> Result<Self, Self::Error> {
        let (block_hash, block_header, block_type) = value;
        let block_data = borsh::to_vec(&block_header).map_err(|_| BorshSerializationError)?;
        let block: Block = match block_type.clone() {
            BlockType::BLOCK => {
                let header = HeaderDataFields {
                    hash: CryptoHash(block_hash.0),
                    height: None,
                    prev_hash: Some(CryptoHash(block_header.prev_hash().0)),
                    bp_hash: Some(CryptoHash(block_header.next_bp_hash().0)),
                    epoch_id: None,
                    next_epoch_id: None,
                    last_ds_final_hash: None,
                    last_final_hash: None,
                    approvals: None,
                };
                Block::new(header, block_data, block_type)
            }
            BlockType::RANDOM => {
                let approvals: Option<Vec<Option<Box<Signature>>>> = Some(
                    block_header
                        .approvals()
                        .iter()
                        .map(|opt_sig| {
                            opt_sig
                                .as_ref()
                                .and_then(|boxed_sig| convert_signature(boxed_sig))
                        })
                        .collect(),
                );
                let header = HeaderDataFields {
                    hash: CryptoHash(block_hash.0),
                    height: Some(block_header.height()),
                    prev_hash: Some(CryptoHash(block_header.prev_hash().0)),
                    bp_hash: Some(CryptoHash(block_header.next_bp_hash().0)),
                    epoch_id: Some(CryptoHash(block_header.epoch_id().0 .0)),
                    next_epoch_id: Some(CryptoHash(block_header.next_epoch_id().0 .0)),
                    last_ds_final_hash: Some(CryptoHash(block_header.last_ds_final_block().0)),
                    last_final_hash: Some(CryptoHash(block_header.last_final_block().0)),
                    approvals,
                };
                Block::new(header, block_data, block_type)
            }
        };
        Ok(block)
    }
}

/// The part of the block approval that is different for endorsements and skips
#[derive(BorshSerialize, BorshDeserialize, serde::Serialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum ApprovalInner {
    Endorsement(CryptoHash),
    Skip(BlockHeight),
}

/// Block approval by other block producers with a signature
#[derive(BorshSerialize, BorshDeserialize, serde::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub inner: ApprovalInner,
    pub target_height: BlockHeight,
    pub signature: Signature,
    pub account_id: AccountId,
}

impl ApprovalInner {
    pub fn new(
        parent_hash: &CryptoHash,
        parent_height: BlockHeight,
        target_height: BlockHeight,
    ) -> Self {
        if target_height == parent_height + 1 {
            ApprovalInner::Endorsement(*parent_hash)
        } else {
            ApprovalInner::Skip(parent_height)
        }
    }
}

impl Approval {
    pub fn get_data_for_sig(inner: &ApprovalInner, target_height: BlockHeight) -> Vec<u8> {
        [
            borsh::to_vec(&inner).unwrap().as_ref(),
            target_height.to_le_bytes().as_ref(),
        ]
        .concat()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum BlockType {
    BLOCK,
    RANDOM,
}

sol! {
    struct PublicValuesRandom{
        uint32 selector;
        bytes32 currentBlockHash;
        bytes32 currentEpochHash;
        bytes32 previousEpochHash;
    }
}

sol! {
    struct PublicValuesEpoch{
        uint32 selector;
        bytes32 currentBlockHash;
        bytes32 previousBlockHash;
        uint64 currentBlockHashHeight;
        uint64 previousBlockHashHeight;
    }
}

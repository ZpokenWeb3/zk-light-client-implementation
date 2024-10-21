use crate::types::signature::Signature;
use crate::types::types::{
    Approval, ApprovalInner, Block, BlockType, Validators, INNER_LITE_BYTES, PK_HASH_BYTES,
    SIG_BYTES, TYPE_BYTE,
};
use crate::types::validators::ValidatorStake;
use near_primitives_core::{
    borsh,
    hash::{hash, CryptoHash},
    types::MerkleHash,
};
use primitive_types::U256;

/// Computes the hash of a block using its components.
///
/// This function computes the hash of a block by combining the hash of its inner parts
/// (`inner_lite` and `inner_rest`) with the previous block hash (`prev_hash`).
///
/// # Arguments
///
/// * `prev_hash` - The hash of the previous block.
/// * `inner_lite` - A byte slice representing the lite inner part of the block.
/// * `inner_rest` - A byte slice representing the rest of the inner part of the block.
///
/// # Returns
///
/// Returns the computed hash of the block.
pub fn compute_hash(prev_hash: &CryptoHash, inner_lite: &[u8], inner_rest: &[u8]) -> CryptoHash {
    let hash_inner = compute_inner_hash(inner_lite, inner_rest);
    combine_hash(&hash_inner, &prev_hash)
}

/// Combines two Merkle hashes into one.
///
/// This function combines two Merkle hashes into a single hash using a borsh serialization.
///
/// # Arguments
///
/// * `hash1` - The first Merkle hash.
/// * `hash2` - The second Merkle hash.
///
/// # Returns
///
/// Returns the combined Merkle hash.
///
pub fn combine_hash(hash1: &MerkleHash, hash2: &MerkleHash) -> MerkleHash {
    CryptoHash::hash_borsh((hash1, hash2))
}

/// Computes the inner hash of a block.
///
/// This function computes the inner hash of a block by hashing its lite inner part
/// (`inner_lite`) and the rest of its inner part (`inner_rest`) and combining them.
///
/// # Arguments
///
/// * `inner_lite` - A byte slice representing the lite inner part of the block.
/// * `inner_rest` - A byte slice representing the rest of the inner part of the block.
///
/// # Returns
///
/// Returns the computed inner hash of the block.
pub fn compute_inner_hash(inner_lite: &[u8], inner_rest: &[u8]) -> CryptoHash {
    let hash_lite = hash(inner_lite);
    let hash_rest = hash(inner_rest);
    combine_hash(&hash_lite, &hash_rest)
}

/// Check hashes for several blocks.
pub fn check_hashes(blocks: &[Block]) {
    assert!(!blocks.is_empty());
    for block in blocks {
        let bi_hash = block.header.hash;
        let bi_header = &block.data;
        let prev_hash_ref = block.header.prev_hash.as_ref().expect("No prev_hash.");

        let bi_hash_computed: CryptoHash = compute_hash(
            prev_hash_ref,
            &bi_header[(TYPE_BYTE + PK_HASH_BYTES)..(TYPE_BYTE + PK_HASH_BYTES + INNER_LITE_BYTES)],
            &bi_header[(TYPE_BYTE + PK_HASH_BYTES + INNER_LITE_BYTES)
                ..(bi_header.len() - TYPE_BYTE - SIG_BYTES)],
        );

        assert_eq!(
            bi_hash, bi_hash_computed,
            "Wrong hash: {} or computed hash: {}.",
            bi_hash, bi_hash_computed
        );
    }
}

/// Check if heights of consecutive blocks are also consecutive.
///
/// height_l - Height of leading block.
/// height_m - Height of the second block.
/// height_f - Height of the first block.
///
/// If the heights are not consecutive, then it is impossible to prove block full finality (BFT).
///
pub fn check_heights(height_l: u64, height_m: u64, height_f: u64) {
    assert_eq!(
        height_f + 1,
        height_m,
        "Heights should be consecutive: height_f + 1 != height_m"
    );
    assert_eq!(
        height_m + 1,
        height_l,
        "Heights should be consecutive: height_m + 1 != height_l"
    );
}

/// Check previous hashes of the set of blocks.
pub fn check_prev_hashes(blocks: &[Block]) {
    assert!(
        (5..=6).contains(&blocks.len()),
        "blocks length must be between 5 and 6."
    );
    let len = blocks.len();
    let mut hash = blocks[len - 1].header.hash;
    let mut i: isize = (len - 2) as isize;
    while i >= 0 {
        let prev_hash = blocks[i as usize].header.prev_hash.expect("No prev_hash.");
        assert_eq!(
            hash, prev_hash,
            "Wrong hash: {} or prev_hash: {}.",
            hash, prev_hash
        );
        hash = blocks[i as usize].header.hash;
        i -= 1;
    }
}

pub fn check_epoch_id(epoch_blocks: &[Block], blocks: &[Block]) {
    assert!(
        (5..=6).contains(&blocks.len()),
        "blocks length must be between 5 and 6."
    );
    // Hash of B_n-1 Epoch_i-2.
    let hash = epoch_blocks[1].header.hash;
    for i in 0..5 {
        let epoch_id = blocks[i].header.epoch_id.expect("No epoch_id");
        assert_eq!(
            hash, epoch_id,
            "Wrong hash: {} or epoch_id for Epoch_i: {}.",
            hash, epoch_id
        );
    }
    // Hash of B_n-1 Epoch_i-3.
    if blocks.len() == 6 {
        let hash = epoch_blocks[2].header.hash;
        let epoch_id = blocks[5].header.epoch_id.expect("No epoch_id");
        assert_eq!(
            hash, epoch_id,
            "Wrong hash: {} or epoch_id for Epoch_i-1: {}.",
            hash, epoch_id
        );
    }
}

pub fn compute_bp_hash(validators: &[ValidatorStake]) -> CryptoHash {
    let validators_len = u32::try_from(validators.len()).unwrap();
    let mut final_bytes =
        Vec::with_capacity(4 + 2 * validators.len() * std::mem::size_of::<ValidatorStake>());
    final_bytes.extend_from_slice(&validators_len.to_le_bytes());
    let count = validators
        .iter()
        .map(|value| {
            final_bytes.extend_from_slice(&borsh::to_vec(value).unwrap());
        })
        .count();
    assert_eq!(count, validators.len());
    hash(&final_bytes)
}

pub fn check_bp_hash(epoch_blocks: &[Block], validators: &Validators) {
    let computed_bp_hash = compute_bp_hash(&validators.validators_n);
    let bp_hash = epoch_blocks[0]
        .header
        .bp_hash
        .expect("No bp_hash for Epoch_i.");
    assert_eq!(
        bp_hash, computed_bp_hash,
        "Wrong next_bp_hash {} or list of validators for Epoch_i: {}.",
        bp_hash, computed_bp_hash
    );
    if epoch_blocks.len() == 3 {
        let validators_n_1 = validators
            .validators_n_1
            .as_ref()
            .expect("No validators for B_n-1.");
        let computed_bp_hash = compute_bp_hash(&validators_n_1);
        let bp_hash = epoch_blocks[1]
            .header
            .bp_hash
            .expect("No bp_hash for Epoch_i-1.");
        assert_eq!(
            bp_hash, computed_bp_hash,
            "Wrong next_bp_hash {} or list of validators for Epoch_i-1: {}.",
            bp_hash, computed_bp_hash
        );
    }
}

/// Generate a message to be signed by validators.
pub fn generate_signed_message(
    ch_height: u64,
    nb_height: u64,
    nb_prev_hash: CryptoHash,
) -> Vec<u8> {
    Approval::get_data_for_sig(
        &if ch_height + 1 == nb_height {
            // If the next block exists, the validators sign the hash of the previous one.
            ApprovalInner::Endorsement(nb_prev_hash)
        } else {
            // If the next block is missed, the validators sign only the missed height.
            ApprovalInner::Skip(ch_height)
        },
        nb_height,
    )
}

pub fn sig_verify(
    msg: &[u8],
    approvals: &[Option<Box<Signature>>],
    validators: &[ValidatorStake],
    validators2: Option<&[ValidatorStake]>,
    block_type: BlockType,
) {
    let mut total_stake: U256 = U256::from(0u8);
    let mut counted_stake: U256 = U256::from(0u8);
    for (pos, approval) in approvals.iter().enumerate() {
        if let Some(sig) = approval {
            let pk = validators[pos].public_key();
            let verify: bool = sig.verify(&msg, pk);
            if !verify {
                match block_type {
                    BlockType::BLOCK => {
                        let validators =
                            validators2.expect("No second list of validators.");
                        let pk = validators[pos].public_key();
                        let verify: bool = sig.verify(&msg, pk);
                        if !verify {
                            panic!("Invalid signature.");
                        }
                    }
                    BlockType::RANDOM => {
                        assert!(validators2.is_none());
                        panic!("Invalid signature.");
                    }
                }
            }
            counted_stake += U256::from(validators[pos].stake());
        }
        total_stake += U256::from(validators[pos].stake());
    }
    // Check counted_stake >= 2/3 of total_stake.
    assert!((U256::from(3u8) * counted_stake) >= (U256::from(2u8) * total_stake));
}

pub fn check_signatures(blocks: &[Block], validators: &Validators) {
    match blocks.len() {
        5 => {
            let len = blocks.len();
            let bi = &blocks[len - 1];
            let bi_1 = &blocks[len - 2];
            let approvals = bi_1
                .header
                .approvals
                .as_ref()
                .expect("No signatures for B_i.");
            let validators = &validators.validators_n;
            let msg = generate_signed_message(
                bi.header.height.expect("No height for B_i."),
                bi_1.header.height.expect("No height for B_i+1."),
                bi_1.header.prev_hash.expect("No prev_hash for B_i."),
            );
            sig_verify(&msg, approvals, validators, None, BlockType::RANDOM);
        }
        6 => {
            let validators_n_1 = validators.validators_n_1.as_ref().expect("No validators.");
            let validators_n = validators.validators_n.as_ref();
            // Check signatures for B_n-1.
            let len = blocks.len();
            let bn_1 = &blocks[len - 1];
            let b0 = &blocks[len - 2];
            let approvals = b0
                .header
                .approvals
                .as_ref()
                .expect("No signatures for Bn-1.");
            let msg = generate_signed_message(
                bn_1.header.height.expect("No height for B_n-1."),
                b0.header.height.expect("No height for B0."),
                b0.header.prev_hash.expect("No prev_hash for B0."),
            );
            sig_verify(
                &msg,
                approvals,
                validators_n_1.as_ref(),
                Some(validators_n),
                BlockType::BLOCK,
            );
            // Check signatures for B0.
            let b1 = &blocks[len - 3];
            let approvals = b1.header.approvals.as_ref().expect("No signatures for B1.");
            let msg = generate_signed_message(
                b0.header.height.expect("No height for B0."),
                b1.header.height.expect("No height for B1."),
                b1.header.prev_hash.expect("No prev_hash for B1."),
            );
            sig_verify(
                &msg,
                approvals,
                &validators_n,
                Some(validators_n_1),
                BlockType::BLOCK,
            );
        }
        _ => {
            panic!("Invalid blocks.len() {}", blocks.len());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rpc::{JsonClient, ARCHIVAL_RPC};
    use crate::test_utils::*;
    use crate::verification::*;
    use near_primitives_core::{
        hash::{hash, CryptoHash},
        types::MerkleHash,
    };

    #[test]
    fn test_compute_hash() {
        let random_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let h1 = hash(&random_bytes);
        let h = compute_hash(&h1, &random_bytes.clone(), &random_bytes.clone());
        // expected
        let in1 = hash(&random_bytes.clone());
        let in2 = hash(&random_bytes.clone());
        let in3 = CryptoHash::hash_borsh((in1, in2));
        let c_h = CryptoHash::hash_borsh((in3, h1));
        assert_eq!(c_h, h);
    }

    #[test]
    fn test_combine_hash() {
        let random_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let h1 = hash(&random_bytes);
        let random_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let h2 = hash(&random_bytes);
        let c_h = combine_hash(&h1, &h2);
    }

    #[test]
    fn test_compute_inner_hash() {
        let RND: usize = 1000;
        let random_bytes1: Vec<u8> = (0..RND).map(|_| rand::random::<u8>()).collect();
        let random_bytes2: Vec<u8> = (0..RND).map(|_| rand::random::<u8>()).collect();
        let c_h = compute_inner_hash(&random_bytes1, &random_bytes2);
    }

    #[tokio::test]
    async fn test_check_hashes() {
        let client = JsonClient::setup(None).unwrap();
        let mut blocks = vec![];
        let mut height: u64 = 121751508;
        for i in 0..5 {
            let result = client.load_block_by_height_from_rpc(height).await;
            assert!(result.is_ok(), "Failed to load block from RPC");
            let block = result.unwrap();
            blocks.push(Block::try_from((block.0, block.1, BlockType::RANDOM)).expect("Error creating block."));
            height += 1;
        }

        check_hashes(&blocks);
    }

    #[tokio::test]
    async fn test_check_prev_hashes() {
        let client = JsonClient::setup(Some(ARCHIVAL_RPC.to_string())).unwrap();
        let mut blocks = vec![];
        let mut height: u64 = 121857713;
        for i in 0..5 {
            let result = client.load_block_by_height_from_rpc(height).await;
            assert!(result.is_ok(), "Failed to load block from RPC");
            let block = result.unwrap();
            blocks.push(Block::try_from((block.0, block.1, BlockType::RANDOM)).expect("Error creating block."));
            height += 1;
        }

        check_prev_hashes(&blocks);
    }

    #[test]
    fn test_check_heights() {
        let random_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let h = hash(&random_bytes);
        let random_h1: u64 = rand::random::<u64>();
        let random_h2: u64 = random_h1 + 1;
        let random_h3: u64 = random_h2 + 1;
        check_heights(random_h3, random_h2, random_h1);
    }

    #[test]
    #[should_panic]
    fn test_check_heights_wrong() {
        let random_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let h = hash(&random_bytes);
        let random_h1: u64 = rand::random::<u64>();
        let random_h2: u64 = random_h1 + 1;
        let random_h3: u64 = random_h2 + 1;
        check_heights(random_h1, random_h2, random_h3);
    }

    #[test]
    fn test_generate_signed_message_with_hash() {
        let random_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let h = hash(&random_bytes);
        let random_h1: u64 = rand::random::<u64>();
        let random_h2: u64 = random_h1 + 1;
        let msg = generate_signed_message(random_h1, random_h2, h);
        assert!(msg.len() == 41);
    }

    #[test]
    fn test_generate_signed_message_with_height() {
        let random_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let h = hash(&random_bytes);
        let random_h1: u64 = rand::random::<u64>();
        let random_h2: u64 = random_h1 + 3;
        let msg = generate_signed_message(random_h1, random_h2, h);
        assert!(msg.len() == 17);
    }

    #[tokio::test]
    async fn test_check_bp_hash() {
        let hash = "317HEkq9TQ6fJ9qkHhiy9MbbXgKbFgMZyqqRjDGbBoiz";
        let mut client = JsonClient::setup(None).unwrap();
        client
            .check_rpc_correctness(hash)
            .await
            .unwrap();
        let result = client
            .set_validators_from_rpc(hash, None)
            .await;
        assert!(result.is_ok(), "Failed to load validators from RPC");
        let validators = result.unwrap();

        let hash = "Envut7DwFF4Gbjg5uHHFnQ9om9Zo5FK43H6outpRJveV";
        client
            .check_rpc_correctness(hash)
            .await
            .unwrap();
        let result = client.load_block_by_hash_from_rpc(hash).await;
        assert!(result.is_ok(), "Failed to load block from RPC");
        let block = result.unwrap();

        check_bp_hash(
            &[Block::try_from((block.0, block.1, BlockType::RANDOM)).expect("Error creating block.")].to_vec(),
            &validators
        );
    }

    #[tokio::test]
    async fn test_check_epoch_id() {
        let client = JsonClient::setup(None).unwrap();
        let mut blocks = vec![];
        let mut height: u64 = 121857713;
        for i in 0..5 {
            let result = client.load_block_by_height_from_rpc(height).await;
            assert!(result.is_ok(), "Failed to load block from RPC");
            let block = result.unwrap();
            blocks.push(Block::try_from((block.0, block.1, BlockType::RANDOM)).expect("Error creating block."));
            height += 1;
        }

        let hash = "CRTZ7cQd77rvfS57Y7M36P1vLhran9HyQFEpTLxHRf9t";
        let mut client = JsonClient::setup(None).unwrap();
        client
            .check_rpc_correctness(hash)
            .await
            .unwrap();
        let result = client.load_block_by_hash_from_rpc(hash).await;
        assert!(result.is_ok(), "Failed to load block from RPC");
        let block = result.unwrap();

        let mut epoch_blocks = vec![];
        epoch_blocks.push(Block::try_from((block.0, block.1, BlockType::BLOCK)).expect("Error creating block."));
        epoch_blocks.push(epoch_blocks[0].clone());

        check_epoch_id(&epoch_blocks, &blocks);
    }

    #[tokio::test]
    async fn test_check_signatures() {
        let mut client = JsonClient::setup(None).unwrap();
        let mut blocks = vec![];
        let mut height: u64 = 121798939;
        for i in 0..5 {
            let result = client.load_block_by_height_from_rpc(height).await;
            assert!(result.is_ok(), "Failed to load block from RPC");
            let block = result.unwrap();
            blocks.push(Block::try_from((block.0, block.1, BlockType::RANDOM)).expect("Error creating block."));
            height += 1;
        }

        let hash = blocks[0].header.hash.to_string();
        client
            .check_rpc_correctness(&hash)
            .await
            .unwrap();
        let result = client
            .set_validators_from_rpc(&hash, None)
            .await;
        assert!(result.is_ok(), "Failed to load validators from RPC");
        let validators = result.unwrap();

        check_signatures(&blocks, &validators);
    }
}

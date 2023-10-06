// use near_primitives::hash::CryptoHash;
//
// pub fn compute_bp_hash(
//         epoch_manager: &dyn EpochManagerAdapter,
//         epoch_id: EpochId,
//         prev_epoch_id: EpochId,
//         last_known_hash: &CryptoHash,
//     ) -> Result<CryptoHash, Error> {
//         let bps = epoch_manager.get_epoch_block_producers_ordered(&epoch_id, last_known_hash)?;
//         let protocol_version = epoch_manager.get_epoch_protocol_version(&prev_epoch_id)?;
//         if checked_feature!("stable", BlockHeaderV3, protocol_version) {
//             let validator_stakes = bps.into_iter().map(|(bp, _)| bp);
//             Ok(CryptoHash::hash_borsh_iter(validator_stakes))
//         } else {
//             let validator_stakes = bps.into_iter().map(|(bp, _)| bp.into_v1());
//             Ok(CryptoHash::hash_borsh_iter(validator_stakes))
//         }
//     }
//


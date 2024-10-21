use near_primitives_core::types::{AccountId, Balance};
use near_primitives_core::borsh::{BorshDeserialize, BorshSerialize};
use serde::{Serialize, Deserialize};
use crate::types::signature::*;

/// Stores validator and its stake.
#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ValidatorStake {
    V1(ValidatorStakeV1),
}

impl ValidatorStake {
    pub fn new_v1(account_id: AccountId, public_key: PublicKey, stake: Balance) -> Self {
        Self::V1(ValidatorStakeV1 { account_id, public_key, stake })
    }

    pub fn new(account_id: AccountId, public_key: PublicKey, stake: Balance) -> Self {
        Self::new_v1(account_id, public_key, stake)
    }

    pub fn test(account_id: AccountId) -> Self {
        Self::new_v1(account_id, PublicKey::empty(KeyType::ED25519), 0)
    }

    pub fn into_v1(self) -> ValidatorStakeV1 {
        match self {
            Self::V1(v1) => v1,
        }
    }

    #[inline]
    pub fn account_and_stake(self) -> (AccountId, Balance) {
        match self {
            Self::V1(v1) => (v1.account_id, v1.stake),
        }
    }

    #[inline]
    pub fn destructure(self) -> (AccountId, PublicKey, Balance) {
        match self {
            Self::V1(v1) => (v1.account_id, v1.public_key, v1.stake),
        }
    }

    #[inline]
    pub fn take_account_id(self) -> AccountId {
        match self {
            Self::V1(v1) => v1.account_id,
        }
    }

    #[inline]
    pub fn account_id(&self) -> &AccountId {
        match self {
            Self::V1(v1) => &v1.account_id,
        }
    }

    #[inline]
    pub fn take_public_key(self) -> PublicKey {
        match self {
            Self::V1(v1) => v1.public_key,
        }
    }

    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        match self {
            Self::V1(v1) => &v1.public_key,
        }
    }

    #[inline]
    pub fn stake(&self) -> Balance {
        match self {
            Self::V1(v1) => v1.stake,
        }
    }

    #[inline]
    pub fn stake_mut(&mut self) -> &mut Balance {
        match self {
            Self::V1(v1) => &mut v1.stake,
        }
    }

    pub fn get_approval_stake(&self, is_next_epoch: bool) -> ApprovalStake {
        ApprovalStake {
            account_id: self.account_id().clone(),
            public_key: self.public_key().clone(),
            stake_this_epoch: if is_next_epoch { 0 } else { self.stake() },
            stake_next_epoch: if is_next_epoch { self.stake() } else { 0 },
        }
    }

    /// Returns the validator's number of mandates (rounded down) at `stake_per_seat`.
    ///
    /// It returns `u16` since it allows infallible conversion to `usize` and with [`u16::MAX`]
    /// equalling 65_535 it should be sufficient to hold the number of mandates per validator.
    ///
    /// # Why `u16` should be sufficient
    ///
    /// As of October 2023, a [recommended lower bound] for the stake required per mandate is
    /// 25k $NEAR. At this price, the validator with highest stake would have 1_888 mandates,
    /// which is well below `u16::MAX`.
    ///
    /// From another point of view, with more than `u16::MAX` mandates for validators, sampling
    /// mandates might become computationally too expensive. This might trigger an increase in
    /// the required stake per mandate, bringing down the number of mandates per validator.
    ///
    /// [recommended lower bound]: https://near.zulipchat.com/#narrow/stream/407237-pagoda.2Fcore.2Fstateless-validation/topic/validator.20seat.20assignment/near/393792901
    ///
    /// # Panics
    ///
    /// Panics if the number of mandates overflows `u16`.
    pub fn num_mandates(&self, stake_per_mandate: Balance) -> u16 {
        // Integer division in Rust returns the floor as described here
        // https://doc.rust-lang.org/std/primitive.u64.html#method.div_euclid
        u16::try_from(self.stake() / stake_per_mandate)
            .expect("number of mandats should fit u16")
    }

    /// Returns the weight attributed to the validator's partial mandate.
    ///
    /// A validator has a partial mandate if its stake cannot be divided evenly by
    /// `stake_per_mandate`. The remainder of that division is the weight of the partial
    /// mandate.
    ///
    /// Due to this definintion a validator has exactly one partial mandate with `0 <= weight <
    /// stake_per_mandate`.
    ///
    /// # Example
    ///
    /// Let `V` be a validator with stake of 12. If `stake_per_mandate` equals 5 then the weight
    /// of `V`'s partial mandate is `12 % 5 = 2`.
    pub fn partial_mandate_weight(&self, stake_per_mandate: Balance) -> Balance {
        self.stake() % stake_per_mandate
    }
}

/// Stores validator and its stake.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize
)]
pub struct ValidatorStakeV1 {
    /// Account that stakes money.
    pub account_id: AccountId,
    /// Public key of the proposed validator.
    pub public_key: PublicKey,
    /// Stake / weight of the validator.
    pub stake: Balance,
}

/// Stores validator and its stake for two consecutive epochs.
/// It is necessary because the blocks on the epoch boundary need to contain approvals from both
/// epochs.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ApprovalStake {
    /// Account that stakes money.
    pub account_id: AccountId,
    /// Public key of the proposed validator.
    pub public_key: PublicKey,
    /// Stake / weight of the validator.
    pub stake_this_epoch: Balance,
    pub stake_next_epoch: Balance,
}

mod deposit;

mod view;

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::U128;
use near_sdk::require;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near_bindgen, AccountId, Balance, PromiseOrValue};

use std::str::FromStr;

pub type WBalance = U128;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct VaultContract {
    pub sender: AccountId,
    pub receiver_addr: AccountId,
    pub asset_id: AccountId,
    pub deposited_amount: Balance,
    pub count_param: Balance,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct BridgeInfo {
    pub receiver_addr: AccountId,
    pub asset_id: AccountId,
    pub deposited_amount: Balance,
}

impl Default for VaultContract {
    fn default() -> Self {
        env::panic_str("Contract should be initialized before usage")
    }
}

#[near_bindgen]
impl VaultContract {
    #[init]
    pub fn initialize_vault_contract(count_param: u128) -> Self {
        require!(!env::state_exists(), "Already initialized");

        Self {
            sender: AccountId::from_str("whatever").unwrap(),
            receiver_addr: AccountId::from_str("whatever").unwrap(),
            asset_id: AccountId::from_str("whatever").unwrap(),
            deposited_amount: 0,
            count_param,
        }
    }
}

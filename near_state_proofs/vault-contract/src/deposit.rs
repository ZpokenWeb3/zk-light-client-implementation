use crate::*;

#[near_bindgen]
impl VaultContract {
    pub fn deposit(
        &mut self,
        receiver_addr: AccountId,
        asset_id: AccountId,
        token_amount: WBalance,
    ) -> PromiseOrValue<WBalance> {
        let sender_id = env::signer_account_id();

        self.count_param += 1;

        self.receiver_addr = receiver_addr.clone();
        self.deposited_amount = token_amount.0.clone();
        self.asset_id = asset_id.clone();
        self.sender = sender_id;


        PromiseOrValue::Value(U128::from(0))
    }
}

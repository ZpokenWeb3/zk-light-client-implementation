use crate::*;

#[near_bindgen]
impl VaultContract {
    pub fn view_sender(&self) -> String {
        self.sender.clone().to_string()
    }

    pub fn view_receiver_addr(&self) -> String {
        self.receiver_addr.clone().to_string()
    }

    pub fn view_asset_id(&self) -> String {
        self.asset_id.clone().to_string()
    }

    pub fn view_deposited_amount(&self) -> WBalance {
        self.deposited_amount.into()
    }

    pub fn view_count(&self) -> u128 {
        self.count_param.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_single_slots() {
        let contract = VaultContract::initialize_vault_contract(12);

        let asset_id = contract.view_asset_id();
        let receiver_addr = contract.view_receiver_addr();
        let deposited_amount = contract.view_deposited_amount();
        let sender = contract.view_sender();

        dbg!(asset_id);
        dbg!(receiver_addr);
        dbg!(deposited_amount);
        dbg!(sender);
    }
}

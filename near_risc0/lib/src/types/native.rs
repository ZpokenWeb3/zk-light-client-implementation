use near_primitives_core::borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use crate::types::types::*;

#[derive(Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq)]
pub struct ProverInput{
    pub epoch_blocks: Vec<Block>,
    pub blocks: Vec<Block>,
    pub validators: Validators,
}

#[cfg(test)]
#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use near_primitives_core::borsh::{from_slice, to_vec};
    use crate::types::native::ProverInput;
    use crate::test_utils::{set_blocks, set_validators};

    const DEFAULT_PATH: &str = "../../data/epochs";

    #[test]
    pub fn test_deser(){
        let epoch_id_i = "CRTZ7cQd77rvfS57Y7M36P1vLhran9HyQFEpTLxHRf9t".to_string();
        let epoch_id_i_1 = "HPi5yyZHZ91t5S4SPAAfEZwGYEqq5i6QjzXoVMi8ksae".to_string();
        let epoch_id_i_2 = "3JMehuv86nBynJ33VBUGAvfd9Ts8EfvytGJ8i8e45XPi".to_string();
        let epoch_id_i_3 = "89PT9SkLXB1FZHvW7EdQHxiSpm5ybuTCvjrGZWWhXMTz".to_string();

        let (epoch_blocks, blocks) = set_blocks(
            DEFAULT_PATH,
            epoch_id_i.clone(),
            epoch_id_i_1.clone(),
            epoch_id_i_2.clone(),
            Some(epoch_id_i_3.clone()),
        ).expect("Failed to read expected test data");
        let validators = set_validators(
            DEFAULT_PATH,
            3,
            &epoch_id_i,
            &epoch_id_i_1,
        ).expect("Failed to read expected test data");
        let input = ProverInput{
            epoch_blocks,
            blocks,
            validators
        };

        let encoded = to_vec(&input).unwrap();
        let decoded = from_slice::<ProverInput>(&encoded).unwrap();

        assert_eq!(decoded, input);
    }
}

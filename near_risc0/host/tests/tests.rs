#[cfg(test)]
mod tests {
    use lib::test_utils::{parse_block_hash, set_blocks, set_validators};
    use lib::types::native::ProverInput;
    use methods::{NEAR_RISC0_ELF, NEAR_RISC0_ID};
    use near_primitives_core::borsh::to_vec;
    use near_primitives_core::hash::CryptoHash;
    use risc0_zkvm::{default_prover, ExecutorEnv};
    use std::env;
    use alloy_sol_types::SolType;
    use lib::types::types::PublicValuesEpoch;

    const DEFAULT_PATH: &str = "../../data/epochs";

    #[test]
    fn test_prove_bft() -> anyhow::Result<()>{
        env::set_var("RISC0_DEV_MODE", "1");

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
        )?;

        // Set the list(s) of validators.
        let validators = set_validators(
            DEFAULT_PATH,
            epoch_blocks.len(),
            &epoch_id_i,
            &epoch_id_i_1,
        )?;

        let input = ProverInput {
            epoch_blocks,
            blocks,
            validators,
        };

        let encoded = to_vec(&input).unwrap();

        let env = ExecutorEnv::builder()
            .write_slice(&encoded)
            .build()
            .unwrap();

        let prover = default_prover();
        let receipt = prover
            .prove(env, NEAR_RISC0_ELF)
            .unwrap()
            .receipt;

        let journal = receipt.journal.bytes.clone();
        let output: PublicValuesEpoch = PublicValuesEpoch::abi_decode(&journal, true)?;

        let previous_hash = CryptoHash(output.previousBlockHash.0);
        let current_hash = CryptoHash(output.currentBlockHash.0);

        let epoch_id_i_hash_0 = parse_block_hash("CbAHBGJ8VQot2m6KhH9PLasMgcDtkPJBfp9bjAEMJ8UK").unwrap();
        let epoch_id_i_1_hash_last = parse_block_hash("4RjXBrNcu39wutFTuFpnRHgNqgHxLMcGBKNEQdtkSBhy").unwrap();

        assert_eq!(previous_hash, epoch_id_i_1_hash_last);
        assert_eq!(current_hash, epoch_id_i_hash_0);

        receipt.verify(NEAR_RISC0_ID).unwrap();

        Ok(())
    }

    #[should_panic(expected = "Guest panicked: assertion `left == right`")]
    #[test]
    fn test_prove_bft_incorrect_block(){
        env::set_var("RISC0_DEV_MODE", "1");

        let epoch_id_i = "CRTZ7cQd77rvfS57Y7M36P1vLhran9HyQFEpTLxHRf9t".to_string();
        let epoch_id_i_1 = "HPi5yyZHZ91t5S4SPAAfEZwGYEqq5i6QjzXoVMi8ksae".to_string();
        let epoch_id_i_2 = "3JMehuv86nBynJ33VBUGAvfd9Ts8EfvytGJ8i8e45XPi".to_string();
        let epoch_id_i_3 = "89PT9SkLXB1FZHvW7EdQHxiSpm5ybuTCvjrGZWWhXMTz".to_string();
        let (epoch_blocks, blocks) = set_blocks(
            DEFAULT_PATH,
            epoch_id_i_1.clone(),
            epoch_id_i.clone(),
            epoch_id_i_2.clone(),
            Some(epoch_id_i_3.clone()),
        ).unwrap();

        // Set the list(s) of validators.
        let validators = set_validators(
            DEFAULT_PATH,
            epoch_blocks.len(),
            &epoch_id_i,
            &epoch_id_i_1,
        ).unwrap();

        let input = ProverInput {
            epoch_blocks,
            blocks,
            validators,
        };

        let encoded = to_vec(&input).unwrap();

        let env = ExecutorEnv::builder()
            .write_slice(&encoded)
            .build()
            .unwrap();

        let prover = default_prover();
        let _ = prover
            .prove(env, NEAR_RISC0_ELF)
            .unwrap();
    }
}
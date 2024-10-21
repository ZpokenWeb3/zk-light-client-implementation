use crate::error::ServiceError;
use crate::types::{EpochProvingResult, EpochProvingTask, RandomProvingResult, RandomProvingTask};
use crate::util::encode_seal;
use alloy_sol_types::SolType;
use lib::rpc::JsonClient;
use lib::types::types::{PublicValuesEpoch, PublicValuesRandom};
use methods::{NEAR_RISC0_ELF, NEAR_RISC0_ID};
use near_primitives_core::borsh::to_vec;
use near_primitives_core::hash::CryptoHash;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};

pub async fn generate_epoch_proof(task: &EpochProvingTask) -> Result<EpochProvingResult, ServiceError> {
    let mut client = JsonClient::setup(None)
        .map_err(|_| ServiceError::InternalServiceError(String::from("Can't create client")))?;
    let input = client.prepare_input(
        task.epoch_id_i_block_hash.as_str(),
        Some(task.epoch_id_i_1_block_hash_last.as_str()),
        task.epoch_id_i_1_block_hash.as_str(),
        task.epoch_id_i_2_block_hash.as_str(),
        Some(task.epoch_id_i_3_block_hash_last.as_str()),
    ).await.map_err(|err| ServiceError::ClientError(err))?;
    let encoded = to_vec(&input)
        .map_err(|_| ServiceError::SerializationError(format!("Failed to serialize input using Borsh: {:?}", input)))?;

    let env = ExecutorEnv::builder()
        .write_slice(&encoded)
        .build()
        .map_err(|_| ServiceError::InternalServiceError(String::from("Environment build failed")))?;

    let prover = default_prover();

    let prove_info = prover
        .prove(env, NEAR_RISC0_ELF)
        .map_err(|_| ServiceError::ProvingError(format!("Failed to prove payload: {:?}", task)))?;

    let receipt = prove_info.receipt;

    receipt
        .verify(NEAR_RISC0_ID)
        .map_err(|_| ServiceError::VerificationError(format!("Failed to verify payload: {:?}", task)))?;

    let journal = receipt.journal.bytes.clone();

    let output: PublicValuesEpoch = PublicValuesEpoch::abi_decode(&journal, true)
        .map_err(|_| ServiceError::DeserializationError("Failed to deserialize output from ZKVM".to_string()))?;

    let block_hash_n_1 = CryptoHash(output.previousBlockHash.0);
    let block_hash_n_0 = CryptoHash(output.currentBlockHash.0);
    let block_height_n_0 = output.currentBlockHashHeight;

    Ok(EpochProvingResult {
        block_hash_n_1: block_hash_n_1.to_string(),
        block_hash_n_0: block_hash_n_0.to_string(),
        status: "OK".to_string(),
        block_height_n_0,
    })
}

pub async fn generate_random_proof(task: &RandomProvingTask) -> Result<RandomProvingResult, ServiceError> {
    let mut client = JsonClient::setup(None)
        .map_err(|_| ServiceError::InternalServiceError(String::from("Can't create client")))?;
    let input = client.prepare_input(
        task.epoch_id_i_hash_i.as_str(),
        None,
        task.epoch_id_i_1_hash_0.as_str(),
        task.epoch_id_i_2_hash_last_str.as_str(),
        None,
    ).await.map_err(|err| ServiceError::ClientError(err))?;
    let encoded = to_vec(&input)
        .map_err(|_| ServiceError::SerializationError(format!("Failed to serialize input using Borsh: {:?}", input)))?;

    let env = ExecutorEnv::builder()
        .write_slice(&encoded)
        .build()
        .map_err(|_| ServiceError::InternalServiceError(String::from("Environment build failed")))?;

    let receipt = default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            NEAR_RISC0_ELF,
            &ProverOpts::groth16(),
        )
        .unwrap()
        .receipt;
    let journal = receipt.journal.bytes.clone();
    println!("LEN: {:?}", journal.len());

    let output: PublicValuesRandom = PublicValuesRandom::abi_decode(&journal, true)
        .map_err(|_| ServiceError::DeserializationError("Failed to deserialize output from ZKVM".to_string()))?;

    receipt
        .verify(NEAR_RISC0_ID)
        .map_err(|_| ServiceError::VerificationError(format!("Failed to verify payload: {:?}", task)))?;

    let epoch_id_i_block_hash = CryptoHash(output.currentBlockHash.0);

    let proof = format!("0x{}", hex::encode(encode_seal(&receipt).unwrap()));
    let journal_hex_string = format!("0x{}", hex::encode(journal));
    Ok(RandomProvingResult {
        epoch_id_i_block_hash: epoch_id_i_block_hash.to_string(),
        journal: journal_hex_string,
        proof,
        status: "OK".to_string(),
    })
}
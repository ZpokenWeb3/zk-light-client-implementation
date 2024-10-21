use lib::rpc::JsonClientError;

#[derive(Debug, Clone, thiserror::Error)]
pub enum ServiceError {
    #[error("Proving error: {0}")]
    ProvingError(String),

    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Proving preparation error: {0}")]
    ProvingPreparationError(String),

    #[error("Client error: {0}")]
    ClientError(#[from] JsonClientError),

    #[error("Internal service error: {0}")]
    InternalServiceError(String),

    #[error("Unexpected service error: {0}")]
    UnexpectedServiceError(String),
}


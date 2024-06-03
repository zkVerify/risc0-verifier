// Copyright 2024, The Horizen Foundation
// LICENSE TO BE ADDED [TODO]

mod deserializer;
mod proof;

use deserializer::*;
pub use proof::ProofRawData;
use risc0_zkvm::*;
use snafu::*;

/// Deserialization error.
#[derive(Debug, Snafu)]
pub enum VerifyError {
    #[snafu(display("Invalid data for verification: [{:?}]", cause))]
    InvalidData {
        #[snafu(source)]
        cause: DeserializeError,
    },
    #[snafu(display("Failed to verify: [{:?}]", cause))]
    Failure {
        cause: risc0_zkp::verify::VerificationError,
    },
}

impl From<DeserializeError> for VerifyError {
    fn from(value: DeserializeError) -> Self {
        VerifyError::InvalidData { cause: value }
    }
}

impl From<risc0_zkp::verify::VerificationError> for VerifyError {
    fn from(value: risc0_zkp::verify::VerificationError) -> Self {
        VerifyError::Failure { cause: value }
    }
}

pub struct Vk(risc0_zkp::core::digest::Digest);

impl From<[u32; 8]> for Vk {
    fn from(value: [u32; 8]) -> Self {
        Self(value.into())
    }
}

pub fn verify(proof: ProofRawData, image_id: Vk) -> Result<(), VerifyError> {
    let receipt = deserialize(&proof)?;
    receipt.verify(image_id.0).map_err(Into::into)
}

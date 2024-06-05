// Copyright 2024, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

mod deserializer;
mod key;
mod proof;

pub use deserializer::extract_pubs_from_full_proof;
use deserializer::{deserialize, extract_pubs_from_receipt, DeserializeError};
pub use key::Vk;
pub use proof::{FullProof, PublicInputs};
use snafu::Snafu;

/// Deserialization error.
#[derive(Debug, Snafu)]
pub enum VerifyError {
    /// Invalid data (not deserializable)
    #[snafu(display("Invalid data for verification: [{}]", cause))]
    InvalidData {
        /// Internal error
        #[snafu(source)]
        cause: DeserializeError,
    },
    /// Mismatching public inputs
    #[snafu(display("Mismatching public inputs"))]
    MismatchingPublicInputs,
    /// Verification failure
    #[snafu(display("Failed to verify: [{}]", cause))]
    Failure {
        /// Internal error
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

/// Verify the given proof and public inputs `full_proof` using verification key `image_id`.
/// Can fail if:
/// - the full proof is not serializable as a `risc0_zkvm::Receipt`
/// - the receipt is not valid for the given verification key
pub fn verify(image_id: Vk, full_proof: FullProof, pubs: PublicInputs) -> Result<(), VerifyError> {
    let receipt = deserialize(full_proof)?;
    let extracted_pubs = extract_pubs_from_receipt(&receipt)?;
    if pubs == extracted_pubs {
        receipt.verify(image_id.0).map_err(Into::into)
    } else {
        Err(VerifyError::MismatchingPublicInputs)
    }
}

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

use deserializer::{deserialize, DeserializeError};
pub use key::Vk;
pub use proof::ProofRawData;
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

/// Verify the given proof raw data `proof` using verification key `image_id`.
/// Can fail if:
/// - the raw proof data is not serializable as a `risc0_zkvm::Receipt`
/// - the receipt is not valid for the given verification key
pub fn verify(raw_proof_data: ProofRawData, image_id: Vk) -> Result<(), VerifyError> {
    let receipt = deserialize(raw_proof_data)?;
    receipt.verify(image_id.0).map_err(Into::into)
}

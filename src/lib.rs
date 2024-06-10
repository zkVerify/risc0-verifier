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

use deserializer::deserialize_full_proof;
pub use deserializer::DeserializeError;
pub use key::Vk;
pub use proof::{Proof, PublicInputs};
use snafu::Snafu;

/// Deserialization error.
#[derive(Debug, Snafu)]
pub enum VerifyError {
    /// Invalid data
    #[snafu(display("Invalid data for verification: [{}]", cause))]
    InvalidData {
        /// Internal error
        #[snafu(source)]
        cause: DeserializeError,
    },
    /// Failure
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

/// Verify the given proof `proof` and public inputs `pubs` using verification key `vk`.
/// Use the given verification key `vk` to verify the proof `proof` against the public inputs `pubs`.
/// Can fail if:
/// - the proof or the pubs are not serializable respectively as a `risc0_zkvm::InnerReceipt` and a `risc0_zkvm::Journal`
/// - the proof is not valid
pub fn verify(vk: Vk, proof: Proof, pubs: PublicInputs) -> Result<(), VerifyError> {
    let receipt = deserialize_full_proof(proof, pubs)?;
    receipt.verify(vk.0).map_err(Into::into)
}

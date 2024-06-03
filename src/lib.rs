// Copyright 2024, The Horizen Foundation
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

#![cfg_attr(not(feature = "std"), no_std)]

mod deserializer;
mod proof;

use deserializer::{deserialize, DeserializeError};
pub use proof::ProofRawData;
use snafu::Snafu;

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
    let receipt = deserialize(proof)?;
    receipt.verify(image_id.0).map_err(Into::into)
}

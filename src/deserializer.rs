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

use crate::proof::{FullProof, PublicInputs};
use risc0_zkvm::Receipt;
use snafu::Snafu;

/// Deserialization error
#[derive(Debug, Snafu)]
pub enum DeserializeError {
    #[snafu(display("Invalid data for deserialization"))]
    InvalidData,
    #[snafu(display("Invalid public inputs for deserialization"))]
    InvalidPublicInputs,
}

pub fn deserialize(byte_stream: &[u8]) -> Result<Receipt, DeserializeError> {
    bincode::deserialize(byte_stream).map_err(|_x| DeserializeError::InvalidData)
}

/// Extract public inputs from full proof
pub fn extract_pubs_from_full_proof(
    full_proof: FullProof,
) -> Result<PublicInputs, DeserializeError> {
    let receipt = deserialize(full_proof)?;

    let mut pubs: PublicInputs = [0; 32];
    let len = receipt.journal.bytes.len();
    if len <= 32 {
        pubs[..len].copy_from_slice(&receipt.journal.bytes[..len]);
    } else {
        return Err(DeserializeError::InvalidPublicInputs);
    }

    Ok(pubs)
}

pub fn extract_pubs_from_receipt(receipt: &Receipt) -> Result<PublicInputs, DeserializeError> {
    let mut pubs: PublicInputs = [0; 32];
    let len = receipt.journal.bytes.len();
    if len <= 32 {
        pubs[..len].copy_from_slice(&receipt.journal.bytes[..len]);
    } else {
        return Err(DeserializeError::InvalidPublicInputs);
    }

    Ok(pubs)
}

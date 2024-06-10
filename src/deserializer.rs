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

use risc0_zkvm::{InnerReceipt, Journal, Receipt};
use snafu::Snafu;

/// Deserialization error
#[derive(Debug, Snafu)]
pub enum DeserializeError {
    /// Invalid proof
    #[snafu(display("Invalid proof for deserialization"))]
    InvalidProof,
    /// Invalid public inputs
    #[snafu(display("Invalid public inputs for deserialization"))]
    InvalidPublicInputs,
}

pub fn deserialize_full_proof(proof: &[u8], pubs: &[u8]) -> Result<Receipt, DeserializeError> {
    let inner_receipt_des = deserialize_proof(proof)?;
    let journal_des = deserialize_pubs(pubs)?;
    Ok(Receipt::new(inner_receipt_des, journal_des.bytes))
}

fn deserialize_proof(proof: &[u8]) -> Result<InnerReceipt, DeserializeError> {
    bincode::deserialize(proof).map_err(|_x| DeserializeError::InvalidProof)
}

fn deserialize_pubs(pubs: &[u8]) -> Result<Journal, DeserializeError> {
    bincode::deserialize(pubs).map_err(|_x| DeserializeError::InvalidPublicInputs)
}

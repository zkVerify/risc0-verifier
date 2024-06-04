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

use risc0_zkvm::Receipt;
use snafu::Snafu;

/// Deserialization error
#[derive(Debug, Snafu)]
pub enum DeserializeError {
    #[snafu(display("Invalid data for deserialization: [{:?}...{:?}]", first, last))]
    InvalidData { first: Option<u8>, last: Option<u8> },
}

pub fn deserialize(byte_stream: &[u8]) -> Result<Receipt, DeserializeError> {
    bincode::deserialize(byte_stream).map_err(|_x| DeserializeError::InvalidData {
        first: byte_stream.first().copied(),
        last: byte_stream.last().copied(),
    })
}

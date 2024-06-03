// Copyright 2024, The Horizen Foundation
// LICENSE TO BE ADDED [TODO]

use risc0_zkvm::*;
use snafu::*;

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

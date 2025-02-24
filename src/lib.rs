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

#[cfg(test)]
extern crate std;

extern crate alloc;
extern crate core;

pub use circuit::CircuitCoreDef;
pub use context::{Verifier, VerifierContext};
pub use key::Vk;
pub use receipt::{
    composite::CompositeReceipt, succinct::SuccinctReceipt, InnerReceipt, Journal, Proof,
};
pub use receipt_claim::{MaybePruned, ReceiptClaim};
pub use sha::{Digest, Digestible};

pub use risc0_zkp::verify::VerificationError;

mod circuit;
mod context;
mod key;
pub mod poseidon2_injection;
mod receipt;
mod receipt_claim;
mod segment;
pub mod sha;

/// Verifies the given `proof` and public inputs `pubs` using the verification key `vk` within the provided
/// `VerifierContext`. The context identifies the prover version used to generate the proof. Refer to [`VerifierContext`]
/// for more details on obtaining the version compatible with the prover used to generate the proof.
///
/// The verification key `vk` is used to validate the proof `proof` against the public inputs `pubs`.
/// Verification can fail if the proof is invalid or was generated with a different RISC Zero prover version.
pub fn verify<RC: CircuitCoreDef, SC: CircuitCoreDef>(
    ctx: &VerifierContext<RC, SC>,
    vk: Vk,
    proof: Proof,
    pubs: Journal,
) -> Result<(), VerificationError> {
    proof.verify(ctx, vk.0, pubs.digest())
}

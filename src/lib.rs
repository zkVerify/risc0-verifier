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
pub use context::VerifierContext;
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
mod receipt;
mod receipt_claim;
mod segment;
pub mod sha;

/// Verify the given proof `proof` and public inputs `pubs` using verification key `vk`.
/// Use this method to verify the proof generate withe the latest risc0 prover version (1.2.x).
/// Use the given verification key `vk` to verify the proof `proof` against the public inputs `pubs`.
/// Can fail if is the proof is not valid or generate with a different risc0 prover version.
pub fn verify(vk: Vk, proof: Proof, pubs: Journal) -> Result<(), VerificationError> {
    proof.verify(vk.0, pubs.digest()).map_err(Into::into)
}

/// Verify the given proof `proof` and public inputs `pubs` using verification key `vk` against the given
/// `VerifierContext`. The context identify the prover version used to generate the proof: see [`VerifierContext`]
/// to get more details about how to get the version compatible to the prover that you used to generate the proof.
/// Use the given verification key `vk` to verify the proof `proof` against the public inputs `pubs`.
/// Can fail if is the proof is not valid or generate with a different risc0 prover version.
pub fn verify_with_context<RC: CircuitCoreDef, SC: CircuitCoreDef>(
    ctx: &VerifierContext<RC, SC>,
    vk: Vk,
    proof: Proof,
    pubs: Journal,
) -> Result<(), VerificationError> {
    proof.verify_with_context(ctx, vk.0, pubs.digest())
}

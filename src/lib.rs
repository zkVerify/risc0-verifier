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

pub use context::SegmentInfo;
pub use key::Vk;
pub use receipt::{
    composite::CompositeReceipt, succinct::SuccinctReceipt, InnerReceipt, Journal, Proof,
};
pub use sha::{Digest, Digestible};

pub use risc0_zkp_v1::verify::VerificationError;
pub use verifier::Verifier;

pub mod poseidon2_injection;
pub mod sha;

mod circuit;
mod context;
mod key;
mod receipt;
pub mod receipt_claim;
mod segment;
mod translate;
mod verifier;

/// Verifies the given `proof` and public inputs `pubs` using the verification key `vk` within the provided
/// `VerifierContext`. The context identifies the prover version used to generate the proof. Refer to [`V1`]
/// for more details on obtaining the version compatible with the prover used to generate the proof.
///
/// The verification key `vk` is used to validate the proof `proof` against the public inputs `pubs`.
/// Verification can fail if the proof is invalid or was generated with a different RISC Zero prover version.
pub fn verify(
    verifier: &impl Verifier,
    vk: Vk,
    proof: Proof,
    pubs: Journal,
) -> Result<(), VerificationError> {
    verifier.verify(vk.0, proof, pubs)
}

/// Returns a `Verifier` for the specified RISC Zero prover 1.0 version.
pub fn v1_0() -> impl Verifier {
    context::v1::V1::v1_0()
}

/// Returns a `Verifier` for the specified RISC Zero prover 1.1 version.
pub fn v1_1() -> impl Verifier {
    context::v1::V1::v1_1()
}

/// Returns a `Verifier` for the specified RISC Zero prover 1.2 version.
pub fn v1_2() -> impl Verifier {
    context::v1::V1::v1_2()
}

/// Returns a `Verifier` for the specified RISC Zero prover 2.0 version.
pub fn v2_0() -> impl Verifier {
    context::v2::V2::v2_0()
}

// Copyright Copyright 2024, Horizen Labs, Inc.
// Copyright Copyright 2024 RISC Zero, Inc.
//
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
//

use alloc::{collections::BTreeSet, string::String, vec::Vec};
use risc0_binfmt::{tagged_iter, tagged_struct, Digestible, ExitCode, SystemState};
use risc0_circuit_rv32im::layout::{SystemStateLayout, OUT_LAYOUT};
use risc0_zkp::{
    adapter::{ProtocolInfo, PROOF_SYSTEM_INFO},
    core::{digest::Digest, hash::sha::Sha256},
    field::{baby_bear::BabyBearElem, Elem},
    layout::Tree,
    verify::VerificationError,
    MIN_CYCLES_PO2,
};

use serde::{Deserialize, Serialize};

use crate::{
    circuit::CircuitCoreDef,
    receipt::DEFAULT_MAX_PO2,
    receipt_claim::{MaybePruned, ReceiptClaim},
    sha, VerifierContext,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SegmentReceipt {
    pub seal: Vec<u32>,
    pub index: u32,
    pub hashfn: String,
    pub verifier_parameters: Digest,
    pub claim: ReceiptClaim,
}

impl SegmentReceipt {
    /// Verify the integrity of this receipt, ensuring the claim is attested
    /// to by the seal.
    pub fn verify_integrity_with_context<SC: CircuitCoreDef, RC: CircuitCoreDef>(
        &self,
        ctx: &VerifierContext<SC, RC>,
    ) -> Result<(), VerificationError> {
        let params = ctx
            .segment_verifier_parameters
            .as_ref()
            .ok_or(VerificationError::VerifierParametersMissing)?;

        // Check that the proof system and circuit info strings match what is implemented by this
        // function. Info strings are used a version identifiers, and this verify implementation
        // supports exactly one proof systema and circuit version at a time.
        if params.proof_system_info != PROOF_SYSTEM_INFO {
            return Err(VerificationError::ProofSystemInfoMismatch {
                expected: PROOF_SYSTEM_INFO,
                received: params.proof_system_info,
            });
        }
        if params.circuit_info != SC::CIRCUIT_INFO {
            return Err(VerificationError::CircuitInfoMismatch {
                expected: SC::CIRCUIT_INFO,
                received: params.circuit_info,
            });
        }

        log::debug!("SegmentReceipt::verify_integrity_with_context");
        let check_code = |_, control_id: &Digest| -> Result<(), VerificationError> {
            params.control_ids.contains(control_id).then_some(()).ok_or(
                VerificationError::ControlVerificationError {
                    control_id: *control_id,
                },
            )
        };
        let suite = ctx
            .suites
            .get(self.hashfn.as_str())
            .ok_or(VerificationError::InvalidHashSuite)?;
        risc0_zkp::verify::verify(ctx.circuit, suite, &self.seal, check_code)?;

        // Receipt is consistent with the claim encoded on the seal. Now check against the
        // claim on the struct.
        let decoded_claim = decode_receipt_claim_from_seal::<SC>(&self.seal)?;
        if decoded_claim.digest::<sha::Impl>() != self.claim.digest::<sha::Impl>() {
            log::debug!(
                "decoded segment receipt claim does not match claim field:\ndecoded: {:#?},\nexpected: {:#?}",
                decoded_claim,
                self.claim,
            );
            return Err(VerificationError::ClaimDigestMismatch {
                expected: self.claim.digest::<sha::Impl>(),
                received: decoded_claim.digest::<sha::Impl>(),
            });
        }

        Ok(())
    }

    /// Return the seal for this receipt, as a vector of bytes.
    pub fn get_seal_bytes(&self) -> Vec<u8> {
        self.seal.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    /// Number of bytes used by the seal for this receipt.
    pub fn seal_size(&self) -> usize {
        core::mem::size_of_val(self.seal.as_slice())
    }
}

fn decode_system_state_from_io<E: Elem + Into<u32>>(
    sys_state: Tree<E, SystemStateLayout>,
) -> Result<SystemState, VerificationError> {
    let bytes: Vec<u8> = sys_state
        .map(|c| c.image_id)
        .get_bytes()
        .or(Err(VerificationError::ReceiptFormatError))?;
    let pc = sys_state
        .map(|c| c.pc)
        .get_u32_from_bytes()
        .or(Err(VerificationError::ReceiptFormatError))?;
    let merkle_root = Digest::try_from(bytes).or(Err(VerificationError::ReceiptFormatError))?;
    Ok(SystemState { pc, merkle_root })
}

pub(crate) fn decode_receipt_claim_from_seal<SC: CircuitCoreDef>(
    seal: &[u32],
) -> Result<ReceiptClaim, VerificationError> {
    let io: &[BabyBearElem] = bytemuck::checked::cast_slice(&seal[..SC::OUTPUT_SIZE]);
    let global = Tree::new(io, OUT_LAYOUT);
    let pre = decode_system_state_from_io(global.map(|c| c.pre))?;
    let post = decode_system_state_from_io(global.map(|c| c.post))?;

    let input_bytes: Vec<u8> = global
        .map(|c| c.input)
        .get_bytes()
        .or(Err(VerificationError::ReceiptFormatError))?;
    let input = Digest::try_from(input_bytes).or(Err(VerificationError::ReceiptFormatError))?;

    let output_bytes: Vec<u8> = global
        .map(|c| c.output)
        .get_bytes()
        .or(Err(VerificationError::ReceiptFormatError))?;
    let output = Digest::try_from(output_bytes).or(Err(VerificationError::ReceiptFormatError))?;

    let sys_exit = global
        .map(|c| c.sys_exit_code)
        .get_u32_from_elem()
        .or(Err(VerificationError::ReceiptFormatError))?;
    let user_exit = global
        .map(|c| c.user_exit_code)
        .get_u32_from_elem()
        .or(Err(VerificationError::ReceiptFormatError))?;
    let exit_code =
        ExitCode::from_pair(sys_exit, user_exit).or(Err(VerificationError::ReceiptFormatError))?;

    Ok(ReceiptClaim {
        pre: pre.into(),
        post: post.into(),
        exit_code,
        input: MaybePruned::Pruned(input),
        output: MaybePruned::Pruned(output),
    })
}

/// Verifier parameters used to verify a [SegmentReceipt].
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SegmentReceiptVerifierParameters {
    /// Set of control ID with which the receipt is expected to verify.
    pub control_ids: BTreeSet<Digest>,
    /// Protocol info string distinguishing the proof system under which the receipt should verify.
    pub proof_system_info: ProtocolInfo,
    /// Protocol info string distinguishing circuit with which the receipt should verify.
    pub circuit_info: ProtocolInfo,
}

impl Digestible for SegmentReceiptVerifierParameters {
    /// Hash the [SegmentReceiptVerifierParameters] to get a digest of the struct.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>(
            "risc0.SegmentReceiptVerifierParameters",
            &[
                tagged_iter::<S>("risc0.ControlIdSet", self.control_ids.iter()),
                *S::hash_bytes(&self.proof_system_info.0),
                *S::hash_bytes(&self.circuit_info.0),
            ],
            &[],
        )
    }
}

impl SegmentReceiptVerifierParameters {
    /// Default set of parameters used to verify a [SegmentReceipt].
    pub fn v1_0() -> Self {
        use crate::circuit::v1_0::control_id::*;
        use risc0_zkp::adapter::{CircuitInfo, PROOF_SYSTEM_INFO};
        Self {
            control_ids: BTreeSet::from_iter(
                POSEIDON2_CONTROL_IDS
                    .into_iter()
                    .chain(SHA256_CONTROL_IDS)
                    .chain(BLAKE2B_CONTROL_IDS)
                    .map(Into::into),
            ),
            proof_system_info: PROOF_SYSTEM_INFO,
            circuit_info: crate::circuit::v1_0::CircuitImpl::CIRCUIT_INFO,
        }
    }
}

impl SegmentReceiptVerifierParameters {
    /// Default set of parameters used to verify a [SegmentReceipt].
    pub fn v1_1() -> Self {
        use risc0_zkp::adapter::{CircuitInfo, PROOF_SYSTEM_INFO};
        Self::from_max_po2(
            &crate::circuit::v1_1::control_id,
            DEFAULT_MAX_PO2,
            PROOF_SYSTEM_INFO,
            crate::circuit::v1_1::CircuitImpl::CIRCUIT_INFO,
        )
    }

    /// Default set of parameters used to verify a [SegmentReceipt].
    pub fn v1_2() -> Self {
        use risc0_zkp::adapter::{CircuitInfo, PROOF_SYSTEM_INFO};
        Self::from_max_po2(
            &crate::circuit::v1_2::control_id,
            DEFAULT_MAX_PO2,
            PROOF_SYSTEM_INFO,
            crate::circuit::v1_2::CircuitImpl::CIRCUIT_INFO,
        )
    }

    fn from_max_po2(
        resolver: &dyn Fn(&str, usize) -> Option<Digest>,
        max_po2: usize,
        proof_system_info: ProtocolInfo,
        circuit_info: ProtocolInfo,
    ) -> Self {
        Self {
            control_ids: BTreeSet::from_iter(
                ["poseidon2", "sha-256", "blake2b"]
                    .into_iter()
                    .flat_map(|hash_name| control_ids(resolver, hash_name, max_po2)),
            ),
            proof_system_info,
            circuit_info,
        }
    }
}

fn control_ids<'a, H: AsRef<str> + 'a>(
    resolver: &'a dyn Fn(&str, usize) -> Option<Digest>,
    hash_name: H,
    po2_max: usize,
) -> impl Iterator<Item = Digest> + 'a {
    // Using `take_while` here ensures termination when po2_max is much greater than the highest po2.
    (MIN_CYCLES_PO2..=po2_max)
        .map(move |po2| resolver(hash_name.as_ref(), po2))
        .take_while(Option::is_some)
        .map(Option::unwrap)
}

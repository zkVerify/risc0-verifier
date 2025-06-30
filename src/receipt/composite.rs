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

use alloc::{vec, vec::Vec};
use risc0_binfmt_v1::{Digestible, ExitCode};
use risc0_zkp_v1::{
    core::{digest::Digest, hash::sha},
    verify::VerificationError,
};

use serde::{Deserialize, Serialize};

use super::InnerAssumptionReceipt;
use crate::{
    context::VerifierContext,
    receipt_claim::{Assumption, Output, PrunedValueError, ReceiptClaim},
    segment::SegmentReceipt,
};

/// A receipt composed of one or more [SegmentReceipt] structs proving a single execution with
/// continuations, and zero or more [InnerAssumptionReceipt](crate::InnerAssumptionReceipt) structs
/// proving any assumptions.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompositeReceipt {
    /// Segment receipts forming the proof of an execution with continuations.
    pub segments: Vec<SegmentReceipt>,

    /// An ordered list of assumptions, either proven or unresolved, made within
    /// the continuation represented by the segment receipts. If any
    /// assumptions are unresolved, this receipt is only _conditionally_
    /// valid.
    // TODO(#982): Allow for unresolved assumptions in this list.
    pub assumption_receipts: Vec<InnerAssumptionReceipt>,

    /// A digest of the verifier parameters that can be used to verify this receipt.
    ///
    /// Acts as a fingerprint to identity differing proof system or circuit versions between a
    /// prover and a verifier. Is not intended to contain the full verifier parameters, which must
    /// be provided by a trusted source (e.g. packaged with the verifier code).
    pub verifier_parameters: Digest,
}

impl CompositeReceipt {
    /// Verify the integrity of this receipt, ensuring the claim is attested
    /// to by the seal.
    pub fn verify_integrity_with_context(
        &self,
        ctx: &impl VerifierContext,
    ) -> Result<(), VerificationError> {
        log::debug!("CompositeReceipt::verify_integrity_with_context");
        // Verify the continuation, by verifying every segment receipt in order.
        let (final_receipt, receipts) = self
            .segments
            .as_slice()
            .split_last()
            .ok_or(VerificationError::ReceiptFormatError)?;

        // Verify each segment and its chaining to the next.
        let mut expected_pre_state_digest = None;
        for receipt in receipts {
            receipt.verify_integrity_with_context(ctx)?;
            let claim = &receipt.claim;
            log::debug!("claim: {claim:#?}");
            if let Some(id) = expected_pre_state_digest {
                if id != claim.pre.digest::<sha::Impl>() {
                    return Err(VerificationError::ImageVerificationError);
                }
            }
            if claim.exit_code != ExitCode::SystemSplit {
                return Err(VerificationError::UnexpectedExitCode);
            }
            if !claim.output.is_none() {
                return Err(VerificationError::ReceiptFormatError);
            }
            expected_pre_state_digest = Some(
                claim
                    .post
                    .as_value()
                    .map_err(|_| VerificationError::ReceiptFormatError)?
                    .digest::<sha::Impl>(),
            );
        }

        // Verify the last receipt in the continuation.
        final_receipt.verify_integrity_with_context(ctx)?;
        log::debug!("final: {:#?}", final_receipt.claim);
        if let Some(id) = expected_pre_state_digest {
            if id != final_receipt.claim.pre.digest::<sha::Impl>() {
                return Err(VerificationError::ImageVerificationError);
            }
        }

        // Verify all assumptions on the receipt are resolved by attached receipts.
        // Ensure that there is one receipt for every assumption. An explicity check is required
        // because zip will terminate if either iterator terminates.
        let assumptions = self.assumptions()?;
        if assumptions.len() != self.assumption_receipts.len() {
            log::debug!(
                "only {} receipts provided for {} assumptions",
                assumptions.len(),
                self.assumption_receipts.len()
            );
            return Err(VerificationError::ReceiptFormatError);
        }
        for (assumption, receipt) in assumptions.into_iter().zip(self.assumption_receipts.iter()) {
            let assumption_ctx = ctx.assumption_context(&assumption);
            log::debug!("verifying assumption: {assumption:?}");
            receipt.verify_integrity_with_context(
                &assumption_ctx
                    .map(|c| c.boxed_clone())
                    .unwrap_or(ctx.boxed_clone()),
            )?;
            if receipt.claim_digest()? != assumption.claim {
                log::debug!(
                    "verifying assumption failed due to claim mismatch: assumption: {assumption:?}, receipt claim digest: {}",
                    receipt.claim_digest()?
                );
                return Err(VerificationError::ClaimDigestMismatch {
                    expected: assumption.claim,
                    received: receipt.claim_digest()?,
                });
            }
        }

        Ok(())
    }

    /// Returns the [ReceiptClaim] for this [CompositeReceipt].
    pub fn claim(&self) -> Result<ReceiptClaim, VerificationError> {
        let first_claim = &self
            .segments
            .first()
            .ok_or(VerificationError::ReceiptFormatError)?
            .claim;
        let last_claim = &self
            .segments
            .last()
            .ok_or(VerificationError::ReceiptFormatError)?
            .claim;

        // Remove the assumptions from the last receipt claim, as the verify routine requires every
        // assumption to have an associated verifiable receipt.
        // TODO(#982) Support unresolved assumptions here by only removing the proven assumptions.
        let output = last_claim
            .output
            .as_value()
            .map_err(|_| VerificationError::ReceiptFormatError)?
            .as_ref()
            .map(|output| Output {
                journal: output.journal.clone(),
                assumptions: vec![].into(),
            })
            .into();

        Ok(ReceiptClaim {
            pre: first_claim.pre.clone(),
            post: last_claim.post.clone(),
            exit_code: last_claim.exit_code,
            input: first_claim.input.clone(),
            output,
        })
    }

    fn assumptions(&self) -> Result<Vec<Assumption>, VerificationError> {
        // Collect the assumptions from the output of the last segment, handling any pruned values
        // encountered and returning and empty list if the output is None.
        Ok(self
            .segments
            .last()
            .ok_or(VerificationError::ReceiptFormatError)?
            .claim
            .output
            .as_value()
            .map_err(|_| VerificationError::ReceiptFormatError)?
            .as_ref()
            .map(|output| match output.assumptions.is_empty() {
                true => Ok(Default::default()),
                false => Ok(output
                    .assumptions
                    .as_value()?
                    .iter()
                    .map(|a| a.as_value().cloned())
                    .collect::<Result<_, _>>()?),
            })
            .transpose()
            .map_err(|_: PrunedValueError| VerificationError::ReceiptFormatError)?
            .unwrap_or_default())
    }

    /// Total number of bytes used by the seals of this receipt.
    pub fn seal_size(&self) -> usize {
        // NOTE: This sum cannot overflow because all seals are in memory.
        self.segments.iter().map(|s| s.seal_size()).sum()
    }
}

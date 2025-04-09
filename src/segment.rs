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

use crate::{context::VerifierContext, receipt::DEFAULT_MAX_PO2, receipt_claim::ReceiptClaim, sha};
use alloc::{collections::BTreeSet, string::String, vec::Vec};
use risc0_binfmt_v1::{tagged_iter, tagged_struct, Digestible};
use risc0_zkp_v1::{
    adapter::{ProtocolInfo, PROOF_SYSTEM_INFO},
    core::{digest::Digest, hash::sha::Sha256},
    verify::VerificationError,
    MIN_CYCLES_PO2,
};

use serde::{Deserialize, Serialize};

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
    pub fn verify_integrity_with_context(
        &self,
        ctx: &impl VerifierContext,
    ) -> Result<(), VerificationError> {
        let params = ctx
            .verifier_parameters()
            .segment_verifier_parameters()
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
        if params.circuit_info != ctx.segment_circuit_info() {
            return Err(VerificationError::CircuitInfoMismatch {
                expected: ctx.segment_circuit_info(),
                received: params.circuit_info,
            });
        }

        ctx.verify_segment(self.hashfn.as_str(), &self.seal, params)?;

        // Receipt is consistent with the claim encoded on the seal. Now check against the
        // claim on the struct.
        // let decoded_claim = decode_from_seal_v2(&self.seal, None)?;
        let decoded_claim = ctx.decode_from_seal(&self.seal)?;
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
        size_of_val(self.seal.as_slice())
    }
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
    /// v1.0 set of parameters used to verify a [SegmentReceipt].
    pub fn v1_0() -> Self {
        use crate::circuit::v1_0::control_id::*;
        use risc0_zkp_v1::adapter::{CircuitInfo, PROOF_SYSTEM_INFO};
        Self {
            control_ids: BTreeSet::from_iter(
                POSEIDON2_CONTROL_IDS
                    .into_iter()
                    .chain(SHA256_CONTROL_IDS)
                    .chain(BLAKE2B_CONTROL_IDS),
            ),
            proof_system_info: PROOF_SYSTEM_INFO,
            circuit_info: crate::circuit::v1_0::CircuitImpl::CIRCUIT_INFO,
        }
    }

    /// v1.1 set of parameters used to verify a [SegmentReceipt].
    pub fn v1_1() -> Self {
        use risc0_zkp_v1::adapter::{CircuitInfo, PROOF_SYSTEM_INFO};
        Self::from_max_po2(
            &crate::circuit::v1_1::control_id,
            DEFAULT_MAX_PO2,
            PROOF_SYSTEM_INFO,
            crate::circuit::v1_1::CircuitImpl::CIRCUIT_INFO,
        )
    }

    /// v1.2 set of parameters used to verify a [SegmentReceipt].
    pub fn v1_2() -> Self {
        use risc0_zkp_v1::adapter::{CircuitInfo, PROOF_SYSTEM_INFO};
        Self::from_max_po2(
            &crate::circuit::v1_2::control_id,
            DEFAULT_MAX_PO2,
            PROOF_SYSTEM_INFO,
            crate::circuit::v1_2::CircuitImpl::CIRCUIT_INFO,
        )
    }

    /// v2.0 set of parameters used to verify a [SegmentReceipt].
    pub fn v2_0() -> Self {
        use risc0_zkp_v2::adapter::{CircuitInfo, PROOF_SYSTEM_INFO};
        let p_info = ProtocolInfo(PROOF_SYSTEM_INFO.0);
        let circuit = ProtocolInfo(crate::circuit::v2_0::CircuitImpl::CIRCUIT_INFO.0);
        fn fake_control_id(_hash_name: &str, _po2: usize) -> Option<Digest> {
            None
        }
        Self::from_max_po2(&fake_control_id, DEFAULT_MAX_PO2, p_info, circuit)
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

#[cfg(test)]
mod tests {

    use super::SegmentReceiptVerifierParameters;
    use crate::sha::Digestible;
    use risc0_zkp_v1::core::digest::{digest, Digest};
    use rstest::rstest;

    // Check that the verifier parameters has a stable digest (and therefore a stable value). This
    // struct encodes parameters used in verification, and so this value should be updated if and
    // only if a change to the verifier parameters is expected. Updating the verifier parameters
    // will result in incompatibility with previous versions.
    #[rstest]
    #[case::v1_0(SegmentReceiptVerifierParameters::v1_0().digest(), digest!("62d97bc46d0a877acb857043cbb90a6beafa21c97f01472952fd28be15b47508"))]
    #[case::v1_1(SegmentReceiptVerifierParameters::v1_1().digest(), digest!("52a27aff2de5a8206e3e88cb8dcb087c1193ede8efaf4889117bc68e704cf29a"))]
    #[case::v1_2(SegmentReceiptVerifierParameters::v1_2().digest(), digest!("52a27aff2de5a8206e3e88cb8dcb087c1193ede8efaf4889117bc68e704cf29a"))]
    fn succinct_receipt_verifier_parameters_is_stable(
        #[case] computed: Digest,
        #[case] hardcoded: Digest,
    ) {
        assert_eq!(computed, hardcoded);
    }
}

// Copyright Copyright 2024, Horizen Labs, Inc.
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

use crate::receipt_claim::ReceiptClaim;
use crate::{
    poseidon2_injection::Poseidon2Mix, receipt::merkle::MerkleProof,
    receipt::succinct::SuccinctReceiptVerifierParameters, receipt_claim::Assumption,
    segment::SegmentReceiptVerifierParameters, Proof,
};
use alloc::{boxed::Box, collections::BTreeMap, string::String};
use risc0_zkp_v1::{adapter::ProtocolInfo, core::digest::Digest, verify::VerificationError};

pub mod v1;
pub mod v2;

pub struct VerifierParameters<Segment, Succinct, HashSuite> {
    /// Parameters for verification of [SuccinctReceipt].
    pub succinct_verifier_parameters: Option<SuccinctReceiptVerifierParameters>,
    /// A registry of hash functions to be used by the verification process.
    pub suites: BTreeMap<String, HashSuite>,
    /// Parameters for verification of [SegmentReceipt].
    pub segment_verifier_parameters: Option<SegmentReceiptVerifierParameters>,

    pub segment: Segment,

    pub succinct: Succinct,
}

impl<Segment: CircuitInfo, Succinct: CircuitInfo, HashSuite>
    VerifierParameters<Segment, Succinct, HashSuite>
{
    pub fn segment_verifier_parameters(&self) -> Option<&SegmentReceiptVerifierParameters> {
        self.segment_verifier_parameters.as_ref()
    }

    pub fn succinct_verifier_parameters(&self) -> Option<&SuccinctReceiptVerifierParameters> {
        self.succinct_verifier_parameters.as_ref()
    }

    pub fn suite(&self, hashfn: &str) -> Option<&HashSuite> {
        self.suites.get(hashfn)
    }
}

pub trait CircuitInfo {
    fn protocol(&self) -> ProtocolInfo;
    fn size(&self) -> usize;
}

pub type BoxedVC<S> = Box<
    dyn VerifierContext<
        Segment = <S as VerifierContext>::Segment,
        Succinct = <S as VerifierContext>::Succinct,
        HashSuite = <S as VerifierContext>::HashSuite,
    >,
>;

pub trait VerifierContext {
    type HashSuite;
    type Segment: CircuitInfo;
    type Succinct: CircuitInfo;

    fn verifier_parameters(
        &self,
    ) -> &VerifierParameters<Self::Segment, Self::Succinct, Self::HashSuite>;

    fn mut_verifier_parameters(
        &mut self,
    ) -> &mut VerifierParameters<Self::Segment, Self::Succinct, Self::HashSuite>;
    fn boxed_clone(&self) -> BoxedVC<Self>;

    fn boxed_succinct_verifier_with_control_root(&self, control_root: Digest) -> BoxedVC<Self>;

    fn assumption_context(&self, assumption: &Assumption) -> Option<BoxedVC<Self>> {
        match assumption.control_root {
            // If the control root is all zeroes, we should use the same verifier parameters.
            Digest::ZERO => None,
            // Otherwise, we should verify the assumption receipt using the guest-provided root.
            control_root => Some(self.boxed_succinct_verifier_with_control_root(control_root)),
        }
    }

    fn segment_circuit_info(&self) -> ProtocolInfo {
        self.verifier_parameters().segment.protocol()
    }
    fn succinct_circuit_info(&self) -> ProtocolInfo {
        self.verifier_parameters().succinct.protocol()
    }
    fn succinct_output_size(&self) -> usize {
        self.verifier_parameters().succinct.size()
    }

    fn decode_from_seal(&self, seal: &[u32]) -> Result<ReceiptClaim, VerificationError>;

    fn verify_segment(
        &self,
        hashfn: &str,
        seal: &[u32],
        params: &SegmentReceiptVerifierParameters,
    ) -> Result<(), VerificationError>;
    fn verify_succinct(
        &self,
        hashfn: &str,
        seal: &[u32],
        control_inclusion_proof: &MerkleProof,
        params: &SuccinctReceiptVerifierParameters,
    ) -> Result<(), VerificationError>;

    fn is_valid_receipt(&self, _proof: &Proof) -> bool {
        true
    }

    fn segment_seal_offset(&self) -> usize;

    fn set_poseidon2_mix_impl(&mut self, poseidon2: Box<dyn Poseidon2Mix + Send + Sync + 'static>);
}

impl<Seg: CircuitInfo, Suc: CircuitInfo, T> VerifierContext
    for Box<dyn VerifierContext<Segment = Seg, Succinct = Suc, HashSuite = T> + 'static>
{
    type HashSuite = T;
    type Segment = Seg;
    type Succinct = Suc;

    fn verifier_parameters(&self) -> &VerifierParameters<Seg, Suc, T> {
        self.as_ref().verifier_parameters()
    }

    fn mut_verifier_parameters(
        &mut self,
    ) -> &mut VerifierParameters<Self::Segment, Self::Succinct, Self::HashSuite> {
        self.as_mut().mut_verifier_parameters()
    }

    fn boxed_clone(&self) -> BoxedVC<Self> {
        self.as_ref().boxed_clone()
    }
    fn boxed_succinct_verifier_with_control_root(&self, control_root: Digest) -> BoxedVC<Self> {
        self.as_ref()
            .boxed_succinct_verifier_with_control_root(control_root)
    }

    fn assumption_context(&self, assumption: &Assumption) -> Option<BoxedVC<Self>> {
        self.as_ref().assumption_context(assumption)
    }

    fn segment_circuit_info(&self) -> ProtocolInfo {
        self.as_ref().segment_circuit_info()
    }

    fn succinct_circuit_info(&self) -> ProtocolInfo {
        self.as_ref().succinct_circuit_info()
    }

    fn succinct_output_size(&self) -> usize {
        self.as_ref().succinct_output_size()
    }

    fn decode_from_seal(&self, seal: &[u32]) -> Result<ReceiptClaim, VerificationError> {
        self.as_ref().decode_from_seal(seal)
    }

    fn verify_segment(
        &self,
        hashfn: &str,
        seal: &[u32],
        params: &SegmentReceiptVerifierParameters,
    ) -> Result<(), VerificationError> {
        self.as_ref().verify_segment(hashfn, seal, params)
    }

    fn verify_succinct(
        &self,
        hashfn: &str,
        seal: &[u32],
        control_inclusion_proof: &MerkleProof,
        params: &SuccinctReceiptVerifierParameters,
    ) -> Result<(), VerificationError> {
        self.as_ref()
            .verify_succinct(hashfn, seal, control_inclusion_proof, params)
    }

    fn segment_seal_offset(&self) -> usize {
        self.as_ref().segment_seal_offset()
    }

    fn set_poseidon2_mix_impl(&mut self, poseidon2: Box<dyn Poseidon2Mix + Send + Sync + 'static>) {
        self.as_mut().set_poseidon2_mix_impl(poseidon2)
    }
}

#[derive(Clone, PartialEq, Debug)]
/// The segment info.
pub struct SegmentInfo {
    /// Hash function name
    pub hash: String,
    /// The power-of-2 proof size
    pub po2: u32,
}

impl SegmentInfo {
    /// Create a new segment-info
    pub fn new(hash: String, po2: u32) -> Self {
        Self { hash, po2 }
    }
}

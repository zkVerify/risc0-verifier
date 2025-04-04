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

use crate::{
    context::{CircuitInfo, VerifierContext},
    poseidon2_injection::Poseidon2Mix,
    receipt::succinct::SuccinctReceiptVerifierParameters,
    CompositeReceipt, Digestible, Journal, Proof, SegmentInfo,
};
use alloc::boxed::Box;
use risc0_zkp_v1::{core::digest::Digest, verify::VerificationError};

mod extract_po2;

impl<Seg: 'static, Suc: 'static, HashSuite: 'static, T> Verifier for T
where
    Seg: CircuitInfo,
    Suc: CircuitInfo,
    T: VerifierContext<Segment = Seg, Succinct = Suc, HashSuite = HashSuite>,
{
    fn verify(
        &self,
        image_id: Digest,
        proof: Proof,
        pubs: Journal,
    ) -> Result<(), VerificationError> {
        proof.verify(self, image_id, pubs.digest())
    }

    fn seal_offset(&self) -> usize {
        self.segment_seal_offset()
    }
    fn segment_circuit_output_size(&self) -> usize {
        self.verifier_parameters().segment.size()
    }

    fn set_poseidon2_mix_impl(&mut self, poseidon2: Box<dyn Poseidon2Mix + Send + Sync + 'static>) {
        <Self as VerifierContext>::set_poseidon2_mix_impl(self, poseidon2)
    }

    fn mut_succinct_verifier_parameters(
        &mut self,
    ) -> Option<&mut SuccinctReceiptVerifierParameters> {
        self.mut_verifier_parameters()
            .succinct_verifier_parameters
            .as_mut()
    }
}

/// Dynamic verifier trait. It's implemented by all verifier context and can be
/// used with dynamic dispatching. Expose just the functionalities that can be
/// dispatched dynamically.
///
pub trait Verifier {
    /// Verify the proof against this verifier context, the given `image_id` and journal.
    fn verify(
        &self,
        image_id: Digest,
        proof: Proof,
        pubs: Journal,
    ) -> Result<(), VerificationError>;

    fn seal_offset(&self) -> usize;

    fn segment_circuit_output_size(&self) -> usize;

    fn set_poseidon2_mix_impl(&mut self, poseidon2: Box<dyn Poseidon2Mix + Send + Sync + 'static>);

    fn mut_succinct_verifier_parameters(
        &mut self,
    ) -> Option<&mut SuccinctReceiptVerifierParameters>;

    fn extract_composite_segments_info(
        &self,
        composite: &CompositeReceipt,
    ) -> Result<alloc::vec::Vec<SegmentInfo>, VerificationError> {
        composite
            .segments
            .iter()
            .map(|s| {
                let (_, seal) = s.seal.split_at(self.seal_offset());
                extract_po2::extract_segment_po2(seal, self.segment_circuit_output_size()).map(
                    |po2| SegmentInfo {
                        hash: s.hashfn.clone(),
                        po2,
                    },
                )
            })
            .collect()
    }
}

impl Verifier for Box<dyn Verifier> {
    fn verify(
        &self,
        image_id: Digest,
        proof: Proof,
        journal: Journal,
    ) -> Result<(), VerificationError> {
        self.as_ref().verify(image_id, proof, journal)
    }

    fn seal_offset(&self) -> usize {
        self.as_ref().seal_offset()
    }

    fn segment_circuit_output_size(&self) -> usize {
        self.as_ref().segment_circuit_output_size()
    }

    fn set_poseidon2_mix_impl(&mut self, poseidon2: Box<dyn Poseidon2Mix + Send + Sync + 'static>) {
        self.as_mut().set_poseidon2_mix_impl(poseidon2)
    }

    fn mut_succinct_verifier_parameters(
        &mut self,
    ) -> Option<&mut SuccinctReceiptVerifierParameters> {
        self.as_mut().mut_succinct_verifier_parameters()
    }
}

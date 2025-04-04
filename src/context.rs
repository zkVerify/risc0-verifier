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

use crate::poseidon2_injection::Poseidon2Mix;
use crate::{circuit::self, receipt::succinct::SuccinctReceiptVerifierParameters, segment::SegmentReceiptVerifierParameters, CompositeReceipt, Digestible, FakeRngFactory, Journal, Proof, ReceiptClaim};
use alloc::{boxed::Box, collections::BTreeMap, string::String};
use risc0_core_v1::field::baby_bear::BabyBearElem;
use risc0_zkp_v1::core::digest::Digest;
use risc0_zkp_v1::verify::VerificationError;
use risc0_zkp_v1::{
    core::hash::HashSuite,
    field::baby_bear::BabyBear,
};
use risc0_zkp_v1::adapter::ProtocolInfo;
use crate::receipt::merkle::MerkleProof;
use crate::receipt_claim::Assumption;

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

impl<Segment: CircuitInfo, Succinct: CircuitInfo, HashSuite> VerifierParameters<Segment, Succinct, HashSuite> {
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

pub type HashSuiteV1 = HashSuite<BabyBear>;

impl<Seg: Default, Suc: Default> Default for VerifierParameters<Seg, Suc, HashSuiteV1> {
    fn default() -> Self {
        Self {
            succinct_verifier_parameters: None,
            suites: BTreeMap::new(),
            segment_verifier_parameters: None,
            segment: Seg::default(),
            succinct: Suc::default(),
        }
    }
}

impl<Seg: Clone, Suc: Clone> Clone for VerifierParameters<Seg, Suc, HashSuiteV1> {
    fn clone(&self) -> Self {
        Self {
            suites: self.suites.iter().map(|(k, v)|
                (k.clone(), HashSuiteV1 {
                    name: v.name.clone(),
                    hashfn: v.hashfn.clone(),
                    rng: v.rng.clone(),
                })
            ).collect(),
            segment_verifier_parameters: self.segment_verifier_parameters.clone(),
            succinct_verifier_parameters: self.succinct_verifier_parameters.clone(),
            segment: self.segment.clone(),
            succinct: self.succinct.clone(),
        }
    }
}

pub(crate) type VerifierParametersV1 = VerifierParameters<SegmentV1, SuccinctV1, HashSuiteV1>;

pub trait CircuitInfo {
    fn protocol(&self) -> ProtocolInfo;
    fn size(&self) -> usize;
}

#[derive(Default, Clone, Copy)]
pub struct SegmentV1;

impl CircuitInfo for SegmentV1 {
    fn protocol(&self) -> ProtocolInfo {
        <circuit::v1_2::CircuitImpl as risc0_zkp_v1::adapter::CircuitInfo>::CIRCUIT_INFO
    }
    fn size(&self) -> usize {
        <circuit::v1_2::CircuitImpl as risc0_zkp_v1::adapter::CircuitInfo>::OUTPUT_SIZE
    }
}

#[derive(Default, Clone, Copy)]
pub struct SuccinctV1;

impl CircuitInfo for SuccinctV1 {
    fn protocol(&self) -> ProtocolInfo {
        <circuit::v1_2::recursive::CircuitImpl as risc0_zkp_v1::adapter::CircuitInfo>::CIRCUIT_INFO
    }
    fn size(&self) -> usize {
        <circuit::v1_2::recursive::CircuitImpl as risc0_zkp_v1::adapter::CircuitInfo>::OUTPUT_SIZE
    }
}

impl <Seg: 'static, Suc: 'static, HashSuite: 'static, T> Verifier for T
    where
        Seg: CircuitInfo,
        Suc: CircuitInfo,
        T: VC<Segment=Seg, Succinct=Suc, HashSuite=HashSuite>,
{
    type HashSuite = HashSuite;

        fn verify(&self, image_id: Digest, proof: Proof, pubs: Journal) -> Result<(), VerificationError> {
            proof.verify(self, image_id, pubs.digest())
        }

        fn seal_offset(&self) -> usize {
            self.segment_seal_offset()
        }
        fn segment_circuit_output_size(&self) -> usize {
            self.verifier_parameters().segment.size()
        }

        fn set_poseidon2_mix_impl(&mut self, poseidon2: Box<dyn Poseidon2Mix + Send + Sync + 'static>) {
            <Self as VC>::set_poseidon2_mix_impl(self, poseidon2)
        }

        fn mut_succinct_verifier_parameters(&mut self) -> Option<&mut SuccinctReceiptVerifierParameters>
        {
            self.mut_verifier_parameters().succinct_verifier_parameters.as_mut()
        }
}

pub trait VC {
    type HashSuite;
    type Segment: CircuitInfo;
    type Succinct: CircuitInfo;

    fn verifier_parameters(&self) -> &VerifierParameters<Self::Segment, Self::Succinct, Self::HashSuite>;

    fn mut_verifier_parameters(&mut self) -> &mut VerifierParameters<Self::Segment, Self::Succinct, Self::HashSuite>;
    fn boxed_clone(&self) -> alloc::boxed::Box<dyn VC<Segment=Self::Segment, Succinct=Self::Succinct, HashSuite=Self::HashSuite>>;

    fn boxed_succinct_verifier_with_control_root(&self, control_root: Digest) -> alloc::boxed::Box<dyn VC<Segment=Self::Segment, Succinct=Self::Succinct, HashSuite=Self::HashSuite>>;

    fn assumption_context(&self, assumption: &Assumption) -> Option<alloc::boxed::Box<dyn VC<Segment=Self::Segment, Succinct=Self::Succinct, HashSuite=Self::HashSuite>>> {
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

    fn decode_from_seal(&self, seal: &[u32]) -> Result<crate::ReceiptClaim, VerificationError>;

    fn verify_segment(&self, hashfn: &str, seal: &[u32], params: &SegmentReceiptVerifierParameters) -> Result<(), VerificationError>;
    fn verify_succinct(&self, hashfn: &str, seal: &[u32], control_inclusion_proof: &MerkleProof, params: &SuccinctReceiptVerifierParameters) -> Result<(), VerificationError>;

    fn is_valid_receipt(&self, _proof: &Proof) -> bool {
        true
    }

    fn segment_seal_offset(&self) -> usize;

    fn set_poseidon2_mix_impl(&mut self, poseidon2: Box<dyn Poseidon2Mix + Send + Sync + 'static>);

}

impl<Seg: CircuitInfo, Suc: CircuitInfo, T> VC for alloc::boxed::Box<dyn VC<Segment=Seg, Succinct=Suc, HashSuite=T> + 'static> {
    type HashSuite = T;
    type Segment = Seg;
    type Succinct = Suc;

    fn verifier_parameters(&self) -> &VerifierParameters<Seg, Suc, T> {
        self.as_ref().verifier_parameters()
    }

    fn assumption_context(&self, assumption: &Assumption) -> Option<alloc::boxed::Box<dyn VC<Segment=Self::Segment, Succinct=Self::Succinct, HashSuite=Self::HashSuite>>> {
        self.as_ref().assumption_context(assumption)
    }

    fn boxed_clone(&self) -> alloc::boxed::Box<dyn VC<Segment=Self::Segment, Succinct=Self::Succinct, HashSuite=Self::HashSuite>> {
        self.as_ref().boxed_clone()
    }
    fn boxed_succinct_verifier_with_control_root(&self, control_root: Digest) -> alloc::boxed::Box<dyn VC<Segment=Self::Segment, Succinct=Self::Succinct, HashSuite=Self::HashSuite>> {
        self.as_ref().boxed_succinct_verifier_with_control_root(control_root)
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

    fn verify_segment(&self, hashfn: &str, seal: &[u32], params: &SegmentReceiptVerifierParameters) -> Result<(), VerificationError> {
        self.as_ref().verify_segment(hashfn, seal, params)
    }

    fn verify_succinct(&self, hashfn: &str, seal: &[u32], control_inclusion_proof: &MerkleProof, params: &SuccinctReceiptVerifierParameters) -> Result<(), VerificationError> {
        self.as_ref().verify_succinct(hashfn, seal, control_inclusion_proof, params)
    }

    fn mut_verifier_parameters(&mut self) -> &mut VerifierParameters<Self::Segment, Self::Succinct, Self::HashSuite> {
        self.as_mut().mut_verifier_parameters()
    }

    fn segment_seal_offset(&self) -> usize {
        self.as_ref().segment_seal_offset()
    }

    fn set_poseidon2_mix_impl(&mut self, poseidon2: Box<dyn Poseidon2Mix + Send + Sync + 'static>) {
        self.as_mut().set_poseidon2_mix_impl(poseidon2)
    }
}

pub mod v1;
pub mod v2;


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

/// Dynamic verifier trait. It's implemented by all verifier context and can be
/// used with dynamic dispatching. Expose just the functionalities that can be
/// dispatched dynamically.
///
pub trait Verifier {
    type HashSuite;

    /// Verify the proof against this verifier context, the given `image_id` and journal.
    fn verify(
        &self,
        image_id: Digest,
        proof: Proof,
        pubs: Journal,
    ) -> Result<(), VerificationError>;

    fn seal_offset(&self) -> usize;

    fn segment_circuit_output_size(&self) -> usize;

    fn set_poseidon2_mix_impl(
        &mut self,
        poseidon2: alloc::boxed::Box<dyn Poseidon2Mix + Send + Sync + 'static>,
    );

    fn mut_succinct_verifier_parameters(&mut self) -> Option<&mut SuccinctReceiptVerifierParameters>;

    fn extract_composite_segments_info(
        &self,
        composite: &CompositeReceipt,
    ) -> Result<alloc::vec::Vec<SegmentInfo>, VerificationError> {
        composite
            .segments
            .iter()
            .map(|s| {
                self.extract_segment_po2(s.seal.as_slice(), s.hashfn.as_str())
                    .map(|po2| SegmentInfo {
                        hash: s.hashfn.clone(),
                        po2,
                    })
            })
            .collect()
    }

    fn extract_segment_po2(&self, seal: &[u32], _hash: &str) -> Result<u32, VerificationError> {
        let (_, seal) = seal.split_at(self.seal_offset());
        let mut iop = risc0_zkp_v1::verify::ReadIOP::<risc0_zkp_v1::field::baby_bear::BabyBear>::new(
            seal,
            &FakeRngFactory,
        );
        let output_size = self.segment_circuit_output_size();
        let slice: &[BabyBearElem] = iop.read_field_elem_slice(output_size + 1);
        let (_, &[po2_elem]) = slice.split_at(output_size) else {
            unreachable!()
        };
        use risc0_zkp_v1::field::Elem;
        let (&[po2], &[]) = po2_elem.to_u32_words().split_at(1) else {
            // That means BabyBear field is more than one u32
            core::panic!("po2 elem is larger than u32");
        };
        Ok(po2)

    }
}

impl<T> Verifier for alloc::boxed::Box<dyn Verifier<HashSuite=T>> {
    type HashSuite = T;

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

    fn set_poseidon2_mix_impl(
        &mut self,
        poseidon2: alloc::boxed::Box<dyn Poseidon2Mix + Send + Sync + 'static>,
    ) {
        self.as_mut().set_poseidon2_mix_impl(poseidon2)
    }

    fn extract_segment_po2(&self, seal: &[u32], hash: &str) -> Result<u32, VerificationError> {
        self.as_ref().extract_segment_po2(seal, hash)
    }

    fn mut_succinct_verifier_parameters(&mut self) -> Option<&mut SuccinctReceiptVerifierParameters> {
        self.as_mut().mut_succinct_verifier_parameters()
    }
}

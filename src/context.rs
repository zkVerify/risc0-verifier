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
use crate::{
    circuit::{self, CircuitCoreDef},
    receipt::succinct::SuccinctReceiptVerifierParameters,
    segment::SegmentReceiptVerifierParameters,
    CompositeReceipt, Digestible, Journal, Proof,
};
use alloc::{collections::BTreeMap, string::String};
use risc0_core::field::baby_bear::BabyBearElem;
use risc0_zkp::core::digest::Digest;
use risc0_zkp::verify::{ReadIOP, VerificationError};
use risc0_zkp::{
    core::hash::{
        blake2b::Blake2bCpuHashSuite, poseidon2::Poseidon2HashSuite, sha::Sha256HashSuite,
        HashSuite,
    },
    field::baby_bear::BabyBear,
};

/// Context available to the verification process. The context contains
/// all the info necessary to verify the proofs there are some
/// preconfigured context configurations to fit the risc0 vm versions.
///
/// The risc0 vm version `1.x` are not interchangeable that means if had
/// generated a proof with the `1.1.x` risc0 version you can verify it only
/// with the `1.1.y` circuit version and so you should use [`VerifierContext::v1_1()`],
/// any other context, even if has a greater version, will fail to verify the proof.
///
/// So, `VerifierContext` define a new constructor for each risc0 minor version
/// in order to have the right context for any risc0 incompatible vm version.
///
#[non_exhaustive]
pub struct VerifierContext<SC: CircuitCoreDef, RC: CircuitCoreDef> {
    /// A registry of hash functions to be used by the verification process.
    pub suites: BTreeMap<String, HashSuite<BabyBear>>,

    /// Parameters for verification of [SegmentReceipt].
    pub segment_verifier_parameters: Option<SegmentReceiptVerifierParameters>,

    /// Parameters for verification of [SuccinctReceipt].
    pub succinct_verifier_parameters: Option<SuccinctReceiptVerifierParameters>,

    pub circuit: &'static SC,

    pub recursive_circuit: &'static RC,
}

impl VerifierContext<circuit::v1_0::CircuitImpl, circuit::v1_0::recursive::CircuitImpl> {
    /// Create an empty [VerifierContext] for any risc0 proof generate for any `1.0.x` vm version.
    pub fn v1_0() -> Self {
        Self::empty(&circuit::v1_0::CIRCUIT, &circuit::v1_0::recursive::CIRCUIT)
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v1_0())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v1_0())
    }
}

impl VerifierContext<circuit::v1_1::CircuitImpl, circuit::v1_1::recursive::CircuitImpl> {
    /// Create an empty [VerifierContext] for any risc0 proof generate for any `1.1.x` vm version.
    pub fn v1_1() -> Self {
        Self::empty(&circuit::v1_1::CIRCUIT, &circuit::v1_1::recursive::CIRCUIT)
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v1_1())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v1_1())
    }
}

impl VerifierContext<circuit::v1_2::CircuitImpl, circuit::v1_2::recursive::CircuitImpl> {
    /// Create an empty [VerifierContext] for any risc0 proof generate for any `1.2.x` vm version.
    pub fn v1_2() -> Self {
        Self::empty(&circuit::v1_2::CIRCUIT, &circuit::v1_2::recursive::CIRCUIT)
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v1_2())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v1_2())
    }
}

impl VerifierContext<circuit::v1_3::CircuitImpl, circuit::v1_3::recursive::CircuitImpl> {
    /// Create an empty [VerifierContext] for any risc0 proof generate for any `1.3.x` vm version.
    pub fn v1_3() -> Self {
        Self::empty(&circuit::v1_3::CIRCUIT, &circuit::v1_3::recursive::CIRCUIT)
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v1_3())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v1_3())
    }
}

#[derive(Clone, PartialEq, Debug)]
/// The segment info.
pub struct SegmentInfo {
    /// Hash function name
    pub hashfn: String,
    /// The power of 2 proof size
    pub po2: u32,
}

impl SegmentInfo {
    /// Create a new segment info
    pub fn new(hashfn: String, po2: u32) -> Self {
        Self { hashfn, po2 }
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
    fn extract_composite_segments_info(
        &self,
        composite: &CompositeReceipt,
    ) -> Result<alloc::vec::Vec<SegmentInfo>, VerificationError> {
        composite
            .segments
            .iter()
            .map(|s| {
                self.extract_segment_info(s.seal.as_slice(), s.hashfn.as_str())
                    .map(|po2| SegmentInfo {
                        hashfn: s.hashfn.clone(),
                        po2,
                    })
            })
            .collect()
    }

    fn suites(&self) -> &BTreeMap<String, HashSuite<BabyBear>>;

    fn set_suites(&mut self, suites: BTreeMap<String, HashSuite<BabyBear>>);

    fn set_poseidon2_mix_impl(
        &mut self,
        poseidon2: alloc::boxed::Box<dyn Poseidon2Mix + Send + Sync + 'static>,
    );

    fn extract_segment_info(&self, seal: &[u32], hashfn: &str) -> Result<u32, VerificationError>;
}

impl<SC: CircuitCoreDef, RC: CircuitCoreDef> Verifier for VerifierContext<SC, RC> {
    fn verify(
        &self,
        image_id: Digest,
        proof: Proof,
        journal: Journal,
    ) -> Result<(), VerificationError> {
        proof.verify(self, image_id, journal.digest())
    }

    fn suites(&self) -> &BTreeMap<String, HashSuite<BabyBear>> {
        &self.suites
    }

    fn set_suites(&mut self, suites: BTreeMap<String, HashSuite<BabyBear>>) {
        self.suites = suites;
    }
    fn set_poseidon2_mix_impl(
        &mut self,
        poseidon2: alloc::boxed::Box<dyn Poseidon2Mix + Send + Sync + 'static>,
    ) {
        Self::set_poseidon2_mix_impl(self, poseidon2)
    }

    fn extract_segment_info(&self, seal: &[u32], hashfn: &str) -> Result<u32, VerificationError> {
        let suite = self
            .suites
            .get(hashfn)
            .ok_or(VerificationError::InvalidHashSuite)?;
        // Make IOP
        let mut iop = ReadIOP::<BabyBear>::new(seal, suite.rng.as_ref());
        let slice: &[BabyBearElem] = iop.read_field_elem_slice(SC::OUTPUT_SIZE + 1);
        let (_, &[po2_elem]) = slice.split_at(SC::OUTPUT_SIZE) else {
            unreachable!()
        };
        use risc0_zkp::field::Elem;
        let (&[po2], &[]) = po2_elem.to_u32_words().split_at(1) else {
            // That means BabyBear field is more than one u32
            core::panic!("po2 elem is larger than u32");
        };
        Ok(po2)
    }
}

impl Verifier for alloc::boxed::Box<dyn Verifier> {
    fn verify(
        &self,
        image_id: Digest,
        proof: Proof,
        journal: Journal,
    ) -> Result<(), VerificationError> {
        self.as_ref().verify(image_id, proof, journal)
    }

    fn suites(&self) -> &BTreeMap<String, HashSuite<BabyBear>> {
        self.as_ref().suites()
    }

    fn set_suites(&mut self, suites: BTreeMap<String, HashSuite<BabyBear>>) {
        self.as_mut().set_suites(suites);
    }

    fn set_poseidon2_mix_impl(
        &mut self,
        poseidon2: alloc::boxed::Box<dyn Poseidon2Mix + Send + Sync + 'static>,
    ) {
        self.as_mut().set_poseidon2_mix_impl(poseidon2)
    }

    fn extract_segment_info(&self, seal: &[u32], hashfn: &str) -> Result<u32, VerificationError> {
        self.as_ref().extract_segment_info(seal, hashfn)
    }
}

impl<SC: CircuitCoreDef, RC: CircuitCoreDef> VerifierContext<SC, RC> {
    /// Create an empty [VerifierContext].
    pub fn empty(circuit: &'static SC, recursive_circuit: &'static RC) -> Self {
        Self {
            suites: BTreeMap::default(),
            segment_verifier_parameters: None,
            succinct_verifier_parameters: None,
            circuit,
            recursive_circuit,
        }
    }

    /// Return the mapping of hash suites used in the default [VerifierContext].
    pub fn default_hash_suites() -> BTreeMap<String, HashSuite<BabyBear>> {
        BTreeMap::from([
            ("blake2b".into(), Blake2bCpuHashSuite::new_suite()),
            ("poseidon2".into(), Poseidon2HashSuite::new_suite()),
            ("sha-256".into(), Sha256HashSuite::new_suite()),
        ])
    }

    /// Return [VerifierContext] with the given map of hash suites.
    pub fn with_suites(mut self, suites: BTreeMap<String, HashSuite<BabyBear>>) -> Self {
        self.suites = suites;
        self
    }

    /// Return [VerifierContext] with the given [SegmentReceiptVerifierParameters] set.
    pub fn with_segment_verifier_parameters(
        mut self,
        params: SegmentReceiptVerifierParameters,
    ) -> Self {
        self.segment_verifier_parameters = Some(params);
        self
    }

    /// Return [VerifierContext] with the given [SuccinctReceiptVerifierParameters] set.
    pub fn with_succinct_verifier_parameters(
        mut self,
        params: SuccinctReceiptVerifierParameters,
    ) -> Self {
        self.succinct_verifier_parameters = Some(params);
        self
    }

    pub fn boxed(self) -> alloc::boxed::Box<dyn Verifier> {
        alloc::boxed::Box::new(self)
    }
}

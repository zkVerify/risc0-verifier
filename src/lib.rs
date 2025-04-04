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
pub use context::{SegmentInfo, Verifier, VerifierContext, VC};
pub use key::Vk;
pub use receipt::{
    composite::CompositeReceipt, succinct::SuccinctReceipt, InnerReceipt, Journal, Proof,
};
pub use receipt_claim::{MaybePruned, ReceiptClaim};
pub use sha::{Digest, Digestible};

pub use risc0_zkp_v1::verify::VerificationError;
use crate::poseidon2_injection::Poseidon2Mix;

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
pub fn verify(
    ctx: &impl VC,
    vk: Vk,
    proof: Proof,
    pubs: Journal,
) -> Result<(), VerificationError> {
    proof.verify(ctx, vk.0, pubs.digest())
}

pub type HashSuiteV2 = risc0_zkp_v2::core::hash::HashSuite<risc0_core_v2::field::baby_bear::BabyBear>;
pub struct V2 {
    pub suites: BTreeMap<String, HashSuiteV2>,
    pub segment_verifier_parameters: Option<SegmentReceiptVerifierParameters>,
    pub succinct_verifier_parameters: Option<SuccinctReceiptVerifierParameters>,
}

struct HashFnWrapper<'a> {
    inner: &'a dyn risc0_zkp_v2::core::hash::HashFn<risc0_core_v2::field::baby_bear::BabyBear>
}
use risc0_zkvm;
impl risc0_zkp_v1::core::hash::HashFn<BabyBear> for HashFnWrapper<'_> {
    fn hash_pair(&self, a: &Digest, b: &Digest) -> Box<Digest> {
        let a = bytemuck::checked::cast_ref(a);
        let b = bytemuck::checked::cast_ref(b);
        (*self.inner.hash_pair(a, b)).into_other().into()
    }

    fn hash_elem_slice(&self, slice: &[<BabyBear as risc0_zkp_v1::field::Field>::Elem]) -> Box<Digest> {
        let slice = bytemuck::checked::cast_slice(slice);
        (*self.inner.hash_elem_slice(slice)).into_other().into()
    }

    fn hash_ext_elem_slice(&self, slice: &[<BabyBear as risc0_zkp_v1::field::Field>::ExtElem]) -> Box<Digest> {
        let slice = bytemuck::checked::cast_slice(slice);
        (*self.inner.hash_ext_elem_slice(slice)).into_other().into()
    }
}

impl V2 {
    /// Create an empty [VerifierContext].
    pub fn empty() -> Self {
        Self {
            suites: BTreeMap::default(),
            segment_verifier_parameters: None,
            succinct_verifier_parameters: None,
        }
    }

    pub fn v2_0() -> Self {
        Self::empty()
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v2_0())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v2_0())
    }

    /// Return the mapping of hash suites used in the default [VerifierContext].

    pub fn default_hash_suites() -> BTreeMap<String, HashSuiteV2> {
        BTreeMap::from([
            ("blake2b".into(), risc0_zkp_v2::core::hash::blake2b::Blake2bCpuHashSuite::new_suite()),
            ("poseidon2".into(), risc0_zkp_v2::core::hash::poseidon2::Poseidon2HashSuite::new_suite()),
            ("sha-256".into(), risc0_zkp_v2::core::hash::sha::Sha256HashSuite::new_suite()),
        ])
    }

    /// Return [VerifierContext] with the given map of hash suites.
    pub fn with_suites(mut self, suites: BTreeMap<String, HashSuiteV2>) -> Self {
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

    pub fn boxed(self) -> alloc::boxed::Box<dyn Verifier<HashSuite=HashSuiteV2>> {
        alloc::boxed::Box::new(self)
    }
}


use alloc::string::String;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use risc0_circuit_rv32im_v2::{CircuitImpl, RV32IM_SEAL_VERSION};
use risc0_core_v1::field::baby_bear::{BabyBear, BabyBearElem};
use risc0_zkp_v1::adapter::{ProtocolInfo, PROOF_SYSTEM_INFO};
use risc0_zkp_v1::core::hash::blake2b::Blake2bCpuHashSuite;
use risc0_zkp_v1::core::hash::HashSuite;
use risc0_zkp_v1::core::hash::poseidon2::Poseidon2HashSuite;
use risc0_zkp_v1::core::hash::sha::Sha256HashSuite;
use risc0_zkp_v1::verify::ReadIOP;
use crate::receipt::merkle::MerkleProof;
use crate::receipt::succinct::SuccinctReceiptVerifierParameters;
use crate::receipt_claim::Assumption;
use crate::segment::SegmentReceiptVerifierParameters;
use crate::context::IntoOther;

impl VC for V2 {
    type HashSuite = HashSuiteV2;

    fn segment_verifier_parameters(&self) -> Option<&SegmentReceiptVerifierParameters> {
        self.segment_verifier_parameters.as_ref()
    }

    fn succinct_verifier_parameters(&self) -> Option<&SuccinctReceiptVerifierParameters> {
        self.succinct_verifier_parameters.as_ref()
    }

    fn assumption_context(&self, assumption: &Assumption) -> Option<Box<dyn VC<HashSuite=Self::HashSuite>>> {
        match assumption.control_root {
            // If the control root is all zeroes, we should use the same verifier parameters.
            Digest::ZERO => None,
            // Otherwise, we should verify the assumption receipt using the guest-provided root.
            control_root => Some(
                alloc::boxed::Box::new(V2::empty()
                                           .with_suites(self.suites.clone())
                                           .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters {
                                               control_root,
                                               inner_control_root: None,
                                               proof_system_info: PROOF_SYSTEM_INFO,
                                               circuit_info: self.succinct_circuit_info(),
                                           }),
                )),
        }

    }

    fn dynamic(&self) -> Box<dyn VC<HashSuite=Self::HashSuite>> {
        let cloned = Self {
            suites: self.suites.iter().map(|(k, v)|
                (k.clone(), Self::HashSuite {
                    name: v.name.clone(),
                    hashfn: v.hashfn.clone(),
                    rng: v.rng.clone(),
                })
            ).collect(),
            segment_verifier_parameters: self.segment_verifier_parameters.clone(),
            succinct_verifier_parameters: self.succinct_verifier_parameters.clone(),
            // circuit: self.circuit,
            // recursive_circuit: self.recursive_circuit,
        };
        alloc::boxed::Box::new(cloned)

    }

    fn suite(&self, hashfn: &str) -> Option<&HashSuiteV2> {
        self.suites.get(hashfn)
    }

    fn segment_circuit_info(&self) -> ProtocolInfo {
        ProtocolInfo(*b"RV32IM:v2_______")
    }

    fn succinct_circuit_info(&self) -> ProtocolInfo {
        ProtocolInfo(*b"RECURSION:rev1v1")
    }

    fn succinct_output_size(&self) -> usize {
        32
    }

    fn decode_from_seal(&self, seal: &[u32]) -> Result<ReceiptClaim, VerificationError> {
        context::v2::decode_from_seal(seal, None)
    }

    fn verify_segment(&self, hashfn: &str, seal: &[u32], params: &SegmentReceiptVerifierParameters) -> Result<(), VerificationError> {
        let suite = self.suite(hashfn)
            .ok_or(VerificationError::InvalidHashSuite)?;

        // We don't have a `code' buffer to verify.
        let check_code_fn = |_: u32, _: &risc0_zkp_v2::core::digest::Digest| Ok(());

        if seal[0] != RV32IM_SEAL_VERSION {
            return Err(risc0_zkp_v1::verify::VerificationError::ReceiptFormatError);
        }

        let seal = &seal[1..];

        risc0_zkp_v2::verify::verify(&CircuitImpl, suite, seal, check_code_fn).map_err(|_|
            VerificationError::InvalidProof
        )
    }

    fn verify_succinct(&self, hashfn: &str, seal: &[u32], control_inclusion_proof: &MerkleProof, params: &SuccinctReceiptVerifierParameters) -> Result<(), VerificationError> {
        let suite = self.suite(hashfn)
            .ok_or(VerificationError::InvalidHashSuite)?;

        let check_code = |_, control_id: &risc0_zkp_v2::core::digest::Digest| -> Result<(), risc0_zkp_v2::verify::VerificationError> {
            let control_id_v1 = bytemuck::checked::cast_ref(control_id);
            control_inclusion_proof
                .verify(control_id_v1, &params.control_root, &HashFnWrapper { inner: suite.hashfn.as_ref() })
                .map_err(|_| {
                    log::debug!(
                        "failed to verify control inclusion proof for {control_id} against root {} with {}",
                        params.control_root,
                        suite.name,
                    );
                    risc0_zkp_v2::verify::VerificationError::ControlVerificationError {
                        control_id: *control_id,
                    }
                })
        };

        // Verify the receipt itself is correct, and therefore the encoded globals are
        // reliable.
        risc0_zkp_v2::verify::verify(&circuit::v2_0::recursive::CIRCUIT, suite, seal, check_code).map_err(|_|
            VerificationError::InvalidProof
        )
    }

    fn is_valid_receipt(&self, proof: &Proof) -> bool {
        if let Some(c) = proof.inner.composite().ok() {
            // V2 proof with `sha-256` segment are not admitted because misleading: they use
            // poseidon2 even if in the segment `hashfn` is "sha-256" as reported in
            // https://github.com/risc0/risc0/issues/3063
            if c.segments.iter().any(|s| s.hashfn == "sha-256") {
                return false;
            }
        }
        true
    }
}

struct FakeRngFactory;

struct FakeRng;

impl risc0_zkp_v1::core::hash::Rng<BabyBear> for FakeRng {
    fn mix(&mut self, val: &Digest) {
        todo!()
    }

    fn random_bits(&mut self, bits: usize) -> u32 {
        todo!()
    }

    fn random_elem(&mut self) -> <BabyBear as risc0_zkp_v1::field::Field>::Elem {
        todo!()
    }

    fn random_ext_elem(&mut self) -> <BabyBear as risc0_zkp_v1::field::Field>::ExtElem {
        todo!()
    }
}

impl risc0_zkp_v1::core::hash::RngFactory<BabyBear> for FakeRngFactory {
    fn new_rng(&self) -> alloc::boxed::Box<dyn risc0_zkp_v1::core::hash::Rng<BabyBear>> {
        alloc::boxed::Box::new(FakeRng)
    }
}

impl Verifier for V2 {

    type HashSuite = HashSuiteV2;
    fn verify(&self, image_id: Digest, proof: Proof, pubs: Journal) -> Result<(), VerificationError> {
        proof.verify(self, image_id, pubs.digest())
    }

    fn suites(&self) -> &BTreeMap<String, Self::HashSuite> {
        &self.suites
    }

    fn set_suites(&mut self, suites: BTreeMap<String, Self::HashSuite>) {
        self.suites = suites;
    }

    fn set_poseidon2_mix_impl(&mut self, poseidon2: Box<dyn Poseidon2Mix + Send + Sync + 'static>) {
        self.suites
            .entry("poseidon2".into())
            .and_modify(|s| s.hashfn = alloc::rc::Rc::new(crate::poseidon2_injection::Poseidon2Impl::new(poseidon2)));

    }

    fn extract_segment_po2(&self, seal: &[u32], hash: &str) -> Result<u32, VerificationError> {
        let seal = &seal[1..];
        let mut iop = risc0_zkp_v1::verify::ReadIOP::<risc0_zkp_v1::field::baby_bear::BabyBear>::new(
            seal,
            &FakeRngFactory,
        );
        const OUTPUT_SIZE: usize = <circuit::v2_0::CircuitImpl as risc0_zkp_v2::adapter::CircuitInfo>::OUTPUT_SIZE;
        let slice: &[BabyBearElem] = iop.read_field_elem_slice(OUTPUT_SIZE + 1);
        let (_, &[po2_elem]) = slice.split_at(OUTPUT_SIZE) else {
            unreachable!()
        };
        use risc0_zkp_v1::field::Elem;
        let (&[po2], &[]) = po2_elem.to_u32_words().split_at(1) else {
            // That means BabyBear field is more than one u32
            core::panic!("po2 elem is larger than u32");
        };
        Ok(po2)
    }

    fn mut_succinct_verifier_parameters(&mut self) -> Option<&mut SuccinctReceiptVerifierParameters> {
        self.succinct_verifier_parameters.as_mut()
    }
}
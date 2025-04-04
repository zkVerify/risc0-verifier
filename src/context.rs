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
use crate::{circuit::{self, CircuitCoreDef}, receipt::succinct::SuccinctReceiptVerifierParameters, segment::SegmentReceiptVerifierParameters, CompositeReceipt, Digestible, Journal, Proof, ReceiptClaim};
use alloc::{collections::BTreeMap, string::String};
use risc0_core_v1::field::baby_bear::BabyBearElem;
use risc0_zkp_v1::core::digest::Digest;
use risc0_zkp_v1::verify::{ReadIOP, VerificationError};
use risc0_zkp_v1::{
    core::hash::{
        blake2b::Blake2bCpuHashSuite, poseidon2::Poseidon2HashSuite, sha::Sha256HashSuite,
        HashSuite,
    },
    field::baby_bear::BabyBear,
};
use risc0_zkp_v1::adapter::{ProtocolInfo, PROOF_SYSTEM_INFO};
use crate::receipt::merkle::MerkleProof;
use crate::receipt_claim::Assumption;

/// Context available to the verification process. The context contains
/// all the info necessary to verify the proofs there are some
/// preconfigured context configurations to fit the risc0 vm versions.
///
/// The risc0 vm versions `1.x` are not interchangeable that means if had
/// generated a proof with the `1.1.x` risc0 version, you can verify it only
/// with the `1.1.y` circuit version and so you should use [`VerifierContext::v1_1()`],
/// any other context, even if it has a greater version, will fail to verify the proof.
///
/// So, `VerifierContext` defines a new constructor for each risc0 minor version
/// to have the right context for any risc0 incompatible vm version.
///
#[non_exhaustive]
#[derive(Clone)]
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

pub trait VC {
    type HashSuite;

    fn segment_verifier_parameters(&self) -> Option<&SegmentReceiptVerifierParameters>;
    fn succinct_verifier_parameters(&self) -> Option<&SuccinctReceiptVerifierParameters>;
    fn assumption_context(&self, assumption: &Assumption) -> Option<alloc::boxed::Box<dyn VC<HashSuite=Self::HashSuite>>>;
    fn dynamic(&self) -> alloc::boxed::Box<dyn VC<HashSuite=Self::HashSuite>>;

    fn suite(&self, hashfn: &str) -> Option<&Self::HashSuite>;
    fn segment_circuit_info(&self) -> ProtocolInfo;
    fn succinct_circuit_info(&self) -> ProtocolInfo;
    fn succinct_output_size(&self) -> usize;
    fn decode_from_seal(&self, seal: &[u32]) -> Result<crate::ReceiptClaim, VerificationError>;

    fn verify_segment(&self, hashfn: &str, seal: &[u32], params: &SegmentReceiptVerifierParameters) -> Result<(), VerificationError>;
    fn verify_succinct(&self, hashfn: &str, seal: &[u32], control_inclusion_proof: &MerkleProof, params: &SuccinctReceiptVerifierParameters) -> Result<(), VerificationError>;

    fn is_valid_receipt(&self, proof: &Proof) -> bool {
        true
    }
}

impl<T> VC for alloc::boxed::Box<dyn VC<HashSuite=T> + 'static> {
    type HashSuite = T;

    fn segment_verifier_parameters(&self) -> Option<&SegmentReceiptVerifierParameters> {
        self.as_ref().segment_verifier_parameters()
    }

    fn succinct_verifier_parameters(&self) -> Option<&SuccinctReceiptVerifierParameters> {
        self.as_ref().succinct_verifier_parameters()
    }

    fn assumption_context(&self, assumption: &Assumption) -> Option<alloc::boxed::Box<dyn VC<HashSuite=Self::HashSuite>>> {
        self.as_ref().assumption_context(assumption)
    }

    fn dynamic(&self) -> alloc::boxed::Box<dyn VC<HashSuite=Self::HashSuite>> {
        self.as_ref().dynamic()
    }

    fn suite(&self, hashfn: &str) -> Option<&Self::HashSuite> {
        self.as_ref().suite(hashfn)
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
}

impl<SC: CircuitCoreDef, RC: CircuitCoreDef> VC for VerifierContext<SC, RC> {

    type HashSuite = HashSuite<BabyBear>;

    fn segment_verifier_parameters(&self) -> Option<&SegmentReceiptVerifierParameters> {
        self.segment_verifier_parameters.as_ref()
    }

    fn succinct_verifier_parameters(&self) -> Option<&SuccinctReceiptVerifierParameters> {
        self.succinct_verifier_parameters.as_ref()
    }

    fn suite(&self, hashfn: &str) -> Option<&HashSuite<BabyBear>> {
        self.suites.get(hashfn)
    }

    fn segment_circuit_info(&self) -> ProtocolInfo {
        ProtocolInfo(*b"RV32IM:rev1v1___")
    }

    fn succinct_circuit_info(&self) -> ProtocolInfo {
        ProtocolInfo(*b"RECURSION:rev1v1")
    }

    fn succinct_output_size(&self) -> usize {
        32
    }

    fn decode_from_seal(&self, seal: &[u32]) -> Result<crate::ReceiptClaim, VerificationError> {
        v1::decode_receipt_claim_from_seal(seal)
    }

    fn assumption_context(&self, assumption: &Assumption) -> Option<alloc::boxed::Box<dyn VC<HashSuite=Self::HashSuite>>> {
        match assumption.control_root {
            // If the control root is all zeroes, we should use the same verifier parameters.
            Digest::ZERO => None,
            // Otherwise, we should verify the assumption receipt using the guest-provided root.
            control_root => Some(
                alloc::boxed::Box::new(VerifierContext::empty(self.circuit, self.recursive_circuit)
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

    fn verify_segment(&self, hashfn: &str, seal: &[u32], params: &SegmentReceiptVerifierParameters) -> Result<(), VerificationError> {
        let suite = self.suite(hashfn)
            .ok_or(VerificationError::InvalidHashSuite)?;

        log::debug!("SegmentReceipt::verify_integrity_with_context");
        let check_code = |_, control_id: &Digest| -> Result<(), VerificationError> {
            params.control_ids.contains(control_id).then_some(()).ok_or(
                VerificationError::ControlVerificationError {
                    control_id: *control_id,
                },
            )
        };

        risc0_zkp_v1::verify::verify(self.circuit, suite, seal, check_code)
    }

    fn verify_succinct(&self, hashfn: &str, seal: &[u32], control_inclusion_proof: &MerkleProof, params: &SuccinctReceiptVerifierParameters) -> Result<(), VerificationError> {
        let suite = self.suite(hashfn)
            .ok_or(VerificationError::InvalidHashSuite)?;

        let check_code = |_, control_id: &Digest| -> Result<(), VerificationError> {
            control_inclusion_proof
                .verify(control_id, &params.control_root, suite.hashfn.as_ref())
                .map_err(|_| {
                    log::debug!(
                        "failed to verify control inclusion proof for {control_id} against root {} with {}",
                        params.control_root,
                        suite.name,
                    );
                    VerificationError::ControlVerificationError {
                        control_id: *control_id,
                    }
                })
        };

        // Verify the receipt itself is correct, and therefore the encoded globals are
        // reliable.
        risc0_zkp_v1::verify::verify(self.recursive_circuit, suite, seal, check_code)
    }

    fn dynamic(&self) -> alloc::boxed::Box<dyn VC<HashSuite=Self::HashSuite>> {
        let cloned = Self {
            suites: self.suites.iter().map(|(k, v)|
                (k.clone(), HashSuite {
                    name: v.name.clone(),
                    hashfn: v.hashfn.clone(),
                    rng: v.rng.clone(),
                })
            ).collect(),
            segment_verifier_parameters: self.segment_verifier_parameters.clone(),
            succinct_verifier_parameters: self.succinct_verifier_parameters.clone(),
            circuit: self.circuit,
            recursive_circuit: self.recursive_circuit,
        };
        alloc::boxed::Box::new(cloned)
    }
}

mod v1 {
    use risc0_binfmt_v1::{ExitCode, SystemState};
    use risc0_core_v1::field::baby_bear::BabyBearElem;
    use risc0_core_v1::field::Elem;
    use risc0_zkp_v1::core::digest::Digest;
    use risc0_zkp_v1::layout::Tree;
    use risc0_zkp_v1::verify::VerificationError;
    use crate::{MaybePruned, ReceiptClaim};
    use risc0_circuit_rv32im_v1::layout::{SystemStateLayout, OUT_LAYOUT};
    use alloc::vec::Vec;
    const OUTPUT_SIZE : usize = 138;


    //noinspection RsUnresolvedPath RustRover False positive SystemStateLayout
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

    //noinspection RsUnresolvedPath RustRover False positive OUT_LAYOUT
    pub(crate) fn decode_receipt_claim_from_seal(
        seal: &[u32],
    ) -> Result<ReceiptClaim, VerificationError> {
        let io: &[BabyBearElem] = bytemuck::checked::cast_slice(&seal[..OUTPUT_SIZE]);
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

}

pub mod v2 {
    use risc0_binfmt_v1::{ExitCode, SystemState};
    use risc0_zkp_v1::core::digest::Digest;
    use risc0_zkp_v1::verify::VerificationError;
    use crate::context::IntoOther;
    use crate::{MaybePruned, ReceiptClaim};

    pub(crate) fn decode_from_seal(
        seal: &[u32],
        _po2: Option<u32>,
    ) -> Result<ReceiptClaim, VerificationError> {
        let claim = risc0_circuit_rv32im_v2::Rv32imV2Claim::decode(seal)
            .map_err(|_e| VerificationError::InvalidProof)?;
        log::debug!("claim: {claim:#?}");

        // TODO(flaub): implement this once shutdownCycle is supported in rv32im-v2 circuit
        // if let Some(po2) = po2 {
        //     let segment_threshold = (1 << po2) - MAX_INSN_CYCLES;
        //     ensure!(claim.shutdown_cycle.unwrap() == segment_threshold as u32);
        // }

        let exit_code = exit_code_from_rv32im_v2_claim(&claim)?;
        let post_state = match exit_code {
            ExitCode::Halted(_) => Digest::ZERO,
            _ => claim.post_state.into_other(),
        };

        Ok(ReceiptClaim {
            pre: MaybePruned::Value(SystemState {
                pc: 0,
                merkle_root: claim.pre_state.into_other(),
            }),
            post: MaybePruned::Value(SystemState {
                pc: 0,
                merkle_root: post_state,
            }),
            exit_code,
            input: MaybePruned::Pruned(claim.input.into_other()),
            output: MaybePruned::Pruned(claim.output.unwrap_or_default().into_other()),
        })
    }

    pub mod halt {
        pub const TERMINATE: u32 = 0;
        pub const PAUSE: u32 = 1;
        pub const SPLIT: u32 = 2;
    }

    pub(crate) fn exit_code_from_rv32im_v2_claim(
        claim: &risc0_circuit_rv32im_v2::Rv32imV2Claim,
    ) -> Result<ExitCode, VerificationError> {
        let exit_code = if let Some(term) = claim.terminate_state {
            let risc0_circuit_rv32im_v2::HighLowU16(user_exit, halt_type) = term.a0;
            match halt_type as u32 {
                halt::TERMINATE => ExitCode::Halted(user_exit as u32),
                halt::PAUSE => ExitCode::Paused(user_exit as u32),
                _ => panic!("Illegal halt type: {halt_type}"),
            }
        } else {
            ExitCode::SystemSplit
        };
        Ok(exit_code)
    }

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

    fn suites(&self) -> &BTreeMap<String, Self::HashSuite>;

    fn set_suites(&mut self, suites: BTreeMap<String, Self::HashSuite>);

    fn set_poseidon2_mix_impl(
        &mut self,
        poseidon2: alloc::boxed::Box<dyn Poseidon2Mix + Send + Sync + 'static>,
    );

    fn extract_segment_po2(&self, seal: &[u32], hash: &str) -> Result<u32, VerificationError>;

    fn mut_succinct_verifier_parameters(&mut self) -> Option<&mut SuccinctReceiptVerifierParameters>;
}

impl<SC: CircuitCoreDef, RC: CircuitCoreDef> Verifier for VerifierContext<SC, RC> {
    type HashSuite = HashSuite<BabyBear>;

    fn verify(
        &self,
        image_id: Digest,
        proof: Proof,
        journal: Journal,
    ) -> Result<(), VerificationError> {
        proof.verify(self, image_id, journal.digest())
    }

    fn suites(&self) -> &BTreeMap<String, Self::HashSuite> {
        &self.suites
    }

    fn set_suites(&mut self, suites: BTreeMap<String, Self::HashSuite>) {
        self.suites = suites;
    }
    fn set_poseidon2_mix_impl(
        &mut self,
        poseidon2: alloc::boxed::Box<dyn Poseidon2Mix + Send + Sync + 'static>,
    ) {
        Self::set_poseidon2_mix_impl(self, poseidon2)
    }

    fn extract_segment_po2(&self, seal: &[u32], hash: &str) -> Result<u32, VerificationError> {
        let suite = self
            .suites
            .get(hash)
            .ok_or(VerificationError::InvalidHashSuite)?;
        // Make IOP
        let mut iop = ReadIOP::<BabyBear>::new(seal, suite.rng.as_ref());
        let slice: &[BabyBearElem] = iop.read_field_elem_slice(SC::OUTPUT_SIZE + 1);
        let (_, &[po2_elem]) = slice.split_at(SC::OUTPUT_SIZE) else {
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

    fn suites(&self) -> &BTreeMap<String, Self::HashSuite> {

        self.as_ref().suites()
    }

    fn set_suites(&mut self, suites: BTreeMap<String, Self::HashSuite>) {
        self.as_mut().set_suites(suites);
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

    pub fn boxed(self) -> alloc::boxed::Box<dyn Verifier<HashSuite=HashSuite<BabyBear>>> {
        alloc::boxed::Box::new(self)
    }
}

pub trait IntoOther<T> {
    fn into_other(self) -> T;
}

impl IntoOther<risc0_zkp_v1::core::digest::Digest> for risc0_zkp_v2::core::digest::Digest {

    fn into_other(self) -> risc0_zkp_v1::core::digest::Digest {
        self.as_words().try_into().unwrap()
    }
}
impl IntoOther<risc0_zkp_v2::core::digest::Digest> for risc0_zkp_v1::core::digest::Digest {

    fn into_other(self) -> risc0_zkp_v2::core::digest::Digest {
        self.as_words().try_into().unwrap()
    }
}
impl IntoOther<risc0_zkp_v2::adapter::ProtocolInfo> for risc0_zkp_v1::adapter::ProtocolInfo {
    fn into_other(self) -> risc0_zkp_v2::adapter::ProtocolInfo {
        risc0_zkp_v2::adapter::ProtocolInfo(self.0)
    }
}

impl IntoOther<risc0_zkp_v1::adapter::ProtocolInfo> for risc0_zkp_v2::adapter::ProtocolInfo {
    fn into_other(self) -> risc0_zkp_v1::adapter::ProtocolInfo {
        risc0_zkp_v1::adapter::ProtocolInfo(self.0)
    }
}

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

use super::{CircuitInfo, VerifierContext, VerifierParameters};
use crate::receipt_claim::{MaybePruned, ReceiptClaim};
use crate::{
    circuit, circuit::CircuitCoreDefV1, poseidon2_injection::Poseidon2Mix,
    receipt::merkle::MerkleProof, receipt::succinct::SuccinctReceiptVerifierParameters,
    segment::SegmentReceiptVerifierParameters, Verifier,
};
use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};
use risc0_binfmt_v1::{ExitCode, SystemState};
//noinspection RsUnresolvedPath RustRover False positive SystemStateLayout
use risc0_circuit_rv32im_v1::layout::{SystemStateLayout, OUT_LAYOUT};
use risc0_core_v1::{
    field::baby_bear::{BabyBear, BabyBearElem},
    field::Elem,
};
use risc0_zkp_v1::adapter::ProtocolInfo;
use risc0_zkp_v1::{
    adapter::PROOF_SYSTEM_INFO, core::digest::Digest, core::hash::blake2b::Blake2bCpuHashSuite,
    core::hash::poseidon2::Poseidon2HashSuite, core::hash::sha::Sha256HashSuite,
    core::hash::HashSuite, layout::Tree, verify::VerificationError,
};

const OUTPUT_SIZE: usize = 138;

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
pub fn decode_receipt_claim_from_seal(seal: &[u32]) -> Result<ReceiptClaim, VerificationError> {
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

/// Context available to the verification process. The context contains
/// all the info necessary to verify the proofs there are some
/// preconfigured context configurations to fit the risc0 vm versions.
///
/// The risc0 vm versions `1.x` are not interchangeable that means if had
/// generated a proof with the `1.1.x` risc0 version, you can verify it only
/// with the `1.1.y` circuit version and so you should use [`V1::v1_1()`],
/// any other context, even if it has a greater version, will fail to verify the proof.
///
/// So, `VerifierContext` defines a new constructor for each risc0 minor version
/// to have the right context for any risc0 incompatible vm version.
///
#[derive(Clone)]
pub struct V1<SC: CircuitCoreDefV1, RC: CircuitCoreDefV1> {
    verifier_parameters: VerifierParametersV1,

    circuit: &'static SC,

    recursive_circuit: &'static RC,
}

impl<SC: CircuitCoreDefV1, RC: CircuitCoreDefV1> VerifierContext for V1<SC, RC> {
    type HashSuite = HashSuite<BabyBear>;

    type Segment = SegmentV1;
    type Succinct = SuccinctV1;

    fn verifier_parameters(&self) -> &VerifierParametersV1 {
        &self.verifier_parameters
    }

    fn mut_verifier_parameters(
        &mut self,
    ) -> &mut VerifierParameters<Self::Segment, Self::Succinct, Self::HashSuite> {
        &mut self.verifier_parameters
    }

    fn boxed_clone(
        &self,
    ) -> alloc::boxed::Box<
        dyn VerifierContext<
            Segment = Self::Segment,
            Succinct = Self::Succinct,
            HashSuite = Self::HashSuite,
        >,
    > {
        let cloned = Self {
            verifier_parameters: self.verifier_parameters.clone(),
            circuit: self.circuit,
            recursive_circuit: self.recursive_circuit,
        };
        alloc::boxed::Box::new(cloned)
    }

    fn boxed_succinct_verifier_with_control_root(
        &self,
        control_root: Digest,
    ) -> alloc::boxed::Box<
        dyn VerifierContext<
            Segment = Self::Segment,
            Succinct = Self::Succinct,
            HashSuite = Self::HashSuite,
        >,
    > {
        alloc::boxed::Box::new(
            V1::empty(self.circuit, self.recursive_circuit)
                .with_suites(self.verifier_parameters.suites.clone())
                .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters {
                    control_root,
                    inner_control_root: None,
                    proof_system_info: PROOF_SYSTEM_INFO,
                    circuit_info: self.succinct_circuit_info(),
                }),
        )
    }

    fn decode_from_seal(&self, seal: &[u32]) -> Result<ReceiptClaim, VerificationError> {
        decode_receipt_claim_from_seal(seal)
    }

    fn verify_segment(
        &self,
        hashfn: &str,
        seal: &[u32],
        params: &SegmentReceiptVerifierParameters,
    ) -> Result<(), VerificationError> {
        let suite = self
            .verifier_parameters()
            .suite(hashfn)
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

    fn verify_succinct(
        &self,
        hashfn: &str,
        seal: &[u32],
        control_inclusion_proof: &MerkleProof,
        params: &SuccinctReceiptVerifierParameters,
    ) -> Result<(), VerificationError> {
        let suite = self
            .verifier_parameters()
            .suite(hashfn)
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

    fn segment_seal_offset(&self) -> usize {
        0
    }

    fn set_poseidon2_mix_impl(&mut self, poseidon2: Box<dyn Poseidon2Mix + Send + Sync + 'static>) {
        self.mut_verifier_parameters()
            .suites
            .entry("poseidon2".into())
            .and_modify(|s| {
                s.hashfn =
                    alloc::rc::Rc::new(crate::poseidon2_injection::Poseidon2Impl::new(poseidon2))
            });
    }
}

impl V1<circuit::v1_0::CircuitImpl, circuit::v1_0::recursive::CircuitImpl> {
    /// Create an empty [V1] for any risc0 proof generate for any `1.0.x` vm version.
    pub fn v1_0() -> Self {
        Self::empty(&circuit::v1_0::CIRCUIT, &circuit::v1_0::recursive::CIRCUIT)
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v1_0())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v1_0())
    }
}

impl V1<circuit::v1_1::CircuitImpl, circuit::v1_1::recursive::CircuitImpl> {
    /// Create an empty [V1] for any risc0 proof generate for any `1.1.x` vm version.
    pub fn v1_1() -> Self {
        Self::empty(&circuit::v1_1::CIRCUIT, &circuit::v1_1::recursive::CIRCUIT)
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v1_1())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v1_1())
    }
}

impl V1<circuit::v1_2::CircuitImpl, circuit::v1_2::recursive::CircuitImpl> {
    /// Create an empty [V1] for any risc0 proof generate for any `1.2.x` vm version.
    pub fn v1_2() -> Self {
        Self::empty(&circuit::v1_2::CIRCUIT, &circuit::v1_2::recursive::CIRCUIT)
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v1_2())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v1_2())
    }
}

impl<SC: CircuitCoreDefV1, RC: CircuitCoreDefV1> V1<SC, RC> {
    /// Create an empty [V1].
    pub fn empty(circuit: &'static SC, recursive_circuit: &'static RC) -> Self {
        Self {
            verifier_parameters: Default::default(),
            circuit,
            recursive_circuit,
        }
    }

    /// Return the mapping of hash suites used in the default [V1].
    pub fn default_hash_suites() -> BTreeMap<String, HashSuite<BabyBear>> {
        BTreeMap::from([
            ("blake2b".into(), Blake2bCpuHashSuite::new_suite()),
            ("poseidon2".into(), Poseidon2HashSuite::new_suite()),
            ("sha-256".into(), Sha256HashSuite::new_suite()),
        ])
    }

    /// Return [V1] with the given map of hash suites.
    pub fn with_suites(mut self, suites: BTreeMap<String, HashSuite<BabyBear>>) -> Self {
        self.verifier_parameters.suites = suites;
        self
    }

    /// Return [V1] with the given [SegmentReceiptVerifierParameters] set.
    pub fn with_segment_verifier_parameters(
        mut self,
        params: SegmentReceiptVerifierParameters,
    ) -> Self {
        self.verifier_parameters.segment_verifier_parameters = Some(params);
        self
    }

    /// Return [V1] with the given [SuccinctReceiptVerifierParameters] set.
    pub fn with_succinct_verifier_parameters(
        mut self,
        params: SuccinctReceiptVerifierParameters,
    ) -> Self {
        self.verifier_parameters.succinct_verifier_parameters = Some(params);
        self
    }

    pub fn boxed(self) -> Box<dyn Verifier> {
        Box::new(self)
    }
}

pub type HashSuiteV1 = HashSuite<BabyBear>;
pub(crate) type VerifierParametersV1 = VerifierParameters<SegmentV1, SuccinctV1, HashSuiteV1>;

impl Default for VerifierParametersV1 {
    fn default() -> Self {
        Self {
            succinct_verifier_parameters: None,
            suites: BTreeMap::new(),
            segment_verifier_parameters: None,
            segment: SegmentV1,
            succinct: SuccinctV1,
        }
    }
}

impl Clone for VerifierParametersV1 {
    fn clone(&self) -> Self {
        Self {
            suites: self
                .suites
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        HashSuiteV1 {
                            name: v.name.clone(),
                            hashfn: v.hashfn.clone(),
                            rng: v.rng.clone(),
                        },
                    )
                })
                .collect(),
            segment_verifier_parameters: self.segment_verifier_parameters.clone(),
            succinct_verifier_parameters: self.succinct_verifier_parameters.clone(),
            segment: self.segment,
            succinct: self.succinct,
        }
    }
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

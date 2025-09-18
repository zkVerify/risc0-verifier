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

use super::{BoxedVC, VerifierContext, VerifierParameters};
use crate::receipt_claim::MaybePruned;
use crate::{
    circuit, circuit::CircuitCoreDefV3, poseidon2_injection::Poseidon2Mix,
    receipt::merkle::MerkleProof, receipt::succinct::SuccinctReceiptVerifierParameters,
    receipt_claim::ReceiptClaim, segment::SegmentReceiptVerifierParameters, translate::Translate,
    Proof,
};
use alloc::{boxed::Box, collections::BTreeMap, string::String};
use risc0_binfmt_v1::{ExitCode, SystemState};
use risc0_circuit_rv32im_v4::RV32IM_SEAL_VERSION;
use risc0_core_v1::field::baby_bear::BabyBear;
use risc0_zkp_v1::{
    adapter::{ProtocolInfo, PROOF_SYSTEM_INFO},
    core::digest::Digest,
    verify::VerificationError,
};
use risc0_zkp_v3::adapter::CircuitInfo;

impl<SC: CircuitCoreDefV3, RC: CircuitCoreDefV3> VerifierContext for V3<SC, RC> {
    type HashSuite = HashSuiteV3;
    type Segment = SegmentV3;
    type Succinct = SuccinctV3;
    fn verifier_parameters(&self) -> &VerifierParametersV3 {
        &self.verifier_parameters
    }

    fn mut_verifier_parameters(
        &mut self,
    ) -> &mut VerifierParameters<Self::Segment, Self::Succinct, Self::HashSuite> {
        &mut self.verifier_parameters
    }

    fn boxed_clone(&self) -> BoxedVC<Self> {
        let cloned = Self {
            verifier_parameters: self.verifier_parameters.clone(),
            circuit: self.circuit,
            recursive_circuit: self.recursive_circuit,
        };
        Box::new(cloned)
    }

    fn boxed_succinct_verifier_with_control_root(&self, control_root: Digest) -> BoxedVC<Self> {
        Box::new(
            V3::empty(&circuit::v3_0::CIRCUIT, &circuit::v3_0::recursive::CIRCUIT)
                .with_suites(self.verifier_parameters.suites.clone())
                .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters {
                    control_root,
                    inner_control_root: None,
                    proof_system_info: PROOF_SYSTEM_INFO,
                    circuit_info: self.succinct_circuit_info(),
                }),
        )
    }

    fn segment_circuit_info(&self) -> ProtocolInfo {
        circuit::v3_0::CircuitImpl::CIRCUIT_INFO.translate()
    }

    fn succinct_circuit_info(&self) -> ProtocolInfo {
        circuit::v3_0::recursive::CircuitImpl::CIRCUIT_INFO.translate()
    }

    fn succinct_output_size(&self) -> usize {
        32
    }

    fn decode_from_seal(&self, seal: &[u32]) -> Result<ReceiptClaim, VerificationError> {
        decode_from_seal(seal, None)
    }

    fn verify_segment(
        &self,
        hashfn: &str,
        seal: &[u32],
        _params: &SegmentReceiptVerifierParameters,
    ) -> Result<(), VerificationError> {
        let suite = self
            .verifier_parameters()
            .suite(hashfn)
            .ok_or(VerificationError::InvalidHashSuite)?;

        // We don't have a `code' buffer to verify.
        let check_code_fn = |_: u32, _: &risc0_zkp_v3::core::digest::Digest| Ok(());

        if seal[0] != RV32IM_SEAL_VERSION {
            return Err(VerificationError::ReceiptFormatError);
        }

        let seal = &seal[1..];

        risc0_zkp_v3::verify::verify(self.circuit, suite, seal, check_code_fn)
            .map_err(Translate::translate)
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

        let check_code = |_,
                          control_id: &risc0_zkp_v3::core::digest::Digest|
         -> Result<(), risc0_zkp_v3::verify::VerificationError> {
            let control_id_v1 = bytemuck::checked::cast_ref(control_id);
            control_inclusion_proof
                .verify(control_id_v1, &params.control_root, &HashFnWrapper { inner: suite.hashfn.as_ref() })
                .map_err(|_| {
                    log::debug!(
                        "failed to verify control inclusion proof for {control_id} against root {} with {}",
                        params.control_root,
                        suite.name,
                    );
                    risc0_zkp_v3::verify::VerificationError::ControlVerificationError {
                        control_id: *control_id,
                    }
                })
        };

        // Verify the receipt itself is correct, and therefore the encoded globals are
        // reliable.
        risc0_zkp_v3::verify::verify(self.recursive_circuit, suite, seal, check_code)
            .map_err(Translate::translate)
    }

    fn is_valid_receipt(&self, proof: &Proof) -> bool {
        if let Ok(c) = proof.inner.composite() {
            // V3 proof with `sha-256` segment are not admitted because misleading: they use
            // poseidon2 even if in the segment `hashfn` is "sha-256" as reported in
            // https://github.com/risc0/risc0/issues/3063
            if c.segments.iter().any(|s| s.hashfn == "sha-256") {
                return false;
            }
        }
        true
    }

    fn segment_seal_offset(&self) -> usize {
        1
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

fn decode_from_seal(seal: &[u32], _po2: Option<u32>) -> Result<ReceiptClaim, VerificationError> {
    let claim = risc0_circuit_rv32im_v4::Rv32imV2Claim::decode(seal)
        .map_err(|_e| VerificationError::InvalidProof)?;
    log::debug!("claim: {claim:#?}");

    let exit_code = exit_code_from_rv32im_v4_claim(&claim)?;
    let post_state = match exit_code {
        ExitCode::Halted(_) => Digest::ZERO,
        _ => claim.post_state.translate(),
    };

    Ok(ReceiptClaim {
        pre: MaybePruned::Value(SystemState {
            pc: 0,
            merkle_root: claim.pre_state.translate(),
        }),
        post: MaybePruned::Value(SystemState {
            pc: 0,
            merkle_root: post_state,
        }),
        exit_code,
        input: MaybePruned::Pruned(claim.input.translate()),
        output: MaybePruned::Pruned(claim.output.unwrap_or_default().translate()),
    })
}

#[allow(unused)]
pub mod halt {
    pub const TERMINATE: u32 = 0;
    pub const PAUSE: u32 = 1;
    pub const SPLIT: u32 = 2;
}

fn exit_code_from_rv32im_v4_claim(
    claim: &risc0_circuit_rv32im_v4::Rv32imV2Claim,
) -> Result<ExitCode, VerificationError> {
    let exit_code = if let Some(term) = claim.terminate_state {
        let risc0_circuit_rv32im_v4::HighLowU16(user_exit, halt_type) = term.a0;
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

#[derive(Default, Clone, Copy)]
pub struct SegmentV3;

impl crate::context::CircuitInfo for SegmentV3 {
    fn protocol(&self) -> ProtocolInfo {
        <circuit::v3_0::CircuitImpl as risc0_zkp_v3::adapter::CircuitInfo>::CIRCUIT_INFO.translate()
    }
    fn size(&self) -> usize {
        <circuit::v3_0::CircuitImpl as risc0_zkp_v3::adapter::CircuitInfo>::OUTPUT_SIZE
    }
}

#[derive(Default, Clone, Copy)]
pub struct SuccinctV3;

impl crate::context::CircuitInfo for SuccinctV3 {
    fn protocol(&self) -> ProtocolInfo {
        <circuit::v3_0::recursive::CircuitImpl as risc0_zkp_v3::adapter::CircuitInfo>::CIRCUIT_INFO
            .translate()
    }
    fn size(&self) -> usize {
        <circuit::v3_0::recursive::CircuitImpl as risc0_zkp_v3::adapter::CircuitInfo>::OUTPUT_SIZE
    }
}

pub type VerifierParametersV3 = VerifierParameters<SegmentV3, SuccinctV3, HashSuiteV3>;
pub type HashSuiteV3 =
    risc0_zkp_v3::core::hash::HashSuite<risc0_core_v3::field::baby_bear::BabyBear>;
pub type HashFnV3 = dyn risc0_zkp_v3::core::hash::HashFn<risc0_core_v3::field::baby_bear::BabyBear>;

pub struct V3<SC: CircuitCoreDefV3, RC: CircuitCoreDefV3> {
    verifier_parameters: VerifierParametersV3,

    circuit: &'static SC,

    recursive_circuit: &'static RC,
}

impl Default for VerifierParametersV3 {
    fn default() -> Self {
        Self {
            succinct_verifier_parameters: None,
            suites: BTreeMap::new(),
            segment_verifier_parameters: None,
            segment: SegmentV3,
            succinct: SuccinctV3,
        }
    }
}

impl Clone for VerifierParametersV3 {
    fn clone(&self) -> Self {
        Self {
            suites: self
                .suites
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        HashSuiteV3 {
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

pub struct HashFnWrapper<'a> {
    inner: &'a HashFnV3,
}

impl risc0_zkp_v1::core::hash::HashFn<BabyBear> for HashFnWrapper<'_> {
    fn hash_pair(&self, a: &Digest, b: &Digest) -> Box<Digest> {
        let a = bytemuck::checked::cast_ref(a);
        let b = bytemuck::checked::cast_ref(b);
        (*self.inner.hash_pair(a, b)).translate().into()
    }

    fn hash_elem_slice(
        &self,
        slice: &[<BabyBear as risc0_zkp_v1::field::Field>::Elem],
    ) -> Box<Digest> {
        let slice = bytemuck::checked::cast_slice(slice);
        (*self.inner.hash_elem_slice(slice)).translate().into()
    }

    fn hash_ext_elem_slice(
        &self,
        slice: &[<BabyBear as risc0_zkp_v1::field::Field>::ExtElem],
    ) -> Box<Digest> {
        let slice = bytemuck::checked::cast_slice(slice);
        (*self.inner.hash_ext_elem_slice(slice)).translate().into()
    }
}

impl<SC: CircuitCoreDefV3, RC: CircuitCoreDefV3> V3<SC, RC> {
    /// Create an empty [V3].
    pub fn empty(circuit: &'static SC, recursive_circuit: &'static RC) -> Self {
        Self {
            verifier_parameters: Default::default(),
            circuit,
            recursive_circuit,
        }
    }

    /// Return the mapping of hash suites used in the default [V3].
    pub fn default_hash_suites() -> BTreeMap<String, HashSuiteV3> {
        BTreeMap::from([
            (
                "blake2b".into(),
                risc0_zkp_v3::core::hash::blake2b::Blake2bCpuHashSuite::new_suite(),
            ),
            (
                "poseidon2".into(),
                risc0_zkp_v3::core::hash::poseidon2::Poseidon2HashSuite::new_suite(),
            ),
            (
                "sha-256".into(),
                risc0_zkp_v3::core::hash::sha::Sha256HashSuite::new_suite(),
            ),
        ])
    }

    /// Return [V3] with the given map of hash suites.
    pub fn with_suites(mut self, suites: BTreeMap<String, HashSuiteV3>) -> Self {
        self.verifier_parameters.suites = suites;
        self
    }

    /// Return [V3] with the given [SegmentReceiptVerifierParameters] set.
    pub fn with_segment_verifier_parameters(
        mut self,
        params: SegmentReceiptVerifierParameters,
    ) -> Self {
        self.verifier_parameters.segment_verifier_parameters = Some(params);
        self
    }

    /// Return [V3] with the given [SuccinctReceiptVerifierParameters] set.
    pub fn with_succinct_verifier_parameters(
        mut self,
        params: SuccinctReceiptVerifierParameters,
    ) -> Self {
        self.verifier_parameters.succinct_verifier_parameters = Some(params);
        self
    }
}

impl V3<circuit::v3_0::CircuitImpl, circuit::v3_0::recursive::CircuitImpl> {
    /// Create an empty [V3] for any risc0 proof generate for any `3.0.x` vm version.
    pub fn v3_0() -> Self {
        Self::empty(&circuit::v3_0::CIRCUIT, &circuit::v3_0::recursive::CIRCUIT)
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v3_0())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v3_0())
    }
}

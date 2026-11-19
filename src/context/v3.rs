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
use risc0_core_v1::field::baby_bear::BabyBear;
use risc0_zkp_v1::{
    adapter::{ProtocolInfo, PROOF_SYSTEM_INFO},
    core::digest::Digest,
    verify::VerificationError,
};
use risc0_zkp_v3::adapter::CircuitInfo;

/// Version specific properties of the rv32im segment circuits verified by [V3].
pub trait Rv32imCircuitV3: CircuitCoreDefV3 + CircuitInfo {
    /// The version word expected at the head of every segment seal.
    const SEAL_VERSION: u32;
    /// Whether the circuit exposes the `totalCycles` global. When it does, the verifier must
    /// check that it equals `2^po2`: this is what guarantees that a segment trace contains
    /// exactly one execution (see GHSA-g6qg-9j8p-7j87 / risc0 3.1.0 release notes).
    const HAS_TOTAL_CYCLES: bool;
}

impl Rv32imCircuitV3 for circuit::v3_0::CircuitImpl {
    const SEAL_VERSION: u32 = 2;
    const HAS_TOTAL_CYCLES: bool = false;
}

impl Rv32imCircuitV3 for circuit::v3_1::CircuitImpl {
    const SEAL_VERSION: u32 = 3;
    const HAS_TOTAL_CYCLES: bool = true;
}

/// Recursion circuits verified by [V3].
pub trait RecursionCircuitV3: CircuitCoreDefV3 + CircuitInfo {}

impl<T: CircuitCoreDefV3 + CircuitInfo> RecursionCircuitV3 for T {}

impl<SC: Rv32imCircuitV3, RC: RecursionCircuitV3> VerifierContext for V3<SC, RC> {
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
        // Assumptions must be verified with the same recursion circuit of this context.
        Box::new(
            V3::empty(self.circuit, self.recursive_circuit)
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
        SC::CIRCUIT_INFO.translate()
    }

    fn succinct_circuit_info(&self) -> ProtocolInfo {
        RC::CIRCUIT_INFO.translate()
    }

    fn succinct_output_size(&self) -> usize {
        32
    }

    fn decode_from_seal(&self, seal: &[u32]) -> Result<ReceiptClaim, VerificationError> {
        decode_from_seal::<SC>(seal)
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

        if seal.first() != Some(&SC::SEAL_VERSION) {
            return Err(VerificationError::ReceiptFormatError);
        }

        let seal = &seal[1..];

        // We don't have a `code' buffer to verify, but (when the circuit exposes it) we use this
        // callback, which receives the po2 of the trace as read from the seal, to check the
        // `totalCycles` global. The circuit constrains the row preceding each first-cycle row
        // (circularly) to have cycle number `totalCycles - 1`, so requiring
        // `totalCycles == 2^po2` ensures that the trace contains exactly one execution.
        let check_code_fn =
            |po2: u32, _: &risc0_zkp_v3::core::digest::Digest| check_total_cycles::<SC>(seal, po2);

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

/// Check the `totalCycles` global against the trace size (`2^po2`) read from the seal (header
/// removed). It's a no-op for circuits that don't expose this global.
fn check_total_cycles<SC: Rv32imCircuitV3>(
    seal: &[u32],
    po2: u32,
) -> Result<(), risc0_zkp_v3::verify::VerificationError> {
    use risc0_zkp_v3::verify::VerificationError as VerificationErrorV3;
    if !SC::HAS_TOTAL_CYCLES {
        return Ok(());
    }
    let total_cycles = globals::<SC>(seal)
        .and_then(|g| g.u32_at(rv32im_layout::TOTAL_CYCLES))
        .map_err(|_| VerificationErrorV3::ReceiptFormatError)?;
    let expected = 1u32
        .checked_shl(po2)
        .ok_or(VerificationErrorV3::ReceiptFormatError)?;
    if total_cycles != expected {
        log::debug!("totalCycles global ({total_cycles}) != 2^po2 ({expected})");
        return Err(VerificationErrorV3::InvalidProof);
    }
    Ok(())
}

/// Offsets of the rv32im (v2 circuit) global registers in the segment seal outputs. They are
/// the same for the `3.0` (`RV32IM:v2rev2`) and the `3.1` (`RV32IM:v2rev3`) circuits: `3.1`
/// just appends the `totalCycles` global. Taken from `LAYOUT_GLOBAL` in the zirgen generated
/// `layout.rs.inc` of `risc0-circuit-rv32im` `4.0.x` and `4.1.0`.
mod rv32im_layout {
    pub const INPUT: usize = 0;
    pub const IS_TERMINATE: usize = 16;
    pub const OUTPUT: usize = 17;
    pub const SHUTDOWN_CYCLE: usize = 53;
    pub const STATE_IN: usize = 54;
    pub const STATE_OUT: usize = 70;
    pub const TERM_A0_HIGH: usize = 86;
    pub const TERM_A0_LOW: usize = 87;
    pub const TERM_A1_HIGH: usize = 88;
    pub const TERM_A1_LOW: usize = 89;
    /// Only available from `RV32IM:v2rev3` (risc0 `3.1`).
    pub const TOTAL_CYCLES: usize = 90;
    /// Number of 16 bits shorts that compose a digest.
    pub const DIGEST_SHORTS: usize = 16;
}

/// The global registers of a segment seal (header removed), decoded from their Montgomery form.
struct Globals<'a>(&'a [risc0_core_v3::field::baby_bear::BabyBearElem]);

fn globals<SC: Rv32imCircuitV3>(seal: &[u32]) -> Result<Globals<'_>, VerificationError> {
    let io = seal
        .get(..SC::OUTPUT_SIZE)
        .ok_or(VerificationError::ReceiptFormatError)?;
    bytemuck::checked::try_cast_slice(io)
        .map(Globals)
        .map_err(|_| VerificationError::ReceiptFormatError)
}

impl Globals<'_> {
    fn u32_at(&self, offset: usize) -> Result<u32, VerificationError> {
        self.0
            .get(offset)
            .map(|e| e.as_u32())
            .ok_or(VerificationError::ReceiptFormatError)
    }

    fn u16_at(&self, offset: usize) -> Result<u16, VerificationError> {
        u16::try_from(self.u32_at(offset)?).map_err(|_| VerificationError::ReceiptFormatError)
    }

    /// Read a digest encoded as 16 little endian 16 bits shorts.
    fn digest_at(&self, offset: usize) -> Result<Digest, VerificationError> {
        let mut words = [0u32; risc0_zkp_v1::core::digest::DIGEST_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            let low = self.u16_at(offset + 2 * i)? as u32;
            let high = self.u16_at(offset + 2 * i + 1)? as u32;
            *w = low | (high << 16);
        }
        debug_assert_eq!(2 * words.len(), rv32im_layout::DIGEST_SHORTS);
        Ok(Digest::new(words))
    }
}

fn decode_from_seal<SC: Rv32imCircuitV3>(seal: &[u32]) -> Result<ReceiptClaim, VerificationError> {
    use rv32im_layout::*;
    if seal.first() != Some(&SC::SEAL_VERSION) {
        return Err(VerificationError::InvalidProof);
    }
    let global = globals::<SC>(&seal[1..]).map_err(|_| VerificationError::InvalidProof)?;

    // NOTE: rng and povw are not read from the globals here. Neither need to be checked to
    // establish the integrity of the claim.
    let pre_state = global.digest_at(STATE_IN)?;
    let post_state = global.digest_at(STATE_OUT)?;
    let input = global.digest_at(INPUT)?;
    let output = global.digest_at(OUTPUT)?;
    let is_terminate = global.u32_at(IS_TERMINATE)? == 1;
    // Read anyway to keep the same validation of the reference implementation.
    let _shutdown_cycle = global.u32_at(SHUTDOWN_CYCLE)?;

    let exit_code = if is_terminate {
        let user_exit = global.u16_at(TERM_A0_HIGH)?;
        let halt_type = global.u16_at(TERM_A0_LOW)?;
        // Validated even if not used in the claim.
        global.u16_at(TERM_A1_HIGH)?;
        global.u16_at(TERM_A1_LOW)?;
        match halt_type as u32 {
            halt::TERMINATE => ExitCode::Halted(user_exit as u32),
            halt::PAUSE => ExitCode::Paused(user_exit as u32),
            _ => {
                log::debug!("Illegal halt type: {halt_type}");
                return Err(VerificationError::InvalidProof);
            }
        }
    } else {
        ExitCode::SystemSplit
    };
    let output = if is_terminate { output } else { Digest::ZERO };

    let post_state = match exit_code {
        ExitCode::Halted(_) => Digest::ZERO,
        _ => post_state,
    };

    Ok(ReceiptClaim {
        pre: MaybePruned::Value(SystemState {
            pc: 0,
            merkle_root: pre_state,
        }),
        post: MaybePruned::Value(SystemState {
            pc: 0,
            merkle_root: post_state,
        }),
        exit_code,
        input: MaybePruned::Pruned(input),
        output: MaybePruned::Pruned(output),
    })
}

#[allow(unused)]
pub mod halt {
    pub const TERMINATE: u32 = 0;
    pub const PAUSE: u32 = 1;
    pub const SPLIT: u32 = 2;
}

/// Segment circuit info of a [V3] context.
#[derive(Clone, Copy)]
pub struct SegmentV3 {
    protocol: ProtocolInfo,
    size: usize,
}

impl SegmentV3 {
    fn new<SC: Rv32imCircuitV3>() -> Self {
        Self {
            protocol: SC::CIRCUIT_INFO.translate(),
            size: SC::OUTPUT_SIZE,
        }
    }
}

impl crate::context::CircuitInfo for SegmentV3 {
    fn protocol(&self) -> ProtocolInfo {
        self.protocol
    }
    fn size(&self) -> usize {
        self.size
    }
}

/// Succinct (recursion) circuit info of a [V3] context.
#[derive(Clone, Copy)]
pub struct SuccinctV3 {
    protocol: ProtocolInfo,
    size: usize,
}

impl SuccinctV3 {
    fn new<RC: RecursionCircuitV3>() -> Self {
        Self {
            protocol: RC::CIRCUIT_INFO.translate(),
            size: RC::OUTPUT_SIZE,
        }
    }
}

impl crate::context::CircuitInfo for SuccinctV3 {
    fn protocol(&self) -> ProtocolInfo {
        self.protocol
    }
    fn size(&self) -> usize {
        self.size
    }
}

pub type VerifierParametersV3 = VerifierParameters<SegmentV3, SuccinctV3, HashSuiteV3>;
pub type HashSuiteV3 =
    risc0_zkp_v3::core::hash::HashSuite<risc0_core_v3::field::baby_bear::BabyBear>;
pub type HashFnV3 = dyn risc0_zkp_v3::core::hash::HashFn<risc0_core_v3::field::baby_bear::BabyBear>;

pub struct V3<SC: Rv32imCircuitV3, RC: RecursionCircuitV3> {
    verifier_parameters: VerifierParametersV3,

    circuit: &'static SC,

    recursive_circuit: &'static RC,
}

impl VerifierParametersV3 {
    fn new<SC: Rv32imCircuitV3, RC: RecursionCircuitV3>() -> Self {
        Self {
            succinct_verifier_parameters: None,
            suites: BTreeMap::new(),
            segment_verifier_parameters: None,
            segment: SegmentV3::new::<SC>(),
            succinct: SuccinctV3::new::<RC>(),
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

impl<SC: Rv32imCircuitV3, RC: RecursionCircuitV3> V3<SC, RC> {
    /// Create an empty [V3].
    pub fn empty(circuit: &'static SC, recursive_circuit: &'static RC) -> Self {
        Self {
            verifier_parameters: VerifierParametersV3::new::<SC, RC>(),
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

impl V3<circuit::v3_1::CircuitImpl, circuit::v3_1::recursive::CircuitImpl> {
    /// Create an empty [V3] for any risc0 proof generate for any `3.1.x` vm version.
    pub fn v3_1() -> Self {
        Self::empty(&circuit::v3_1::CIRCUIT, &circuit::v3_1::recursive::CIRCUIT)
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v3_1())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v3_1())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use risc0_core_v3::field::baby_bear::BabyBearElem;
    use risc0_zkp_v3::verify::VerificationError as VerificationErrorV3;

    fn globals_with_total_cycles(output_size: usize, total_cycles: u32) -> alloc::vec::Vec<u32> {
        let mut seal = alloc::vec![BabyBearElem::new(0).as_u32_montgomery(); output_size + 10];
        if rv32im_layout::TOTAL_CYCLES < output_size {
            seal[rv32im_layout::TOTAL_CYCLES] = BabyBearElem::new(total_cycles).as_u32_montgomery();
        }
        seal
    }

    #[test]
    fn v3_1_accepts_total_cycles_equal_to_trace_size() {
        for po2 in 14..=24 {
            let seal = globals_with_total_cycles(91, 1 << po2);
            assert_eq!(
                Ok(()),
                check_total_cycles::<circuit::v3_1::CircuitImpl>(&seal, po2)
            );
        }
    }

    #[test]
    fn v3_1_rejects_total_cycles_different_from_trace_size() {
        for (total_cycles, po2) in [
            (1 << 16, 17),
            (1 << 17, 16),
            ((1 << 20) + 1, 20),
            (2 << 20, 20),
            (0, 20),
        ] {
            let seal = globals_with_total_cycles(91, total_cycles);
            assert_eq!(
                Err(VerificationErrorV3::InvalidProof),
                check_total_cycles::<circuit::v3_1::CircuitImpl>(&seal, po2),
                "total_cycles = {total_cycles}, po2 = {po2}"
            );
        }
    }

    #[test]
    fn v3_1_rejects_too_short_or_malformed_seal() {
        assert_eq!(
            Err(VerificationErrorV3::ReceiptFormatError),
            check_total_cycles::<circuit::v3_1::CircuitImpl>(&[0; 90], 16)
        );
        // Not a valid BabyBear element
        let mut seal = globals_with_total_cycles(91, 1 << 16);
        seal[rv32im_layout::TOTAL_CYCLES] = u32::MAX;
        assert_eq!(
            Err(VerificationErrorV3::ReceiptFormatError),
            check_total_cycles::<circuit::v3_1::CircuitImpl>(&seal, 16)
        );
        // po2 overflow
        let seal = globals_with_total_cycles(91, 1 << 16);
        assert_eq!(
            Err(VerificationErrorV3::ReceiptFormatError),
            check_total_cycles::<circuit::v3_1::CircuitImpl>(&seal, 32)
        );
    }

    #[test]
    fn v3_0_does_not_check_total_cycles() {
        let seal = globals_with_total_cycles(90, 0);
        assert_eq!(
            Ok(()),
            check_total_cycles::<circuit::v3_0::CircuitImpl>(&seal, 20)
        );
    }

    #[test]
    fn decode_rejects_wrong_seal_version() {
        let mut seal = alloc::vec![3u32];
        seal.extend(globals_with_total_cycles(91, 1 << 16));
        assert!(decode_from_seal::<circuit::v3_1::CircuitImpl>(&seal).is_ok());
        assert!(decode_from_seal::<circuit::v3_0::CircuitImpl>(&seal).is_err());
        seal[0] = 2;
        assert!(decode_from_seal::<circuit::v3_1::CircuitImpl>(&seal).is_err());
        assert!(decode_from_seal::<circuit::v3_0::CircuitImpl>(&seal).is_ok());
    }

    #[test]
    fn decode_rejects_illegal_halt_type() {
        let mut seal = alloc::vec![3u32];
        seal.extend(globals_with_total_cycles(91, 1 << 16));
        seal[1 + rv32im_layout::IS_TERMINATE] = BabyBearElem::new(1).as_u32_montgomery();
        seal[1 + rv32im_layout::TERM_A0_LOW] = BabyBearElem::new(2).as_u32_montgomery();
        assert_eq!(
            Err(VerificationError::InvalidProof),
            decode_from_seal::<circuit::v3_1::CircuitImpl>(&seal).map(|_| ())
        );
    }
}

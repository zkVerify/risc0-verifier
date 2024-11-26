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

use alloc::{collections::BTreeMap, string::String};
use risc0_zkp::{
    core::hash::{
        blake2b::Blake2bCpuHashSuite, poseidon2::Poseidon2HashSuite, sha::Sha256HashSuite,
        HashSuite,
    },
    field::baby_bear::BabyBear,
};

use crate::{
    circuit::{self, CircuitCoreDef},
    receipt::succinct::SuccinctReceiptVerifierParameters,
    segment::SegmentReceiptVerifierParameters,
};

/// Context available to the verification process.
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
    /// Create an empty [VerifierContext].
    pub fn v1_0() -> Self {
        Self::empty(&circuit::v1_0::CIRCUIT, &circuit::v1_0::recursive::CIRCUIT)
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v1_0())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v1_0())
    }
}

impl VerifierContext<circuit::v1_1::CircuitImpl, circuit::v1_1::recursive::CircuitImpl> {
    /// Create an empty [VerifierContext].
    pub fn v1_1() -> Self {
        Self::empty(&circuit::v1_1::CIRCUIT, &circuit::v1_1::recursive::CIRCUIT)
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v1_1())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v1_1())
    }
}

impl VerifierContext<circuit::v1_2::CircuitImpl, circuit::v1_2::recursive::CircuitImpl> {
    /// Create an empty [VerifierContext].
    pub fn v1_2() -> Self {
        Self::empty(&circuit::v1_2::CIRCUIT, &circuit::v1_2::recursive::CIRCUIT)
            .with_suites(Self::default_hash_suites())
            .with_segment_verifier_parameters(SegmentReceiptVerifierParameters::v1_2())
            .with_succinct_verifier_parameters(SuccinctReceiptVerifierParameters::v1_2())
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

    /// Return the mapping of hash suites used in the defaul [VerifierContext].
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
}

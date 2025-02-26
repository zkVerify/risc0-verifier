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

pub trait CircuitCoreDef:
    risc0_zkp::adapter::CircuitCoreDef<risc0_zkp::field::baby_bear::BabyBear> + 'static
{
}

impl<T: risc0_zkp::adapter::CircuitCoreDef<risc0_zkp::field::baby_bear::BabyBear> + 'static>
    CircuitCoreDef for T
{
}

pub mod v1_0;

pub mod v1_1;

pub mod v1_2;

pub mod v1_3 {
    pub use risc0_circuit_rv32im::*;
    use risc0_zkp::{core::digest::Digest, MAX_CYCLES_PO2, MIN_CYCLES_PO2};

    /// Fetch a control ID with the given hash, by name, and cycle limit as a power of two (po2) from
    /// the precomputed table. If the hash function is not precomputed, or the po2 is out of range,
    /// this function will return `None`.
    ///
    /// Supported values for hash_name are "sha-256", "poseidon2", and "blake2b".
    pub fn control_id(hash_name: &str, po2: usize) -> Option<Digest> {
        if !(MIN_CYCLES_PO2..=MAX_CYCLES_PO2).contains(&po2) {
            return None;
        }
        let idx = po2 - MIN_CYCLES_PO2;
        use control_id::*;
        match hash_name {
            "sha-256" => Some(SHA256_CONTROL_IDS[idx]),
            "poseidon2" => Some(POSEIDON2_CONTROL_IDS[idx]),
            "blake2b" => Some(BLAKE2B_CONTROL_IDS[idx]),
            _ => None,
        }
    }

    pub mod recursive {
        pub use risc0_circuit_recursion::*;
    }
}

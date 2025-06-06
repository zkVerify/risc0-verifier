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

use risc0_core_v1::field::baby_bear::BabyBear;

use risc0_zkp_v1::{
    adapter::{CircuitCoreDef, CircuitInfo, ProtocolInfo},
    taps::TapSet,
};

pub mod control_id;
mod poly_ext;
mod taps;

pub const CIRCUIT: CircuitImpl = CircuitImpl::new();
pub struct CircuitImpl;

impl CircuitImpl {
    const fn new() -> Self {
        CircuitImpl
    }
}

impl risc0_zkp_v1::adapter::TapsProvider for CircuitImpl {
    fn get_taps(&self) -> &'static TapSet<'static> {
        taps::TAPSET
    }
}

impl CircuitInfo for CircuitImpl {
    #[rustfmt::skip]
    const CIRCUIT_INFO: ProtocolInfo = ProtocolInfo(*b"RV32IM:rev1v1___");

#[rustfmt::skip]
    const OUTPUT_SIZE: usize = 138;

#[rustfmt::skip]
    const MIX_SIZE: usize = 40;
}

impl CircuitCoreDef<BabyBear> for CircuitImpl {}

pub mod recursive {
    use risc0_zkp_v1::{
        adapter::{CircuitCoreDef, CircuitInfo, ProtocolInfo, TapsProvider},
        field::baby_bear::BabyBear,
        taps::TapSet,
    };

    #[allow(dead_code)]
    pub mod control_id;
    mod poly_ext;
    mod taps;

    /// This struct implements traits that are defined by code generated by the
    /// circuit definition.
    pub struct CircuitImpl;

    impl CircuitImpl {
        const fn new() -> Self {
            CircuitImpl
        }
    }

    impl TapsProvider for CircuitImpl {
        fn get_taps(&self) -> &'static TapSet<'static> {
            self::taps::TAPSET
        }
    }

    pub const CIRCUIT: CircuitImpl = CircuitImpl::new();

    impl CircuitInfo for CircuitImpl {
        #[rustfmt::skip]
        const CIRCUIT_INFO: ProtocolInfo = ProtocolInfo(*b"RECURSION:rev1v1");

        #[rustfmt::skip]
        const OUTPUT_SIZE: usize = 32;

        #[rustfmt::skip]
        const MIX_SIZE: usize = 20;
    }

    impl CircuitCoreDef<BabyBear> for CircuitImpl {}
}

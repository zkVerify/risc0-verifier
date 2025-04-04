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

use alloc::boxed::Box;
use risc0_core_v1::field::baby_bear::{BabyBear, BabyBearElem};
use risc0_zkp_v1::core::digest::Digest;
use risc0_zkp_v1::core::hash::{Rng, RngFactory};
use risc0_zkp_v1::verify::{ReadIOP, VerificationError};

pub fn extract_segment_po2(seal: &[u32], output_size: usize) -> Result<u32, VerificationError> {
    let mut iop = ReadIOP::<risc0_zkp_v1::field::baby_bear::BabyBear>::new(seal, &FakeRngFactory);
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

pub struct FakeRngFactory;

impl RngFactory<BabyBear> for FakeRngFactory {
    fn new_rng(&self) -> alloc::boxed::Box<dyn Rng<BabyBear>> {
        Box::new(FakeRng)
    }
}

pub struct FakeRng;

impl Rng<BabyBear> for FakeRng {
    fn mix(&mut self, _val: &Digest) {
        unreachable!("Not implemented : IT'S A FAKE")
    }

    fn random_bits(&mut self, _bits: usize) -> u32 {
        unreachable!("Not implemented : IT'S A FAKE")
    }

    fn random_elem(&mut self) -> <BabyBear as risc0_zkp_v1::field::Field>::Elem {
        unreachable!("Not implemented : IT'S A FAKE")
    }

    fn random_ext_elem(&mut self) -> <BabyBear as risc0_zkp_v1::field::Field>::ExtElem {
        unreachable!("Not implemented : IT'S A FAKE")
    }
}

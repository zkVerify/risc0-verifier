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

//! This module export the necessary traits and functions to override the Poseidon2 hash function
//! implementation. It also define a an adapter [`Poseidon2Adapter`] that's useful to adapt a
//! poseidon2 implementation that respect the [`Poseidon2Impl`] trait be inject in verifier context.
//!
//! Finally provide a reexport of the poseidon2 risc0 implementation that can be used a to compute
//! the values: useful if you want to provide a native implementation of poseidon2 in a context where
//! the rest of the verifier is compiled and run in WASM.
//!
//!
//! ```
//! # use std::path::PathBuf;
//! # use risc0_verifier::{ Digestible, Journal, Proof,  Verifier, v1_2, Vk };
//! # use serde::{ Deserialize, Serialize };
//! # #[derive(Serialize, Deserialize)]
//! # struct Case {
//! #     receipt_path: PathBuf,
//! #     journal: Journal,
//! #     vk: Vk,
//! # }
//! # fn read_bin_all<T: serde::de::DeserializeOwned>(path: impl AsRef<std::path::Path>) -> anyhow::Result<T> {
//! #     let file = std::fs::File::open(path.as_ref())?;
//! #     let buf_reader = std::io::BufReader::new(file);
//! #     ciborium::from_reader(buf_reader).map_err(Into::into)
//! # }
//! # fn read_all<T: serde::de::DeserializeOwned>(path: impl AsRef<std::path::Path>) -> anyhow::Result<T> {
//! #     let file = std::fs::File::open(path.as_ref())?;
//! #     let buf_reader = std::io::BufReader::new(file);
//! #     let result: T = serde_json::from_reader(buf_reader)?;
//! #     Ok(result)
//! # }
//! # impl Case {
//! #     fn get_proof(&self) -> anyhow::Result<Proof> {
//! #         match self.receipt_path.extension() {
//! #             Some(ext) if ext == "json" => read_all(&self.receipt_path),
//! #             Some(ext) if ext == "bin" => read_bin_all(&self.receipt_path),
//! #             _ => Err(anyhow::anyhow!(
//! #                 "Unsupported file extension: {:?}",
//! #                 self.receipt_path.extension()
//! #             )),
//! #         }
//! #     }
//! # }
//! use risc0_verifier::{
//!     poseidon2_injection::{
//!     BabyBearElem, poseidon2_mix, Poseidon2Mix, POSEIDON2_CELLS
//! } };
//! struct LocPoseidon2;
//!
//! impl Poseidon2Mix for LocPoseidon2 {
//!     #[inline]
//!     fn poseidon2_mix(
//!         &self,
//!         cells: &mut [BabyBearElem; POSEIDON2_CELLS],
//!     ) {
//!         poseidon2_mix(cells);
//!     }
//! }
//!
//! let mut verifier = v1_2();
//! verifier.set_poseidon2_mix_impl(Box::new(LocPoseidon2));
//!
//! let case: Case = read_all("./resources/cases/prover_1.2.0/vm_1.2.0/poseidon2_22.json").unwrap();
//! let proof = case.get_proof().unwrap();
//!
//! verifier.verify(case.vk.into(), proof, case.journal).unwrap()
//! ```
//!

extern crate alloc;
use alloc::boxed::Box;

use super::Digest;
use risc0_core_v1::field::baby_bear::BabyBear;

// Re-export the poseidon2 risc0 implementation and field type.

/// Babybear element is a `transparent` wrapper of `u32`: so it's safe to transmute it in
/// a `u32`.
pub use risc0_core_v1::field::baby_bear::BabyBearElem;
pub use risc0_zkp_v1::core::hash::poseidon2::{poseidon2_mix, CELLS as POSEIDON2_CELLS};

use risc0_zkp_v1::{
    core::{
        digest::DIGEST_WORDS,
        hash::{
            poseidon2::{CELLS_OUT, CELLS_RATE},
            HashFn,
        },
    },
    field::{Elem as _, ExtElem as _},
};

/// Abstract the capability of implement a base poseidon2 hash function.
pub trait Poseidon2Mix {
    fn poseidon2_mix(&self, cells: &mut [BabyBearElem; POSEIDON2_CELLS]);
}

impl Poseidon2Mix for alloc::boxed::Box<dyn Poseidon2Mix + Send + Sync> {
    fn poseidon2_mix(&self, cells: &mut [BabyBearElem; POSEIDON2_CELLS]) {
        self.as_ref().poseidon2_mix(cells)
    }
}

pub trait Boxed {
    fn boxed(self) -> Box<dyn Poseidon2Mix + Send + Sync>;
}
impl<T: Poseidon2Mix + Send + Sync + 'static> Boxed for T {
    fn boxed(self) -> Box<dyn Poseidon2Mix + Send + Sync> {
        Box::new(self)
    }
}

pub(crate) struct Poseidon2Impl<T>(T);

impl<T> Poseidon2Impl<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }
}

fn to_digest(elems: [BabyBearElem; CELLS_OUT]) -> Box<Digest> {
    let mut state: [u32; DIGEST_WORDS] = [0; DIGEST_WORDS];
    for i in 0..DIGEST_WORDS {
        state[i] = elems[i].as_u32_montgomery();
    }
    Box::new(Digest::from(state))
}

impl<T: Poseidon2Mix> Poseidon2Impl<T> {
    /// Perform an unpadded hash of a vector of elements.  Because this is unpadded
    /// collision resistance is only true for vectors of the same size.  If the size
    /// is variable, this is subject to length extension attacks.
    fn unpadded_hash<'a, I>(&self, iter: I) -> [BabyBearElem; CELLS_OUT]
    where
        I: Iterator<Item = &'a BabyBearElem>,
    {
        let mut state = [BabyBearElem::ZERO; POSEIDON2_CELLS];
        let mut count = 0;
        let mut unmixed = 0;
        for val in iter {
            state[unmixed] = *val;
            count += 1;
            unmixed += 1;
            if unmixed == CELLS_RATE {
                poseidon2_mix(&mut state);
                unmixed = 0;
            }
        }
        if unmixed != 0 || count == 0 {
            // Zero pad to get a CELLS_RATE-aligned number of inputs
            for elem in state.iter_mut().take(CELLS_RATE).skip(unmixed) {
                *elem = BabyBearElem::ZERO;
            }
            self.0.poseidon2_mix(&mut state);
        }
        state.as_slice()[0..CELLS_OUT].try_into().unwrap()
    }
}

impl<T: Poseidon2Mix + Send + Sync> HashFn<BabyBear> for Poseidon2Impl<T> {
    fn hash_pair(&self, a: &Digest, b: &Digest) -> Box<Digest> {
        let both: alloc::vec::Vec<BabyBearElem> = a
            .as_words()
            .iter()
            .chain(b.as_words().iter())
            .map(|w| BabyBearElem::new_raw(*w))
            .collect();
        assert!(both.len() == DIGEST_WORDS * 2);
        for elem in &both {
            assert!(elem.is_reduced());
        }
        to_digest(self.unpadded_hash(both.iter()))
    }

    fn hash_elem_slice(
        &self,
        slice: &[<BabyBear as risc0_zkp_v1::field::Field>::Elem],
    ) -> Box<Digest> {
        to_digest(self.unpadded_hash(slice.iter()))
    }

    fn hash_ext_elem_slice(
        &self,
        slice: &[<BabyBear as risc0_zkp_v1::field::Field>::ExtElem],
    ) -> Box<Digest> {
        to_digest(self.unpadded_hash(slice.iter().flat_map(|ee| ee.subelems().iter())))
    }
}

mod v2 {
    use crate::poseidon2_injection::{Poseidon2Impl, Poseidon2Mix};
    use crate::translate::Translate;
    use alloc::boxed::Box;
    use risc0_core_v2::field::{baby_bear::BabyBear, Field};
    use risc0_zkp_v2::core::digest::Digest;

    impl<T: Poseidon2Mix + Send + Sync> risc0_zkp_v2::core::hash::HashFn<BabyBear>
        for Poseidon2Impl<T>
    {
        fn hash_pair(&self, a: &Digest, b: &Digest) -> Box<Digest> {
            let a = bytemuck::checked::cast_ref(a);
            let b = bytemuck::checked::cast_ref(b);
            let d = *<Self as risc0_zkp_v1::core::hash::HashFn<
                risc0_core_v1::field::baby_bear::BabyBear,
            >>::hash_pair(self, a, b);
            d.translate().into()
        }

        fn hash_elem_slice(&self, slice: &[<BabyBear as Field>::Elem]) -> Box<Digest> {
            let slice = bytemuck::checked::cast_slice(slice);
            (*<Self as risc0_zkp_v1::core::hash::HashFn<
                risc0_core_v1::field::baby_bear::BabyBear,
            >>::hash_elem_slice(self, slice))
            .translate()
            .into()
        }

        fn hash_ext_elem_slice(&self, slice: &[<BabyBear as Field>::ExtElem]) -> Box<Digest> {
            let slice = bytemuck::checked::cast_slice(slice);
            (*<Self as risc0_zkp_v1::core::hash::HashFn<
                risc0_core_v1::field::baby_bear::BabyBear,
            >>::hash_ext_elem_slice(self, slice))
            .translate()
            .into()
        }
    }
}

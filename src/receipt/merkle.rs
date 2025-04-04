// Copyright Copyright 2024, Horizen Labs, Inc.
// Copyright Copyright 2024 RISC Zero, Inc.
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

//! Minimal Merkle tree implementation used in the recursion system for committing to a group of
//! control IDs.

use alloc::vec::Vec;

use anyhow::{ensure, Result};
use risc0_core_v1::field::baby_bear::BabyBear;
use risc0_zkp_v1::core::{digest::Digest, hash::HashFn};
use serde::{Deserialize, Serialize};

/// Used to verify inclusion of a given recursion program in the committed set.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MerkleProof {
    /// Index of the leaf for which inclusion is being proven.
    pub index: u32,
    /// Sibling digests on the path from the root to the leaf.
    /// Does not include the root of the leaf.
    pub digests: Vec<Digest>,
}

impl MerkleProof {
    /// Verify the Merkle inclusion proof against the given leaf and root.
    pub fn verify(
        &self,
        leaf: &Digest,
        root: &Digest,
        hashfn: &dyn HashFn<BabyBear>,
    ) -> Result<()> {
        ensure!(
            self.root(leaf, hashfn) == *root,
            "merkle proof verify failed"
        );
        Ok(())
    }

    /// Calculate the root of this branch by iteratively hashing, starting from the leaf.
    pub fn root(&self, leaf: &Digest, hashfn: &dyn HashFn<BabyBear>) -> Digest {
        let mut cur = *leaf;
        let mut cur_index = self.index;
        for sibling in &self.digests {
            cur = if cur_index & 1 == 0 {
                *hashfn.hash_pair(&cur, sibling)
            } else {
                *hashfn.hash_pair(sibling, &cur)
            };
            cur_index >>= 1;
        }
        cur
    }
}

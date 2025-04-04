// Copyright 2024, Horizen Labs, Inc.
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

use serde::{Deserialize, Serialize};

/// The verification key (aka image id, the hash of the guest program)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vk(pub risc0_zkp_v1::core::digest::Digest);

impl Vk {
    pub fn as_words(&self) -> &[u32] {
        self.0.as_words()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<[u32; risc0_zkp_v1::core::digest::DIGEST_WORDS]> for Vk {
    fn from(value: [u32; risc0_zkp_v1::core::digest::DIGEST_WORDS]) -> Self {
        Self(value.into())
    }
}

impl From<[u8; risc0_zkp_v1::core::digest::DIGEST_BYTES]> for Vk {
    fn from(value: [u8; risc0_zkp_v1::core::digest::DIGEST_BYTES]) -> Self {
        Vk(value.into())
    }
}

impl From<Vk> for risc0_zkp_v1::core::digest::Digest {
    fn from(value: Vk) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::Vk;

    #[test]
    fn should_have_same_from_result() {
        let vu32: [u32; 8] = [
            1067704626, 3452143673, 166143985, 2720203724, 4153258584, 3584210768, 3821389021,
            2575106175,
        ];
        let vu8: [u8; 32] = [
            0x32, 0xe1, 0xa3, 0x3f, 0x39, 0x88, 0xc3, 0xcd, 0xf1, 0x27, 0xe7, 0x09, 0xcc, 0x03,
            0x23, 0xa2, 0x58, 0xb2, 0x8d, 0xf7, 0x50, 0xb7, 0xa2, 0xd5, 0xdd, 0xc4, 0xc5, 0xe3,
            0x7f, 0x00, 0x7d, 0x99,
        ];

        let vu32: Vk = vu32.into();
        let vu8: Vk = vu8.into();

        assert!(vu32.0.eq(&vu8.0));
    }
}

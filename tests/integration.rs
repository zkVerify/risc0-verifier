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

use risc0_verifier::{verify, DeserializeError, VerifyError};
use rstest::rstest;
use serde::Deserialize;
use std::path::{Path, PathBuf};

fn load_data(path: &Path) -> ([u32; 8], Vec<u8>, Vec<u8>) {
    #[derive(Deserialize)]
    struct Data {
        vk: [u32; 8],
        proof: String,
        pubs: String,
    }

    let Data { vk, proof, pubs } =
        serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();

    let proof = <Vec<u8>>::try_from(hex::decode(proof).unwrap()).unwrap();
    let pubs = <Vec<u8>>::try_from(hex::decode(pubs).unwrap()).unwrap();

    (vk, proof, pubs)
}

#[rstest]
fn should_verify_valid_proof(#[files("./resources/valid_proof_*.json")] path: PathBuf) {
    let (vk, proof, pubs) = load_data(&path);

    assert!(verify(vk.into(), &proof, &pubs).is_ok());
}

#[test]
fn should_not_verify_invalid_proof() {
    let (vk, mut proof, pubs) = load_data(Path::new("./resources/valid_proof_1.json"));

    proof[0] = proof.first().unwrap().wrapping_add(1);

    assert!(matches!(
        verify(vk.into(), &proof, &pubs),
        Err(VerifyError::InvalidData {
            cause: DeserializeError::InvalidProof
        })
    ));
}

#[test]
fn should_not_verify_invalid_pubs() {
    let (vk, proof, mut pubs) = load_data(Path::new("./resources/valid_proof_1.json"));

    pubs[0] = pubs.first().unwrap().wrapping_add(1);

    assert!(matches!(
        verify(vk.into(), &proof, &pubs),
        Err(VerifyError::InvalidData {
            cause: DeserializeError::InvalidPublicInputs
        })
    ));
}

#[test]
fn should_not_verify_false_proof() {
    let (vk, proof, mut pubs) = load_data(Path::new("./resources/valid_proof_1.json"));

    let len = pubs.len();

    pubs[len - 1] = pubs.last().unwrap().wrapping_add(1);

    assert!(matches!(
        verify(vk.into(), &proof, &pubs),
        Err(VerifyError::Failure { .. })
    ));
}

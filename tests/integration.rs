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

use risc0_verifier::{verify, VerifyError};
use rstest::rstest;
use serde::Deserialize;
use std::path::{Path, PathBuf};

fn load_data(path: &Path) -> (Vec<u8>, [u32; 8]) {
    #[derive(Deserialize)]
    struct Data {
        proof_raw_data: String,
        image_id: [u32; 8],
    }

    let Data {
        proof_raw_data,
        image_id,
    } = serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();

    let proof_raw_data = <Vec<u8>>::try_from(hex::decode(proof_raw_data).unwrap()).unwrap();

    (proof_raw_data, image_id)
}

#[rstest]
fn should_verify_valid_proof(#[files("./resources/valid_proof_*.json")] path: PathBuf) {
    let (proof_raw_data, image_id_data) = load_data(&path);

    assert!(verify(&proof_raw_data, image_id_data.into()).is_ok());
}

#[test]
fn should_not_verify_invalid_proof() {
    let (mut proof_raw_data, image_id_data) =
        load_data(Path::new("./resources/valid_proof_1.json"));

    proof_raw_data[0] = proof_raw_data.first().unwrap().wrapping_add(1);

    assert!(matches!(
        verify(&proof_raw_data, image_id_data.into()),
        Err(VerifyError::InvalidData { .. })
    ));
}

#[test]
fn should_not_verify_false_proof() {
    let (mut proof_raw_data, image_id_data) =
        load_data(Path::new("./resources/valid_proof_1.json"));

    let len = proof_raw_data.len();
    proof_raw_data[len - 1] = proof_raw_data.last().unwrap().wrapping_add(1);

    assert!(matches!(
        verify(&proof_raw_data, image_id_data.into()),
        Err(VerifyError::Failure { .. })
    ));
}

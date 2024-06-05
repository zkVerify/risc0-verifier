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

use risc0_verifier::{extract_pubs_from_full_proof, verify, VerifyError};
use rstest::rstest;
use serde::Deserialize;
use std::path::{Path, PathBuf};

fn load_data(path: &Path) -> ([u32; 8], Vec<u8>, [u8; 32]) {
    #[derive(Deserialize)]
    struct Data {
        image_id: [u32; 8],
        full_proof: String,
    }

    let Data {
        image_id,
        full_proof,
    } = serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();

    let full_proof = <Vec<u8>>::try_from(hex::decode(full_proof).unwrap()).unwrap();
    let pubs = extract_pubs_from_full_proof(&full_proof).unwrap();

    (image_id, full_proof, pubs)
}

#[rstest]
fn should_verify_valid_proof(#[files("./resources/valid_proof_*.json")] path: PathBuf) {
    let (image_id, full_proof, pubs) = load_data(&path);

    assert!(verify(image_id.into(), &full_proof, pubs).is_ok());
}

#[test]
fn should_not_verify_invalid_proof() {
    let (image_id, mut full_proof, pubs) = load_data(Path::new("./resources/valid_proof_1.json"));

    full_proof[0] = full_proof.first().unwrap().wrapping_add(1);

    assert!(matches!(
        verify(image_id.into(), &full_proof, pubs),
        Err(VerifyError::InvalidData { .. })
    ));
}

#[test]
fn should_not_verify_mismatching_inputs() {
    let (image_id, mut full_proof, pubs) = load_data(Path::new("./resources/valid_proof_1.json"));

    let len = full_proof.len();
    full_proof[len - 1] = full_proof.last().unwrap().wrapping_add(1);

    assert!(matches!(
        verify(image_id.into(), &full_proof, pubs),
        Err(VerifyError::MismatchingPublicInputs { .. })
    ));
}

#[test]
fn should_not_verify_false_proof() {
    let (image_id, mut full_proof, mut pubs) =
        load_data(Path::new("./resources/valid_proof_1.json"));

    // we know journal.bytes for that proof is 4 bytes
    let journal_bytes_size = 4;
    let len = full_proof.len();
    full_proof[len - journal_bytes_size] = full_proof[len - journal_bytes_size].wrapping_add(1);
    pubs[0] = pubs[0].wrapping_add(1);

    assert!(matches!(
        verify(image_id.into(), &full_proof, pubs),
        Err(VerifyError::Failure { .. })
    ));
}

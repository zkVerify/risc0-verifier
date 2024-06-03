// Copyright 2024, The Horizen Foundation
// LICENSE TO BE ADDED [TODO]

use risc0_verifier::{verify, ProofRawData, VerifyError};
use rstest::rstest;
use serde::Deserialize;
use std::path::{Path, PathBuf};

fn load_data(path: &Path) -> (ProofRawData, [u32; 8]) {
    #[derive(Deserialize)]
    struct Data {
        raw_proof_data: String,
        image_id_data: [u32; 8],
    }

    let Data {
        raw_proof_data,
        image_id_data,
    } = serde_json::from_reader(std::fs::File::open(path).unwrap()).unwrap();

    let proof_raw_data = <ProofRawData>::try_from(hex::decode(raw_proof_data).unwrap()).unwrap();

    (proof_raw_data, image_id_data)
}

#[rstest]
fn should_verify_valid_proof(#[files("./resources/*.json")] path: PathBuf) {
    let (proof_raw_data, image_id_data) = load_data(&path);

    assert!(verify(proof_raw_data, image_id_data.into()).is_ok());
}

#[test]
fn should_not_verify_invalid_proof() {
    let (mut proof_raw_data, image_id_data) =
        load_data(Path::new("./resources/valid_proof_1.json"));

    proof_raw_data[0] = (proof_raw_data.first().unwrap() + 1) % 255;

    assert!(matches!(
        verify(proof_raw_data, image_id_data.into()),
        Err(VerifyError::InvalidData { .. })
    ));
}

#[test]
fn should_not_verify_false_proof() {
    let (mut proof_raw_data, image_id_data) =
        load_data(Path::new("./resources/valid_proof_1.json"));

    let len = proof_raw_data.len();
    proof_raw_data[len - 1] = (proof_raw_data.last().unwrap() + 1) % 255;

    assert!(matches!(
        verify(proof_raw_data, image_id_data.into()),
        Err(VerifyError::Failure { .. })
    ));
}

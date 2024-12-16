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

use risc0_verifier::Digestible as _;
use risc0_verifier::{verify, verify_with_context};
use risc0_verifier::{
    CircuitCoreDef, CompositeReceipt, Journal, MaybePruned, Proof, ReceiptClaim, SuccinctReceipt,
    VerifierContext, Vk,
};
use risc0_zkp::core::hash::HashFn;
use risc0_zkp::field::baby_bear::BabyBear;
use risc0_zkp::field::Field;
use risc0_zkp::verify::VerificationError;
use rstest::rstest;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

mod legacy {

    use super::*;
    use snafu::Snafu;

    #[rstest]
    fn should_verify_valid_proof(#[files("./resources/old/valid_proof_*.json")] path: PathBuf) {
        let (vk, proof, pubs) = load_data(&path);

        let inner_receipt = deserialize_proof(&proof).unwrap();
        let journal = deserialize_pubs(&pubs).unwrap();

        let ctx = VerifierContext::v1_0();
        let proof = Proof::new(inner_receipt);
        proof
            .verify_with_context(&ctx, vk, journal.digest())
            .unwrap()
    }

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

    /// Deserialization error
    #[derive(Debug, Snafu)]
    enum DeserializeError {
        /// Invalid proof
        #[snafu(display("Invalid proof for deserialization"))]
        InvalidProof,
        /// Invalid public inputs
        #[snafu(display("Invalid public inputs for deserialization"))]
        InvalidPublicInputs,
    }

    fn deserialize_proof(proof: &[u8]) -> Result<risc0_verifier::InnerReceipt, DeserializeError> {
        bincode::deserialize(proof).map_err(|_x| DeserializeError::InvalidProof)
    }

    fn deserialize_pubs(pubs: &[u8]) -> Result<Journal, DeserializeError> {
        bincode::deserialize(pubs).map_err(|_x| DeserializeError::InvalidPublicInputs)
    }
}

#[test]
fn verify_valid_proof() {
    let case: Case = read_all("./resources/cases/prover_1.2.0/vm_1.2.0/poseidon2_22.json").unwrap();

    let proof = case.get_proof().unwrap();

    verify(case.vk, proof, case.journal).unwrap()
}

#[test]
fn verify_with_context_valid_proof() {
    let case: Case = read_all("./resources/cases/prover_1.0.3/vm_1.1.3/sha_16.json").unwrap();

    let proof = case.get_proof().unwrap();

    verify_with_context(&VerifierContext::v1_0(), case.vk, proof, case.journal).unwrap()
}

mod v1_0 {
    use super::*;

    #[rstest]
    #[case::should_pass(VerifierContext::v1_0())]
    #[should_panic(expected = "control_id mismatch")]
    #[case::should_fails_with_new_verifier(VerifierContext::v1_1())]
    fn verify_valid_proof<SC: CircuitCoreDef, RC: CircuitCoreDef>(
        #[case] ctx: VerifierContext<SC, RC>,
        #[files("./resources/cases/prover_1.0.*/**/*.json")] path: PathBuf,
    ) {
        let case: Case = read_all(path).unwrap();

        let proof = case.get_proof().unwrap();

        proof
            .verify_with_context(&ctx, case.vk, case.journal.digest())
            .unwrap()
    }
}

mod v1_1 {
    use super::*;

    #[rstest]
    #[case::should_pass(VerifierContext::v1_1())]
    #[should_panic(expected = "control_id mismatch")]
    #[case::should_fails_with_old_verifier(VerifierContext::v1_0())]
    fn verify_valid_proof<SC: CircuitCoreDef, RC: CircuitCoreDef>(
        #[case] ctx: VerifierContext<SC, RC>,
        #[files("./resources/cases/prover_1.1.*/**/*.json")] path: PathBuf,
    ) {
        let case: Case = read_all(path).unwrap();

        let proof = case.get_proof().unwrap();

        proof
            .verify_with_context(&ctx, case.vk, case.journal.digest())
            .unwrap()
    }
}

mod v1_2 {
    use super::*;

    #[rstest]
    #[case::should_pass(VerifierContext::v1_2())]
    #[should_panic(expected = "control_id mismatch")]
    #[case::should_fails_with_old_verifier(VerifierContext::v1_0())]
    fn verify_valid_proof<SC: CircuitCoreDef, RC: CircuitCoreDef>(
        #[case] ctx: VerifierContext<SC, RC>,
        #[files("./resources/cases/prover_1.2.*/**/*.json")] path: PathBuf,
    ) {
        let case: Case = read_all(path).unwrap();

        let proof = case.get_proof().unwrap();

        proof
            .verify_with_context(&ctx, case.vk, case.journal.digest())
            .unwrap()
    }
}

mod use_custom_local_implemented_hash_function {
    use super::*;

    use risc0_verifier::sha::Sha256;
    use risc0_zkp::core::digest::Digest;
    use risc0_zkp::core::hash::sha::cpu::Impl;
    struct CorrectSha256;

    impl HashFn<BabyBear> for CorrectSha256 {
        fn hash_pair(&self, a: &Digest, b: &Digest) -> Box<Digest> {
            (*Impl::hash_pair(a, b)).into()
        }

        fn hash_elem_slice(&self, slice: &[<BabyBear as Field>::Elem]) -> Box<Digest> {
            (*Impl::hash_raw_data_slice(slice)).into()
        }

        fn hash_ext_elem_slice(&self, slice: &[<BabyBear as Field>::ExtElem]) -> Box<Digest> {
            (*Impl::hash_raw_data_slice(slice)).into()
        }
    }

    struct FakeSha256;

    impl HashFn<BabyBear> for FakeSha256 {
        fn hash_pair(&self, _a: &Digest, _b: &Digest) -> Box<Digest> {
            (Digest::ZERO).into()
        }

        fn hash_elem_slice(&self, _slice: &[<BabyBear as Field>::Elem]) -> Box<Digest> {
            (Digest::ZERO).into()
        }

        fn hash_ext_elem_slice(&self, _slice: &[<BabyBear as Field>::ExtElem]) -> Box<Digest> {
            (Digest::ZERO).into()
        }
    }

    #[test]
    fn should_work() {
        let mut ctx = VerifierContext::v1_2();
        let mut suites = ctx.suites.clone();
        let mut sha = suites.get("sha-256").cloned().unwrap();
        sha.hashfn = std::rc::Rc::new(CorrectSha256);

        suites.insert("sha-256".to_owned(), sha).unwrap();
        ctx = ctx.with_suites(suites);

        let case: Case = read_all("./resources/cases/prover_1.2.0/vm_1.2.0/sha_16.json").unwrap();

        let proof = case.get_proof().unwrap();

        proof
            .verify_with_context(&ctx, case.vk, case.journal.digest())
            .unwrap()
    }

    #[test]
    fn should_fail() {
        let mut ctx = VerifierContext::v1_2();
        let mut suites = ctx.suites.clone();
        let mut sha = suites.get("sha-256").cloned().unwrap();
        sha.hashfn = std::rc::Rc::new(FakeSha256);

        suites.insert("sha-256".to_owned(), sha).unwrap();
        ctx = ctx.with_suites(suites);

        let case: Case = read_all("./resources/cases/prover_1.2.0/vm_1.2.0/sha_16.json").unwrap();

        let proof = case.get_proof().unwrap();

        proof
            .verify_with_context(&ctx, case.vk, case.journal.digest())
            .unwrap_err();
    }
}

#[rstest_reuse::apply(segments)]
fn fails_on_invalid_segment<SC: CircuitCoreDef, RC: CircuitCoreDef>(
    #[case] ctx: VerifierContext<SC, RC>,
    #[case] path: &str,
    #[values(0, 1, 2)] segment: usize,
) {
    let case: Case = read_all(path).unwrap();
    let mut proof = case.get_proof().unwrap();

    let seal = proof.inner.mut_composite().unwrap().segments[segment]
        .seal
        .as_mut_slice();

    seal[seal.len() / 2] = seal[seal.len() / 2].wrapping_add(1);

    let res = proof.verify_with_context(&ctx, case.vk, case.journal.digest());

    assert!(res.is_err());
    assert!(matches!(res, Err(VerificationError::InvalidProof { .. })));
}

#[rstest_reuse::apply(succinct)]
fn fails_on_invalid_succinct<SC: CircuitCoreDef, RC: CircuitCoreDef>(
    #[case] ctx: VerifierContext<SC, RC>,
    #[case] path: &str,
) {
    let case: Case = read_all(path).unwrap();
    let mut proof = case.get_proof().unwrap();

    let seal = proof.inner.mut_succinct().unwrap().seal.as_mut_slice();

    seal[seal.len() / 2] = seal[seal.len() / 2].wrapping_add(1);

    let res = proof.verify_with_context(&ctx, case.vk, case.journal.digest());

    assert!(res.is_err());
    assert!(matches!(res, Err(VerificationError::InvalidProof { .. })));
}

#[rstest_reuse::apply(all)]
fn fails_on_invalid_vk<SC: CircuitCoreDef, RC: CircuitCoreDef>(
    #[case] ctx: VerifierContext<SC, RC>,
    #[case] path: &str,
) {
    let mut case: Case = read_all(path).unwrap();
    let proof = case.get_proof().unwrap();

    case.vk
        .0
        .as_mut_words()
        .last_mut()
        .map(|l| *l = l.wrapping_add(1));

    let res = proof.verify_with_context(&ctx, case.vk, case.journal.digest());

    assert!(res.is_err());
    assert!(
        matches!(res, Err(VerificationError::ClaimDigestMismatch { .. })),
        "Invalid err {res:?}"
    );
}

#[rstest_reuse::apply(all)]
fn fails_on_invalid_pubs<SC: CircuitCoreDef, RC: CircuitCoreDef>(
    #[case] ctx: VerifierContext<SC, RC>,
    #[case] path: &str,
) {
    let mut case: Case = read_all(path).unwrap();
    let proof = case.get_proof().unwrap();

    case.journal
        .bytes
        .last_mut()
        .map(|l| *l = l.wrapping_add(1));

    let res = proof.verify_with_context(&ctx, case.vk, case.journal.digest());

    assert!(res.is_err());
    assert!(
        matches!(res, Err(VerificationError::ClaimDigestMismatch { .. })),
        "Invalid err {res:?}"
    );
}

#[rstest_reuse::apply(segments)]
fn fails_on_invalid_claim<SC: CircuitCoreDef, RC: CircuitCoreDef>(
    #[case] ctx: VerifierContext<SC, RC>,
    #[case] path: &str,
) {
    let case: Case = read_all(path).unwrap();
    let mut proof = case.get_proof().unwrap();

    proof.inner.mut_composite().unwrap().segments[0]
        .claim
        .exit_code = risc0_binfmt::ExitCode::Halted(0);

    let res = proof.verify_with_context(&ctx, case.vk, case.journal.digest());

    assert!(res.is_err());
    assert!(
        matches!(res, Err(VerificationError::ClaimDigestMismatch { .. })),
        "Invalid err {res:?}"
    );
}

#[rstest_reuse::apply(succinct)]
fn fails_on_invalid_inner_control_root<SC: CircuitCoreDef, RC: CircuitCoreDef>(
    #[case] mut ctx: VerifierContext<SC, RC>,
    #[case] path: &str,
) {
    let case: Case = read_all(path).unwrap();
    let proof = case.get_proof().unwrap();

    ctx.succinct_verifier_parameters
        .as_mut()
        .map(|p| p.inner_control_root = Some(risc0_verifier::Digest::ZERO));

    let res = proof.verify_with_context(&ctx, case.vk, case.journal.digest());

    assert!(res.is_err());
    assert!(
        matches!(res, Err(VerificationError::ControlVerificationError { .. })),
        "Invalid err {res:?}"
    );
}

#[rstest_reuse::apply(succinct)]
fn fails_on_invalid_succinct_claim<SC: CircuitCoreDef, RC: CircuitCoreDef>(
    #[case] ctx: VerifierContext<SC, RC>,
    #[case] path: &str,
) {
    let case: Case = read_all(path).unwrap();
    let mut proof = case.get_proof().unwrap();

    proof.inner.mut_succinct().unwrap().claim = MaybePruned::Pruned(risc0_verifier::Digest::ZERO);

    let res = proof.verify_with_context(&ctx, case.vk, case.journal.digest());

    assert!(res.is_err());
    assert!(
        matches!(res, Err(VerificationError::JournalDigestMismatch { .. })),
        "Invalid err {res:?}"
    );
}

#[rstest_reuse::template]
#[rstest]
#[case::poseidon_proof_v1_0(
    VerifierContext::v1_0(),
    "./resources/cases/prover_1.0.3/vm_1.0.5/poseidon2_22.json"
)]
#[case::sha_proof_v1_0(
    VerifierContext::v1_0(),
    "./resources/cases/prover_1.0.3/vm_1.0.5/sha_22.json"
)]
#[case::poseidon_proof_v1_1(
    VerifierContext::v1_1(),
    "./resources/cases/prover_1.1.3/vm_1.1.3/poseidon2_22.json"
)]
#[case::sha_proof_v1_1(
    VerifierContext::v1_1(),
    "./resources/cases/prover_1.1.3/vm_1.1.3/sha_22.json"
)]
#[case::poseidon_proof_v1_2(
    VerifierContext::v1_2(),
    "./resources/cases/prover_1.2.0/vm_1.2.0/poseidon2_22.json"
)]
#[case::sha_proof_v1_2(
    VerifierContext::v1_2(),
    "./resources/cases/prover_1.2.0/vm_1.2.0/sha_22.json"
)]
fn segments(#[case] ctx: VerifierContext<SC, RC>, #[case] path: &str) {}

#[rstest_reuse::template]
#[rstest]
#[case::succinct_proof_v1_0(
    VerifierContext::v1_0(),
    "./resources/cases/prover_1.0.3/vm_1.0.5/succinct_22.json"
)]
#[case::succinct_proof_v1_1(
    VerifierContext::v1_1(),
    "./resources/cases/prover_1.1.3/vm_1.1.3/succinct_22.json"
)]
#[case::succinct_proof_v1_2(
    VerifierContext::v1_2(),
    "./resources/cases/prover_1.2.0/vm_1.2.0/succinct_22.json"
)]
fn succinct(#[case] ctx: VerifierContext<SC, RC>, #[case] path: &str) {}

#[rstest_reuse::template]
#[rstest]
#[case::poseidon_proof_v1_0(
    VerifierContext::v1_0(),
    "./resources/cases/prover_1.0.3/vm_1.0.5/poseidon2_22.json"
)]
#[case::sha_proof_v1_0(
    VerifierContext::v1_0(),
    "./resources/cases/prover_1.0.3/vm_1.0.5/sha_22.json"
)]
#[case::poseidon_proof_v1_1(
    VerifierContext::v1_1(),
    "./resources/cases/prover_1.1.3/vm_1.1.3/poseidon2_22.json"
)]
#[case::sha_proof_v1_1(
    VerifierContext::v1_1(),
    "./resources/cases/prover_1.1.3/vm_1.1.3/sha_22.json"
)]
#[case::poseidon_proof_v1_2(
    VerifierContext::v1_2(),
    "./resources/cases/prover_1.2.0/vm_1.2.0/poseidon2_22.json"
)]
#[case::sha_proof_v1_2(
    VerifierContext::v1_2(),
    "./resources/cases/prover_1.2.0/vm_1.2.0/sha_22.json"
)]
#[case::succinct_proof_v1_0(
    VerifierContext::v1_0(),
    "./resources/cases/prover_1.0.3/vm_1.0.5/succinct_22.json"
)]
#[case::succinct_proof_v1_1(
    VerifierContext::v1_1(),
    "./resources/cases/prover_1.1.3/vm_1.1.3/succinct_22.json"
)]
#[case::succinct_proof_v1_2(
    VerifierContext::v1_2(),
    "./resources/cases/prover_1.2.0/vm_1.2.0/succinct_22.json"
)]
fn all(#[case] ctx: VerifierContext<SC, RC>, #[case] path: &str) {}

fn read_all<T: DeserializeOwned>(path: impl AsRef<Path>) -> anyhow::Result<T> {
    let file = File::open(path.as_ref())?;
    let buf_reader = BufReader::new(file);
    let result: T = serde_json::from_reader(buf_reader)?;
    Ok(result)
}

fn read_bin_all<T: DeserializeOwned>(path: impl AsRef<Path>) -> anyhow::Result<T> {
    let file = File::open(path.as_ref())?;
    let buf_reader = BufReader::new(file);
    ciborium::from_reader(buf_reader).map_err(Into::into)
}

#[derive(Serialize, Deserialize)]
struct Case {
    receipt_path: PathBuf,
    journal: Journal,
    vk: Vk,
}

impl Case {
    fn get_proof(&self) -> anyhow::Result<Proof> {
        match self.receipt_path.extension() {
            Some(ext) if ext == "json" => read_all(&self.receipt_path),
            Some(ext) if ext == "bin" => read_bin_all(&self.receipt_path),
            _ => Err(anyhow::anyhow!(
                "Unsupported file extension: {:?}",
                self.receipt_path.extension()
            )),
        }
    }
}

trait ExInnerReceipt {
    fn mut_composite(&mut self) -> Result<&mut CompositeReceipt, VerificationError>;

    fn mut_succinct(&mut self) -> Result<&mut SuccinctReceipt<ReceiptClaim>, VerificationError>;
}

impl ExInnerReceipt for risc0_verifier::InnerReceipt {
    fn mut_composite(&mut self) -> Result<&mut CompositeReceipt, VerificationError> {
        if let Self::Composite(x) = self {
            Ok(x)
        } else {
            Err(VerificationError::ReceiptFormatError)
        }
    }

    fn mut_succinct(&mut self) -> Result<&mut SuccinctReceipt<ReceiptClaim>, VerificationError> {
        if let Self::Succinct(x) = self {
            Ok(x)
        } else {
            Err(VerificationError::ReceiptFormatError)
        }
    }
}

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

use risc0_verifier::{
    v1_0, v1_1, v1_2, v2_0, v2_1, v2_2, verify, CompositeReceipt, Journal, Proof, SegmentInfo,
    SuccinctReceipt, Verifier, Vk,
};
use risc0_zkp_v1::verify::VerificationError;
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

        let verifier = v1_0();
        let proof = Proof::new(inner_receipt);
        verifier.verify(vk.into(), proof, journal).unwrap()
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

        let proof = hex::decode(proof).unwrap();
        let pubs = hex::decode(pubs).unwrap();

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

#[rstest]
#[case::v1(v1_0(), "./resources/cases/prover_1.0.3/vm_1.1.3/sha_16.json")]
#[case::v2(v2_1(), "./resources/cases/prover_2.1.0/vm_2.1.0/poseidon2_16.json")]
fn verify_valid_proof(#[case] verifier: impl Verifier, #[case] path: &str) {
    let case: Case = read_all(path).unwrap();

    let proof = case.get_proof().unwrap();

    verify(&verifier, case.vk, proof, case.journal).unwrap()
}

#[rstest]
#[case::v1(v1_0().boxed(), "./resources/cases/prover_1.0.3/vm_1.1.3/sha_16.json")]
#[case::v2(v2_1().boxed(), "./resources/cases/prover_2.1.0/vm_2.1.0/poseidon2_16.json")]
fn verify_valid_proof_dynamic(#[case] verifier: Box<dyn Verifier>, #[case] path: &str) {
    let case: Case = read_all(path).unwrap();

    let proof = case.get_proof().unwrap();

    verifier
        .verify(case.vk.into(), proof, case.journal)
        .unwrap()
}

#[rstest]
fn read_po2_segment_v1(
    #[values(v1_0(), v1_1(), v1_2())] verifier: impl Verifier,
    #[values(16, 17, 18, 19, 20, 21)] expected_po2: u32,
    #[values("sha-256", "poseidon2")] hash: &str,
) {
    let case: Case = read_all(format!(
        "./resources/cases/single_full_segment_v1/{hash}_{expected_po2}.json"
    ))
    .unwrap();
    let proof = case.get_proof().unwrap();

    let po2s = verifier
        .extract_composite_segments_info(proof.inner.composite().unwrap())
        .unwrap();

    assert_eq!(vec![SegmentInfo::new(hash.to_owned(), expected_po2)], po2s)
}

#[rstest]
fn read_po2_segment_v2(
    #[values(v2_1())] verifier: impl Verifier,
    #[values(16, 17, 18, 19, 20, 21, 22)] expected_po2: u32,
    #[values("poseidon2")] hash: &str,
) {
    let case: Case = read_all(format!(
        "./resources/cases/single_full_segment_v2/{hash}_{expected_po2}.json"
    ))
    .unwrap();
    let proof = case.get_proof().unwrap();

    let po2s = verifier
        .extract_composite_segments_info(proof.inner.composite().unwrap())
        .unwrap();

    assert_eq!(vec![SegmentInfo::new(hash.to_owned(), expected_po2)], po2s)
}

#[rstest]
#[case(v1_0(), "./resources/cases/prover_1.0.3/vm_1.0.5/sha_22.json", ("sha-256", [20,20,17].as_slice()))]
#[case(v1_1(), "./resources/cases/prover_1.1.3/vm_1.1.1/sha_22.json", ("sha-256", [20,20,17].as_slice()))]
#[case(v1_2(), "./resources/cases/prover_1.2.0/vm_1.2.0/sha_22.json", ("sha-256", [20,20,17].as_slice()))]
#[case(v2_1(), "./resources/cases/prover_2.1.0/vm_2.1.0/poseidon2_16.json", ("poseidon2", [16].as_slice()))]
#[case(v2_1(), "./resources/cases/prover_2.1.0/vm_2.1.0/poseidon2_22.json", ("poseidon2", [20,20,20,20].as_slice()))]
fn read_po2_segments(
    #[case] verifier: impl Verifier,
    #[case] path: &str,
    #[case] expected: (&str, &[u32]),
) {
    let case: Case = read_all(path).unwrap();
    let proof = case.get_proof().unwrap();

    let po2s = verifier
        .extract_composite_segments_info(proof.inner.composite().unwrap())
        .unwrap();

    let expected = expected
        .1
        .iter()
        .map(|&po2| SegmentInfo::new(expected.0.to_owned(), po2))
        .collect::<Vec<_>>();

    assert_eq!(expected, po2s)
}

#[rstest]
#[case(v1_2(), "./resources/cases/poseidon2_22_segment_20.json")]
#[case(v2_1(), "./resources/cases/prover_2.1.0/vm_2.1.0/poseidon2_22.json")]
fn read_po2_segments_case_limit_segments(#[case] verifier: impl Verifier, #[case] path: &str) {
    let case: Case = read_all(path).unwrap();
    let proof = case.get_proof().unwrap();

    let po2s = verifier
        .extract_composite_segments_info(proof.inner.composite().unwrap())
        .unwrap();

    let expected = (0..4)
        .map(|_| SegmentInfo::new("poseidon2".to_owned(), 20))
        .collect::<Vec<_>>();
    assert_eq!(expected, po2s)
}

mod v1_0 {
    use super::*;

    #[rstest]
    #[case::should_pass(v1_0())]
    #[should_panic(expected = "control_id mismatch")]
    #[case::should_fails_with_new_verifier(v1_1())]
    fn verify_valid_proof(
        #[case] verifier: impl Verifier,
        #[files("./resources/cases/prover_1.0.*/**/*.json")] path: PathBuf,
    ) {
        let case: Case = read_all(path).unwrap();

        let proof = case.get_proof().unwrap();

        verifier
            .verify(case.vk.into(), proof, case.journal)
            .unwrap()
    }
}

mod v1_1 {
    use super::*;

    #[rstest]
    #[case::should_pass(v1_1())]
    #[should_panic(expected = "control_id mismatch")]
    #[case::should_fails_with_old_verifier(v1_0())]
    fn verify_valid_proof(
        #[case] verifier: impl Verifier,
        #[files("./resources/cases/prover_1.1.*/**/*.json")] path: PathBuf,
    ) {
        let case: Case = read_all(path).unwrap();

        let proof = case.get_proof().unwrap();

        verifier
            .verify(case.vk.into(), proof, case.journal)
            .unwrap()
    }
}

mod v1_2 {
    use super::*;

    #[rstest]
    #[case::should_pass(v1_2())]
    #[should_panic(expected = "control_id mismatch")]
    #[case::should_fails_with_old_verifier(v1_0())]
    fn verify_valid_proof(
        #[case] verifier: impl Verifier,
        #[files("./resources/cases/prover_1.2.*/**/*.json")] path: PathBuf,
    ) {
        let case: Case = read_all(path).unwrap();

        let proof = case.get_proof().unwrap();

        verifier
            .verify(case.vk.into(), proof, case.journal)
            .unwrap()
    }
}

mod v2_0 {
    use super::*;

    #[rstest]
    #[case::should_pass(v2_0())]
    #[should_panic]
    #[case::should_fails_with_old_verifier(v1_2().boxed())]
    fn verify_valid_proof(
        #[case] verifier: impl Verifier,
        #[files("./resources/cases/prover_2.0.*/**/*.json")] path: PathBuf,
    ) {
        let case: Case = read_all(path).unwrap();

        let proof = case.get_proof().unwrap();

        verifier
            .verify(case.vk.into(), proof, case.journal)
            .unwrap()
    }

    #[test]
    #[should_panic(expected = "invalid receipt format")]
    fn should_reject_sha2_proofs() {
        let verifier = v2_0();
        let case: Case =
            read_all("./resources/cases/reject/prover_2.0.0/vm_2.0.0/sha_16.json").unwrap();
        let proof = case.get_proof().unwrap();

        verifier
            .verify(case.vk.into(), proof, case.journal)
            .unwrap()
    }
}

mod v2_1 {
    use super::*;

    #[rstest]
    #[case::should_pass(v2_1())]
    #[should_panic]
    #[case::should_fails_with_old_verifier(v1_2().boxed())]
    fn verify_valid_proof(
        #[case] verifier: impl Verifier,
        #[files("./resources/cases/prover_2.1.*/**/*.json")] path: PathBuf,
    ) {
        let case: Case = read_all(path).unwrap();

        let proof = case.get_proof().unwrap();

        verifier
            .verify(case.vk.into(), proof, case.journal)
            .unwrap()
    }
}

mod v2_2 {
    use super::*;

    #[rstest]
    #[case::should_pass(v2_2())]
    #[should_panic]
    #[case::should_fails_with_old_verifier(v2_1().boxed())]
    fn verify_valid_proof(
        #[case] verifier: impl Verifier,
        #[files("./resources/cases/prover_2.2.*/**/*.json")] path: PathBuf,
    ) {
        let case: Case = read_all(path).unwrap();

        let proof = case.get_proof().unwrap();

        verifier
            .verify(case.vk.into(), proof, case.journal)
            .unwrap()
    }
}

mod use_custom_local_implemented_hash_function {
    use super::*;

    use risc0_verifier::poseidon2_injection::{
        poseidon2_mix, BabyBearElem, Poseidon2Mix, POSEIDON2_CELLS,
    };

    pub struct LocPoseidon2;

    impl Poseidon2Mix for LocPoseidon2 {
        #[inline]
        fn poseidon2_mix(&self, cells: &mut [BabyBearElem; POSEIDON2_CELLS]) {
            poseidon2_mix(cells);
        }
    }

    pub struct FakePoseidon2;

    impl Poseidon2Mix for FakePoseidon2 {
        #[inline]
        fn poseidon2_mix(&self, _cells: &mut [BabyBearElem; POSEIDON2_CELLS]) {}
    }

    #[rstest]
    #[case::v1(
        v1_2(),
        "./resources/cases/prover_1.2.0/vm_1.2.0/poseidon2_22.json",
        LocPoseidon2
    )]
    #[case::v1_succinct(
        v1_2(),
        "./resources/cases/prover_1.2.0/vm_1.2.0/succinct_22.json",
        LocPoseidon2
    )]
    #[should_panic(expected = "invalid")]
    #[case::v1_with_fake(
        v1_2(),
        "./resources/cases/prover_1.2.0/vm_1.2.0/poseidon2_22.json",
        FakePoseidon2
    )]
    #[should_panic(expected = "invalid")]
    #[case::v1_succinct_with_fake(
        v1_2(),
        "./resources/cases/prover_1.2.0/vm_1.2.0/succinct_22.json",
        FakePoseidon2
    )]
    #[case::v2(
        v2_1(),
        "./resources/cases/prover_2.1.0/vm_2.1.0/poseidon2_22.json",
        LocPoseidon2
    )]
    #[case::v2_succinct(
        v2_1(),
        "./resources/cases/prover_2.1.0/vm_2.1.0/succinct_22.json",
        LocPoseidon2
    )]
    #[should_panic(expected = "invalid")]
    #[case::v2_with_fake(
        v2_1(),
        "./resources/cases/prover_2.1.0/vm_2.1.0/poseidon2_22.json",
        FakePoseidon2
    )]
    #[should_panic(expected = "invalid")]
    #[case::v2_succinct_with_fake(
        v2_1(),
        "./resources/cases/prover_2.1.0/vm_2.1.0/succinct_22.json",
        FakePoseidon2
    )]
    fn should_poseidon2_injected(
        #[case] mut verifier: impl Verifier,
        #[case] path: &str,
        #[case] hash: impl Poseidon2Mix + Send + Sync + 'static,
    ) {
        verifier.set_poseidon2_mix_impl(Box::new(hash));

        let case: Case = read_all(path).unwrap();

        let proof = case.get_proof().unwrap();

        verifier
            .verify(case.vk.into(), proof, case.journal)
            .unwrap()
    }
}

#[rstest_reuse::apply(segments)]
fn fails_on_invalid_segment(
    #[case] verifier: impl Verifier,
    #[case] path: &str,
    #[values(0, 1, 2)] segment: usize,
) {
    let case: Case = read_all(path).unwrap();
    let mut proof = case.get_proof().unwrap();

    let seal = proof.inner.mut_composite().unwrap().segments[segment]
        .seal
        .as_mut_slice();

    seal[seal.len() / 2] = seal[seal.len() / 2].wrapping_add(1);

    let res = verifier.verify(case.vk.into(), proof, case.journal);

    assert!(res.is_err());
    assert!(matches!(res, Err(VerificationError::InvalidProof)));
}

#[rstest_reuse::apply(succinct)]
fn fails_on_invalid_succinct(#[case] verifier: impl Verifier, #[case] path: &str) {
    let case: Case = read_all(path).unwrap();
    let mut proof = case.get_proof().unwrap();

    let seal = proof.inner.mut_succinct().unwrap().seal.as_mut_slice();

    seal[seal.len() / 2] = seal[seal.len() / 2].wrapping_add(1);

    let res = verifier.verify(case.vk.into(), proof, case.journal);

    assert!(res.is_err());
    assert!(matches!(res, Err(VerificationError::InvalidProof)));
}

#[rstest_reuse::apply(all)]
fn fails_on_invalid_vk(#[case] verifier: impl Verifier, #[case] path: &str) {
    let mut case: Case = read_all(path).unwrap();
    let proof = case.get_proof().unwrap();

    if let Some(l) = case.vk.0.as_mut_words().last_mut() {
        *l = l.wrapping_add(1);
    }

    let res = verifier.verify(case.vk.into(), proof, case.journal);

    assert!(res.is_err());
    assert!(
        matches!(res, Err(VerificationError::ClaimDigestMismatch { .. })),
        "Invalid err {res:?}"
    );
}

#[rstest_reuse::apply(all)]
fn fails_on_invalid_pubs(#[case] verifier: impl Verifier, #[case] path: &str) {
    let mut case: Case = read_all(path).unwrap();
    let proof = case.get_proof().unwrap();

    if let Some(l) = case.journal.bytes.last_mut() {
        *l = l.wrapping_add(1);
    }

    let res = verifier.verify(case.vk.into(), proof, case.journal);

    assert!(res.is_err());
    assert!(
        matches!(res, Err(VerificationError::ClaimDigestMismatch { .. })),
        "Invalid err {res:?}"
    );
}

#[rstest_reuse::apply(segments)]
fn fails_on_invalid_claim(#[case] verifier: impl Verifier, #[case] path: &str) {
    let case: Case = read_all(path).unwrap();
    let mut proof = case.get_proof().unwrap();

    proof.inner.mut_composite().unwrap().segments[0]
        .claim
        .exit_code = risc0_binfmt_v1::ExitCode::Halted(0);

    let res = verifier.verify(case.vk.into(), proof, case.journal);

    assert!(res.is_err());
    assert!(
        matches!(res, Err(VerificationError::ClaimDigestMismatch { .. })),
        "Invalid err {res:?}"
    );
}

#[rstest_reuse::apply(succinct)]
fn fails_on_invalid_inner_control_root(#[case] mut verifier: impl Verifier, #[case] path: &str) {
    let case: Case = read_all(path).unwrap();
    let proof = case.get_proof().unwrap();

    if let Some(p) = verifier.mut_succinct_verifier_parameters() {
        p.inner_control_root = Some(risc0_verifier::Digest::ZERO);
    }

    let res = verifier.verify(case.vk.into(), proof, case.journal);

    assert!(res.is_err());
    assert!(
        matches!(res, Err(VerificationError::ControlVerificationError { .. })),
        "Invalid err {res:?}"
    );
}

#[rstest_reuse::apply(succinct)]
fn fails_on_invalid_succinct_claim(#[case] verifier: impl Verifier, #[case] path: &str) {
    let case: Case = read_all(path).unwrap();
    let mut proof = case.get_proof().unwrap();

    proof.inner.mut_succinct().unwrap().claim =
        risc0_verifier::receipt_claim::MaybePruned::Pruned(risc0_verifier::Digest::ZERO);

    let res = verifier.verify(case.vk.into(), proof, case.journal);

    assert!(res.is_err());
    assert!(
        matches!(res, Err(VerificationError::JournalDigestMismatch)),
        "Invalid err {res:?}"
    );
}

#[rstest_reuse::template]
#[rstest]
#[case::poseidon_proof_v1_0(v1_0(), "./resources/cases/prover_1.0.3/vm_1.0.5/poseidon2_22.json")]
#[case::sha_proof_v1_0(v1_0(), "./resources/cases/prover_1.0.3/vm_1.0.5/sha_22.json")]
#[case::poseidon_proof_v1_1(v1_1(), "./resources/cases/prover_1.1.3/vm_1.1.3/poseidon2_22.json")]
#[case::sha_proof_v1_1(v1_1(), "./resources/cases/prover_1.1.3/vm_1.1.3/sha_22.json")]
#[case::poseidon_proof_v1_2(v1_2(), "./resources/cases/prover_1.2.0/vm_1.2.0/poseidon2_22.json")]
#[case::sha_proof_v1_2(v1_2(), "./resources/cases/prover_1.2.0/vm_1.2.0/sha_22.json")]
#[case::poseidon_proof_v2_1(v2_1(), "./resources/cases/prover_2.1.0/vm_2.1.0/poseidon2_22.json")]
#[case::poseidon_proof_v2_2(v2_2(), "./resources/cases/prover_2.2.0/vm_2.2.0/poseidon2_22.json")]
fn segments(#[case] verifier: impl Verifier, #[case] path: &str) {}

#[rstest_reuse::template]
#[rstest]
#[case::succinct_proof_v1_0(v1_0(), "./resources/cases/prover_1.0.3/vm_1.0.5/succinct_22.json")]
#[case::succinct_proof_v1_1(v1_1(), "./resources/cases/prover_1.1.3/vm_1.1.3/succinct_22.json")]
#[case::succinct_proof_v1_2(v1_2(), "./resources/cases/prover_1.2.0/vm_1.2.0/succinct_22.json")]
#[case::succinct_proof_v2_1(v2_1(), "./resources/cases/prover_2.1.0/vm_2.1.0/succinct_22.json")]
#[case::succinct_proof_v2_2(v2_2(), "./resources/cases/prover_2.2.0/vm_2.2.0/succinct_22.json")]
fn succinct(#[case] verifier: impl Verifier, #[case] path: &str) {}

#[rstest_reuse::template]
#[rstest]
#[case::poseidon_proof_v1_0(v1_0(), "./resources/cases/prover_1.0.3/vm_1.0.5/poseidon2_22.json")]
#[case::sha_proof_v1_0(v1_0(), "./resources/cases/prover_1.0.3/vm_1.0.5/sha_22.json")]
#[case::poseidon_proof_v1_1(v1_1(), "./resources/cases/prover_1.1.3/vm_1.1.3/poseidon2_22.json")]
#[case::sha_proof_v1_1(v1_1(), "./resources/cases/prover_1.1.3/vm_1.1.3/sha_22.json")]
#[case::poseidon_proof_v1_2(v1_2(), "./resources/cases/prover_1.2.0/vm_1.2.0/poseidon2_22.json")]
#[case::sha_proof_v1_2(v1_2(), "./resources/cases/prover_1.2.0/vm_1.2.0/sha_22.json")]
#[case::poseidon_proof_v2_1(v2_1(), "./resources/cases/prover_2.1.0/vm_2.1.0/poseidon2_22.json")]
#[case::poseidon_proof_v2_2(v2_2(), "./resources/cases/prover_2.2.0/vm_2.2.0/poseidon2_22.json")]
#[case::succinct_proof_v1_0(v1_0(), "./resources/cases/prover_1.0.3/vm_1.0.5/succinct_22.json")]
#[case::succinct_proof_v1_1(v1_1(), "./resources/cases/prover_1.1.3/vm_1.1.3/succinct_22.json")]
#[case::succinct_proof_v1_2(v1_2(), "./resources/cases/prover_1.2.0/vm_1.2.0/succinct_22.json")]
#[case::succinct_proof_v2_1(v2_1(), "./resources/cases/prover_2.1.0/vm_2.1.0/succinct_22.json")]
#[case::succinct_proof_v2_2(v2_2(), "./resources/cases/prover_2.2.0/vm_2.2.0/succinct_22.json")]
fn all(#[case] verifier: impl Verifier, #[case] path: &str) {}

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

    fn mut_succinct(
        &mut self,
    ) -> Result<&mut SuccinctReceipt<risc0_verifier::receipt_claim::ReceiptClaim>, VerificationError>;
}

impl ExInnerReceipt for risc0_verifier::InnerReceipt {
    fn mut_composite(&mut self) -> Result<&mut CompositeReceipt, VerificationError> {
        if let Self::Composite(x) = self {
            Ok(x)
        } else {
            Err(VerificationError::ReceiptFormatError)
        }
    }

    fn mut_succinct(
        &mut self,
    ) -> Result<&mut SuccinctReceipt<risc0_verifier::receipt_claim::ReceiptClaim>, VerificationError>
    {
        if let Self::Succinct(x) = self {
            Ok(x)
        } else {
            Err(VerificationError::ReceiptFormatError)
        }
    }
}

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

fn main() {
    // Run registered benchmarks.
    divan::main();
}

use risc0_verifier::{Digestible as _, VerifierContext};

use utils::*;

mod utils;

pub mod sha {
    use super::*;

    #[divan::bench]
    fn verify_1_2_0_16() {
        let ctx = VerifierContext::v1_2();
        let case: Case = read_json("resources/cases/prover_1.2.0/vm_1.2.0/sha_16.json").unwrap();
        let proof = read_bin(case.receipt_path).unwrap();

        compute(
            divan::black_box(&ctx),
            divan::black_box(&proof),
            divan::black_box(case.vk),
            divan::black_box(case.journal.digest()),
        )
    }

    #[divan::bench]
    fn verify_1_2_0_22() {
        let ctx = VerifierContext::v1_2();
        let case: Case = read_json("resources/cases/prover_1.2.0/vm_1.2.0/sha_22.json").unwrap();
        let proof = read_bin(case.receipt_path).unwrap();

        compute(
            divan::black_box(&ctx),
            divan::black_box(&proof),
            divan::black_box(case.vk),
            divan::black_box(case.journal.digest()),
        )
    }

    mod single_full_segment {
        use super::*;

        fn path(po2: u32) -> String {
            format!("resources/cases/single_full_segment/sha_{po2}.json")
        }

        #[divan::bench]
        fn verify_1_2_0_16() {
            let ctx = VerifierContext::v1_2();
            let case: Case = read_json(path(16)).unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&ctx),
                divan::black_box(&proof),
                divan::black_box(case.vk),
                divan::black_box(case.journal.digest()),
            )
        }

        #[divan::bench]
        fn verify_1_2_0_17() {
            let ctx = VerifierContext::v1_2();
            let case: Case = read_json(path(17)).unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&ctx),
                divan::black_box(&proof),
                divan::black_box(case.vk),
                divan::black_box(case.journal.digest()),
            )
        }

        #[divan::bench]
        fn verify_1_2_0_18() {
            let ctx = VerifierContext::v1_2();
            let case: Case = read_json(path(18)).unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&ctx),
                divan::black_box(&proof),
                divan::black_box(case.vk),
                divan::black_box(case.journal.digest()),
            )
        }

        #[divan::bench]
        fn verify_1_2_0_19() {
            let ctx = VerifierContext::v1_2();
            let case: Case = read_json(path(19)).unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&ctx),
                divan::black_box(&proof),
                divan::black_box(case.vk),
                divan::black_box(case.journal.digest()),
            )
        }

        #[divan::bench]
        fn verify_1_2_0_20() {
            let ctx = VerifierContext::v1_2();
            let case: Case = read_json(path(20)).unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&ctx),
                divan::black_box(&proof),
                divan::black_box(case.vk),
                divan::black_box(case.journal.digest()),
            )
        }

        #[divan::bench]
        fn verify_1_2_0_21() {
            let ctx = VerifierContext::v1_2();
            let case: Case = read_json(path(21)).unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&ctx),
                divan::black_box(&proof),
                divan::black_box(case.vk),
                divan::black_box(case.journal.digest()),
            )
        }
    }
}

pub mod poseidon2 {
    use super::*;

    #[divan::bench]
    fn verify_1_2_0_16() {
        let ctx = VerifierContext::v1_2();
        let case: Case =
            read_json("resources/cases/prover_1.2.0/vm_1.2.0/poseidon2_16.json").unwrap();
        let proof = read_bin(case.receipt_path).unwrap();

        compute(
            divan::black_box(&ctx),
            divan::black_box(&proof),
            divan::black_box(case.vk),
            divan::black_box(case.journal.digest()),
        )
    }

    #[divan::bench]
    fn verify_1_2_0_22() {
        let ctx = VerifierContext::v1_2();
        let case: Case =
            read_json("resources/cases/prover_1.2.0/vm_1.2.0/poseidon2_22.json").unwrap();
        let proof = read_bin(case.receipt_path).unwrap();

        compute(
            divan::black_box(&ctx),
            divan::black_box(&proof),
            divan::black_box(case.vk),
            divan::black_box(case.journal.digest()),
        )
    }

    mod single_full_segment {
        use super::*;

        fn path(po2: u32) -> String {
            format!("resources/cases/single_full_segment/poseidon2_{po2}.json")
        }

        #[divan::bench]
        fn verify_1_2_0_16() {
            let ctx = VerifierContext::v1_2();
            let case: Case = read_json(path(16)).unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&ctx),
                divan::black_box(&proof),
                divan::black_box(case.vk),
                divan::black_box(case.journal.digest()),
            )
        }

        #[divan::bench]
        fn verify_1_2_0_17() {
            let ctx = VerifierContext::v1_2();
            let case: Case = read_json(path(17)).unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&ctx),
                divan::black_box(&proof),
                divan::black_box(case.vk),
                divan::black_box(case.journal.digest()),
            )
        }

        #[divan::bench]
        fn verify_1_2_0_18() {
            let ctx = VerifierContext::v1_2();
            let case: Case = read_json(path(18)).unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&ctx),
                divan::black_box(&proof),
                divan::black_box(case.vk),
                divan::black_box(case.journal.digest()),
            )
        }

        #[divan::bench]
        fn verify_1_2_0_19() {
            let ctx = VerifierContext::v1_2();
            let case: Case = read_json(path(19)).unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&ctx),
                divan::black_box(&proof),
                divan::black_box(case.vk),
                divan::black_box(case.journal.digest()),
            )
        }

        #[divan::bench]
        fn verify_1_2_0_20() {
            let ctx = VerifierContext::v1_2();
            let case: Case = read_json(path(20)).unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&ctx),
                divan::black_box(&proof),
                divan::black_box(case.vk),
                divan::black_box(case.journal.digest()),
            )
        }

        #[divan::bench]
        fn verify_1_2_0_21() {
            let ctx = VerifierContext::v1_2();
            let case: Case = read_json(path(21)).unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&ctx),
                divan::black_box(&proof),
                divan::black_box(case.vk),
                divan::black_box(case.journal.digest()),
            )
        }
    }
}

pub mod succinct {
    use super::*;

    #[divan::bench]
    fn verify_1_2_0_16() {
        let ctx = VerifierContext::v1_2();
        let case: Case =
            read_json("resources/cases/prover_1.2.0/vm_1.2.0/succinct_16.json").unwrap();
        let proof = read_bin(case.receipt_path).unwrap();

        compute(
            divan::black_box(&ctx),
            divan::black_box(&proof),
            divan::black_box(case.vk),
            divan::black_box(case.journal.digest()),
        )
    }

    #[divan::bench]
    fn verify_1_2_0_22() {
        let ctx = VerifierContext::v1_2();
        let case: Case =
            read_json("resources/cases/prover_1.2.0/vm_1.2.0/succinct_22.json").unwrap();
        let proof = read_bin(case.receipt_path).unwrap();

        compute(
            divan::black_box(&ctx),
            divan::black_box(&proof),
            divan::black_box(case.vk),
            divan::black_box(case.journal.digest()),
        )
    }
}

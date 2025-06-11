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

use risc0_verifier::{v1_2, v2_1, Verifier};
use utils::*;

mod utils;

pub mod sha {
    use super::*;

    mod v_1_2 {
        use super::*;

        fn verifier() -> impl Verifier {
            v1_2()
        }

        #[divan::bench]
        fn verify_16() {
            let verifier = verifier();
            let case: Case =
                read_json("resources/cases/prover_1.2.0/vm_1.2.0/sha_16.json").unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&verifier),
                divan::black_box(proof),
                divan::black_box(case.vk.into()),
                divan::black_box(case.journal),
            )
        }

        #[divan::bench]
        fn verify_1_2_0_22() {
            let verifier = verifier();
            let case: Case =
                read_json("resources/cases/prover_1.2.0/vm_1.2.0/sha_22.json").unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&verifier),
                divan::black_box(proof),
                divan::black_box(case.vk.into()),
                divan::black_box(case.journal),
            )
        }

        mod single_full_segment {
            use super::*;

            fn path(po2: u32) -> String {
                format!("resources/cases/single_full_segment_v1/sha-256_{po2}.json")
            }

            #[divan::bench]
            fn verify_1_2_0_16() {
                let verifier = verifier();
                let case: Case = read_json(path(16)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_1_2_0_17() {
                let verifier = verifier();
                let case: Case = read_json(path(17)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_1_2_0_18() {
                let verifier = verifier();
                let case: Case = read_json(path(18)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_1_2_0_19() {
                let verifier = verifier();
                let case: Case = read_json(path(19)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_1_2_0_20() {
                let verifier = verifier();
                let case: Case = read_json(path(20)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_1_2_0_21() {
                let verifier = verifier();
                let case: Case = read_json(path(21)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }
        }
    }
}

#[divan::bench]
fn case_limit() {
    let verifier = v1_2();
    let case: Case = read_json("resources/cases/poseidon2_22_segment_20.json").unwrap();
    let proof = read_bin(case.receipt_path).unwrap();

    compute(
        divan::black_box(&verifier),
        divan::black_box(proof),
        divan::black_box(case.vk.into()),
        divan::black_box(case.journal),
    )
}

pub mod poseidon2 {
    use super::*;

    mod v_1_2 {
        use super::*;

        fn verifier() -> impl Verifier {
            v1_2()
        }

        #[divan::bench]
        fn verify_16() {
            let verifier = verifier();
            let case: Case =
                read_json("resources/cases/prover_1.2.0/vm_1.2.0/poseidon2_16.json").unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&verifier),
                divan::black_box(proof),
                divan::black_box(case.vk.into()),
                divan::black_box(case.journal),
            )
        }

        #[divan::bench]
        fn verify_22() {
            let verifier = verifier();
            let case: Case =
                read_json("resources/cases/prover_1.2.0/vm_1.2.0/poseidon2_22.json").unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&verifier),
                divan::black_box(proof),
                divan::black_box(case.vk.into()),
                divan::black_box(case.journal),
            )
        }

        mod single_full_segment {
            use super::*;

            fn path(po2: u32) -> String {
                format!("resources/cases/single_full_segment_v1/poseidon2_{po2}.json")
            }

            #[divan::bench]
            fn verify_16() {
                let verifier = verifier();
                let case: Case = read_json(path(16)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_17() {
                let verifier = verifier();
                let case: Case = read_json(path(17)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_18() {
                let verifier = verifier();
                let case: Case = read_json(path(18)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_19() {
                let verifier = verifier();
                let case: Case = read_json(path(19)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_20() {
                let verifier = verifier();
                let case: Case = read_json(path(20)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_21() {
                let verifier = verifier();
                let case: Case = read_json(path(21)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }
        }
    }

    mod v_2_1 {
        use super::*;

        fn verifier() -> impl Verifier {
            v2_1()
        }

        #[divan::bench]
        fn verify_16() {
            let verifier = verifier();
            let case: Case =
                read_json("resources/cases/prover_2.1.0/vm_2.1.0/poseidon2_16.json").unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&verifier),
                divan::black_box(proof),
                divan::black_box(case.vk.into()),
                divan::black_box(case.journal),
            )
        }

        #[divan::bench]
        fn verify_22() {
            let verifier = verifier();
            let case: Case =
                read_json("resources/cases/prover_2.1.0/vm_2.1.0/poseidon2_22.json").unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&verifier),
                divan::black_box(proof),
                divan::black_box(case.vk.into()),
                divan::black_box(case.journal),
            )
        }

        mod single_full_segment {
            use super::*;

            fn path(po2: u32) -> String {
                format!("resources/cases/single_full_segment_v2/poseidon2_{po2}.json")
            }

            #[divan::bench]
            fn verify_16() {
                let verifier = verifier();
                let case: Case = read_json(path(16)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_17() {
                let verifier = verifier();
                let case: Case = read_json(path(17)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_18() {
                let verifier = verifier();
                let case: Case = read_json(path(18)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_19() {
                let verifier = verifier();
                let case: Case = read_json(path(19)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_20() {
                let verifier = verifier();
                let case: Case = read_json(path(20)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }

            #[divan::bench]
            fn verify_21() {
                let verifier = verifier();
                let case: Case = read_json(path(21)).unwrap();
                let proof = read_bin(case.receipt_path).unwrap();

                compute(
                    divan::black_box(&verifier),
                    divan::black_box(proof),
                    divan::black_box(case.vk.into()),
                    divan::black_box(case.journal),
                )
            }
        }
    }
}

pub mod succinct {
    use super::*;

    mod v_1_2 {
        use super::*;

        fn verifier() -> impl Verifier {
            v1_2()
        }

        #[divan::bench]
        fn verify_16() {
            let verifier = verifier();
            let case: Case =
                read_json("resources/cases/prover_1.2.0/vm_1.2.0/succinct_16.json").unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&verifier),
                divan::black_box(proof),
                divan::black_box(case.vk.into()),
                divan::black_box(case.journal),
            )
        }

        #[divan::bench]
        fn verify_22() {
            let verifier = verifier();
            let case: Case =
                read_json("resources/cases/prover_1.2.0/vm_1.2.0/succinct_22.json").unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&verifier),
                divan::black_box(proof),
                divan::black_box(case.vk.into()),
                divan::black_box(case.journal),
            )
        }
    }

    mod v_2_1 {
        use super::*;

        fn verifier() -> impl Verifier {
            v2_1()
        }

        #[divan::bench]
        fn verify_16() {
            let verifier = verifier();
            let case: Case =
                read_json("resources/cases/prover_2.1.0/vm_2.1.0/succinct_16.json").unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&verifier),
                divan::black_box(proof),
                divan::black_box(case.vk.into()),
                divan::black_box(case.journal),
            )
        }

        #[divan::bench]
        fn verify_22() {
            let verifier = verifier();
            let case: Case =
                read_json("resources/cases/prover_2.1.0/vm_2.1.0/succinct_22.json").unwrap();
            let proof = read_bin(case.receipt_path).unwrap();

            compute(
                divan::black_box(&verifier),
                divan::black_box(proof),
                divan::black_box(case.vk.into()),
                divan::black_box(case.journal),
            )
        }
    }
}

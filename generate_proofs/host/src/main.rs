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

use std::path::{Path, PathBuf};

use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

        let powers = vec![16_u32, 22];
    let provers = [
        ("poseidon2", ProverOpts::default()),
        ("sha", ProverOpts::fast()),
        ("succinct", ProverOpts::succinct()),
    ];
    let versions = ["1.2.0", "1.1.3", "1.1.1", "1.0.5", "1.0.1"];
    let out = "output_1.1.3";

    for version in &versions[..1] {
        let method_elf = read_elf(format!("m{version}/method"));
        let method_id = read_method_id(format!("m{version}/info.txt"));
        println!("============= VERSION {version} =============");

        let outdir = PathBuf::from(out).join(version);

        std::fs::create_dir_all(&outdir).unwrap();

        let json_id = std::fs::File::create(outdir.join("id.json")).unwrap();
        serde_json::to_writer_pretty(json_id, &method_id).unwrap();

        for power in &powers[..] {
            for (prover_name, prover_opts) in &provers {
                println!("============= {prover_name} - {power} =============");
                let receipt = compute(&method_elf, prover_opts, *power);
                let output: u32 = receipt.journal.decode().unwrap();
                println!("============= output = {output} =============");
                if prover_opts.receipt_kind == risc0_zkvm::ReceiptKind::Composite {
                    let len = receipt.inner.composite().unwrap().segments.len();
                    println!("============= len = {len} =============");
                } else {
                    println!("============= succinct =============");
                }

                receipt.verify(method_id).unwrap();
                save(&outdir, prover_name, *power, receipt);
                println!("============= DONE =============");
            }
        }
    }
}

fn read_elf(path: impl AsRef<Path>) -> Vec<u8> {
    std::fs::read(path).expect("Failed to read ELF file")
}

fn read_method_id(path: impl AsRef<Path>) -> [u32; 8] {
    let body = std::fs::read_to_string(path).expect("Failed to read ELF file");
    let h = body.lines().nth(0).unwrap();
    hex::decode(h)
        .expect("Invalid method ID")
        .to_method_id_u32_format()
}

trait ToMethodIdU32Format {
    fn to_method_id_u32_format(&self) -> [u32; 8];
}

impl ToMethodIdU32Format for &[u8] {
    fn to_method_id_u32_format(&self) -> [u32; 8] {
        self.chunks_exact(4)
            .map(TryInto::try_into)
            .map(Result::unwrap)
            .map(u32::from_le_bytes)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

impl ToMethodIdU32Format for [u8; 32] {
    fn to_method_id_u32_format(&self) -> [u32; 8] {
        self.as_slice().to_method_id_u32_format()
    }
}

impl ToMethodIdU32Format for Vec<u8> {
    fn to_method_id_u32_format(&self) -> [u32; 8] {
        self.as_slice().to_method_id_u32_format()
    }
}

fn save(outdir: impl AsRef<Path>, prover_name: &str, power: u32, receipt: Receipt) {
    let journal = std::fs::File::create(
        outdir
            .as_ref()
            .join(format!("journal_{prover_name}_{power}.json")),
    )
    .unwrap();
    serde_json::to_writer_pretty(journal, &receipt.journal).unwrap();
    let bin_receipt = std::fs::File::create(
        outdir
            .as_ref()
            .join(format!("receipt_{prover_name}_{power}.bin")),
    )
    .unwrap();
    ciborium::into_writer(&receipt, bin_receipt).unwrap();

    let bin_inner_receipt = std::fs::File::create(
        outdir
            .as_ref()
            .join(format!("inner_receipt_{prover_name}_{power}.bin")),
    )
    .unwrap();
    ciborium::into_writer(&receipt.inner, bin_inner_receipt).unwrap();

    let json_inner_receipt = std::fs::File::create(
        outdir
            .as_ref()
            .join(format!("inner_receipt_{prover_name}_{power}.json")),
    )
    .unwrap();
    serde_json::to_writer_pretty(json_inner_receipt, &receipt.inner).unwrap();
}

fn compute(method_elf: &[u8], opts: &ProverOpts, power: u32) -> Receipt {
    // For example:
    let cycles: u64 = u64::pow(2, power - 1) + 1;
    let env = ExecutorEnv::builder()
        .write(&cycles)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Proof information by proving the specified ELF binary.
    // This struct contains the receipt along with statistics about execution of the guest
    let prove_info = prover.prove_with_opts(env, method_elf, opts).unwrap();

    // extract the receipt.
    prove_info.receipt
}

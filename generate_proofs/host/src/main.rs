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

use clap::{Parser, ValueEnum};
use risc0_zkp::MAX_CYCLES_PO2;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt, DEFAULT_MAX_PO2};
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{debug, info, warn};

#[derive(Copy, Clone, ValueEnum, Debug)]
enum Prover {
    /// Sha hash : faster prover/verifier continuation segments
    Sha,
    /// Poseidon2 hash : slower prover/verifier continuation segments but can be wrapped in a succinct proof
    Poseidon2,
    /// Generate the poseidon2 segment and the succinct proof. Tho output segment size is fixed
    Succinct,
}

impl Display for Prover {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Prover {
    fn as_str(&self) -> &'static str {
        match self {
            Prover::Sha => "sha",
            Prover::Poseidon2 => "poseidon2",
            Prover::Succinct => "succinct",
        }
    }

    fn opts(&self) -> ProverOpts {
        match self {
            Prover::Sha => {
                warn!("From risc0 2.1.0 just poseidon was supported, it'll use poseidon2 instead");
                ProverOpts::fast()
            },
            Prover::Poseidon2 => ProverOpts::default(),
            Prover::Succinct => ProverOpts::succinct(),
        }
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Input folder for method elf and vk
    #[arg(short, long, value_name = "FOLDER", default_value = "method")]
    method: PathBuf,

    /// Output folder artifacts
    #[arg(short, long, value_name = "FOLDER", default_value = "output")]
    output: PathBuf,

    /// Provers to run
    #[arg(
        short,
        long,
        value_name = "PROVERS",
        default_values_t = vec![Prover::Sha, Prover::Poseidon2, Prover::Succinct]
    )]
    provers: Vec<Prover>,

    /// Powers of 2. Generate an execution that fit in a proof of 2^po2 cycle. If the segment size
    /// is not fix will use the default value of 2^20 as segment maximum size.
    #[arg(short='2', long, value_name = "PO2", default_values_t = vec![16, 22])]
    po2: Vec<u32>,

    /// If present, remove some cycles from the computed from power of 2
    #[arg(short, long, value_name = "REMOVE_CYCLES")]
    remove_cycles: Option<u64>,

    /// If is true is trying to create a single proof with a single segment
    #[arg(short, long, default_value = "false")]
    no_continuation: bool,

    /// Use a defined segment size: should be >= 16 and less than 22. Raise error if no_continuation
    /// is enabled.
    #[arg(short, long)]
    segment_size: Option<u32>,

    /// Verbose
    #[arg(short, long)]
    verbose: bool,
}

fn max_segment_size() -> u32 {
    MAX_CYCLES_PO2.min(DEFAULT_MAX_PO2) as u32
}

impl Cli {
    fn validate(&self) {
        for p in self.po2.clone() {
            if p < 15 {
                panic!("invalid po2 component: {p}");
            }
            if p > 24 {
                panic!("invalid po2 component: {p}");
            }
            if self.no_continuation {
                if p < 16 {
                    panic!("invalid po2 component for no continuation: {p}");
                }
                if p > max_segment_size() {
                    panic!("invalid po2 component for no continuation: {p}");
                }
            }
        }
        if matches!(self.segment_size, Some(s) if s < 16 && s > max_segment_size()) {
            panic!("invalid segment_size")
        }
    }
}

fn main() {
    let cli = Cli::parse();
    cli.validate();

    let log_default_cfg = if cli.verbose {
        "host=debug"
    } else {
        "host=info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::filter::EnvFilter::from_default_env()
                .add_directive(log_default_cfg.parse().unwrap()),
        )
        .init();

    let elf_path = cli.method.join("method");
    let vk_path = cli.method.join("info.txt");

    info!(
        "Read elf method from {} and vk (AKA method id) form {}",
        elf_path.display(),
        vk_path.display()
    );

    let method_elf = read_elf(elf_path);
    let method_id = read_method_id(vk_path);

    let output_path = cli.output;

    info!("Write artifacts in {}", output_path.display());

    std::fs::create_dir_all(&output_path).unwrap();

    let id_json_path = output_path.join("id.json");
    debug!("Vk json: {}", id_json_path.display());
    let json_id = std::fs::File::create(id_json_path).unwrap();
    serde_json::to_writer_pretty(json_id, &method_id).unwrap();

    debug!("Powers: {:?}", cli.po2);
    debug!("Provers: {:?}", cli.provers);
    debug!("Enabled continuation {}", !cli.no_continuation);
    debug!("Segment size {:?}", cli.segment_size);
    debug!("Removed cycle {:?}", cli.remove_cycles);
    for power in &cli.po2 {
        for prover in &cli.provers {
            let prover_name = prover.as_str();
            info!("============= {prover_name} - {power} =============");
            let start = Instant::now();
            let segment_size = if cli.no_continuation {
                Some(*power)
            } else {
                cli.segment_size
            };
            let prover_opts = prover.opts();
            let cycles = cycles(*power) - cli.remove_cycles.unwrap_or_default();
            let receipt = compute(&method_elf, &prover_opts, cycles, segment_size);
            let elapsed = start.elapsed().as_millis();
            let output: u32 = receipt.journal.decode().unwrap();
            info!("============= output = {output}  in {elapsed}ms =============");
            if prover_opts.receipt_kind == risc0_zkvm::ReceiptKind::Composite {
                let len = receipt.inner.composite().unwrap().segments.len();
                info!("============= len = {len} =============");
            } else {
                debug!("============= succinct =============");
            }

            receipt.verify(method_id).unwrap();
            save(&output_path, prover_name, *power, receipt);
            info!("============= DONE =============");
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
    let journal_path = outdir
        .as_ref()
        .join(format!("journal_{prover_name}_{power}.json"));
    debug!("Output journal file: {}", journal_path.display());
    let journal = std::fs::File::create(journal_path).unwrap();
    serde_json::to_writer_pretty(journal, &receipt.journal).unwrap();
    let bin_receipt_path = outdir
        .as_ref()
        .join(format!("receipt_{prover_name}_{power}.bin"));
    debug!("Output binary receipt: {}", bin_receipt_path.display());
    let bin_receipt = std::fs::File::create(bin_receipt_path).unwrap();
    ciborium::into_writer(&receipt, bin_receipt).unwrap();

    let bin_inner_receipt_path = outdir
        .as_ref()
        .join(format!("inner_receipt_{prover_name}_{power}.bin"));
    debug!(
        "Output binary inner receipt: {}",
        bin_inner_receipt_path.display()
    );
    let bin_inner_receipt = std::fs::File::create(bin_inner_receipt_path).unwrap();
    ciborium::into_writer(&receipt.inner, bin_inner_receipt).unwrap();

    let json_inner_receipt_path = outdir
        .as_ref()
        .join(format!("inner_receipt_{prover_name}_{power}.json"));
    debug!(
        "Output json inner receipt: {}",
        json_inner_receipt_path.display()
    );
    let json_inner_receipt = std::fs::File::create(json_inner_receipt_path).unwrap();
    serde_json::to_writer_pretty(json_inner_receipt, &receipt.inner).unwrap();
}

fn cycles(power: u32) -> u64 {
    match power {
        16 => 1024 * 16,
        17 => 1024 * 64,
        18 => 1024 * 128,
        19 => 1024 * 256,
        20 => 1024 * 256 * 3,
        21 => 1024 * 256 * 7,
        22 => 1024 * 256 * 15,
        23 => 1024 * 256 * 31,
        24 => 1024 * 256 * 63,
        _ => panic!("Unsupported power of two: {power}"),
    }
}

fn compute(method_elf: &[u8], opts: &ProverOpts, cycles: u64, segment_size: Option<u32>) -> Receipt {
    debug!("Cycles : {cycles}");

    let mut builder = ExecutorEnv::builder();

    builder.write(&cycles).unwrap();
    if let Some(size) = segment_size {
        debug!("Set segment size to 2^{size}");
        builder.segment_limit_po2(size);
    }
    let env = builder.build().unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Proof information by proving the specified ELF binary.
    // This struct contains the receipt along with statistics about execution of the guest
    let prove_info = prover.prove_with_opts(env, method_elf, opts).unwrap();

    // extract the receipt.
    prove_info.receipt
}

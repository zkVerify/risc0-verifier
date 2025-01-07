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

use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use anyhow::Context;
use argh::FromArgs;
use bytes::{Buf, BufMut, Bytes};
use risc0_verifier::{Journal, Proof};
use serde::{de::DeserializeOwned, Serialize};

#[derive(FromArgs)]
/// Perform conversion.
struct Convert {
    /// hex input format
    #[argh(switch, short = 'x')]
    hex_input: bool,

    /// hex output format
    #[argh(switch, short = 'X')]
    hex_output: bool,

    /// convert journal
    #[argh(switch, short = 'j')]
    journal: bool,

    /// input data (none for stdin)
    #[argh(option, short = 'i')]
    input: Option<PathBuf>,

    /// output data (none for stdout)
    #[argh(option, short = 'o')]
    output: Option<PathBuf>,
}

impl Convert {
    fn convert(&self) -> anyhow::Result<()> {
        if self.journal {
            let journal = self.read::<Journal>().context("Journal")?;
            self.write_data(&journal.bytes)
        } else {
            let proof = self.read::<Proof>().context("Proof")?;
            self.write(&proof)
        }
    }

    fn read<T: DeserializeOwned>(&self) -> anyhow::Result<T> {
        let input = self.get_input_file().context("Cannot open input file")?;
        let input = self.handle_input_format(input)?;
        bincode::deserialize_from(input).context("Reading data")
    }

    fn write<T: Serialize>(&self, d: &T) -> anyhow::Result<()> {
        let mut buf = bytes::BytesMut::new().writer();

        ciborium::into_writer(d, &mut buf).context("Writing data buffer")?;

        let buf = buf.into_inner();

        self.write_data(buf.as_ref())
    }

    fn write_data(&self, data: &[u8]) -> anyhow::Result<()> {
        let mut output = self.get_output_file().context("Cannot open output file")?;
        if self.hex_output {
            output
                .write_all(hex::encode(data).as_bytes())
                .context("Write hex data")
        } else {
            output.write_all(data).context("Write data")
        }
    }

    fn get_input_file(&self) -> anyhow::Result<Box<dyn Read>> {
        if let Some(ref path) = self.input {
            Ok(Box::new(File::open(path)?))
        } else {
            Ok(Box::new(std::io::stdin()))
        }
    }

    fn handle_input_format(&self, mut input: Box<dyn Read>) -> anyhow::Result<Box<dyn Read>> {
        if self.hex_input {
            let mut data = String::new();
            input
                .read_to_string(&mut data)
                .context("Cannot read input string")?;
            let bytes = Bytes::from_owner(
                hex::decode(data).map_err(|e| anyhow::anyhow!("Invalid hex data: {}", e))?,
            );

            Ok(Box::new(bytes.reader()))
        } else {
            Ok(Box::new(input))
        }
    }

    fn get_output_file(&self) -> anyhow::Result<Box<dyn Write>> {
        if let Some(ref path) = self.output {
            Ok(Box::new(File::create(path)?))
        } else {
            Ok(Box::new(std::io::stdout()))
        }
    }
}

fn main() -> anyhow::Result<()> {
    let convert: Convert = argh::from_env();

    convert.convert()
}

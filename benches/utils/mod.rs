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
    io::BufReader,
    path::{Path, PathBuf},
};

use risc0_verifier::{CircuitCoreDef, Digest, Journal, Proof, VerifierContext, Vk};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Case {
    pub receipt_path: PathBuf,
    pub journal: Journal,
    pub vk: Vk,
}

pub fn compute<SC: CircuitCoreDef + 'static, RC: CircuitCoreDef + 'static>(
    ctx: &VerifierContext<SC, RC>,
    proof: &Proof,
    vk: Vk,
    pubs: Digest,
) {
    proof.verify(&ctx, vk, pubs).unwrap()
}

pub fn read_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> anyhow::Result<T> {
    let file = File::open(path.as_ref())?;
    let buf_reader = BufReader::new(file);
    let result: T = serde_json::from_reader(buf_reader)?;
    Ok(result)
}

pub fn read_bin<T: DeserializeOwned>(path: impl AsRef<Path>) -> anyhow::Result<T> {
    let file = File::open(path.as_ref())?;
    let buf_reader = BufReader::new(file);
    ciborium::from_reader(buf_reader).map_err(Into::into)
}

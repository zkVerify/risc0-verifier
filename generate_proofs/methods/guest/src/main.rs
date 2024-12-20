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

use risc0_zkvm::guest::env;

fn main() {
    // read the input
    let cycles: u64 = env::read();
    let mut count: u64 = 0;

    while env::cycle_count() < cycles {
        count += 1;
    }

    // write public output to the journal
    env::commit(&count);
}

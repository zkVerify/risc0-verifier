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

mod risc0_dependency_version_checker {
    use semver::Version;
    use std::{collections::HashMap, fs};
    use toml::Value;

    #[test]
    fn risc0_dependencies_are_up_to_date() {
        // Update manually when needed
        let crate_to_version: HashMap<&str, &str> =
            HashMap::from([("risc0-zkp", "1.2.0"), ("risc0-circuit-rv32im", "1.2.0")]);

        // Read Cargo.lock file contents
        let lockfile_content = fs::read_to_string("Cargo.lock").expect("Failed to read Cargo.lock");

        // Parse the Cargo.toml file
        let lockfile: Value = lockfile_content
            .parse()
            .expect("Failed to parse Cargo.toml");

        // Fail the test if any crate version does not match (ignores patch version updates)
        for (crate_name, expected_version) in crate_to_version.iter() {
            assert!(is_up_to_date(&lockfile, crate_name, expected_version).is_ok());
        }
    }

    fn is_up_to_date(
        lockfile: &Value,
        crate_name: &str,
        expected_version: &str,
    ) -> Result<(), String> {
        // Locate the `risc0-zkp` package entry
        let packages = lockfile
            .get("package")
            .or_else(|| lockfile.get("dependencies"))
            .ok_or("Cargo.toml does not contain a [package] or [dependencies] section")?;

        let actual_version = packages
            .as_array()
            .and_then(|pkgs| {
                pkgs.iter().find_map(|pkg| {
                    if pkg.get("name")?.as_str()? == crate_name {
                        pkg.get("version")?.as_str()
                    } else {
                        None
                    }
                })
            })
            .ok_or("{crate_name:?} dependency not found or missing version field in Cargo.toml")?;

        // Parse actual and expected versions
        let actual_version = Version::parse(actual_version)
            .map_err(|_| "Failed to parse actual {crate_name:?} version")?;
        let expected_version = Version::parse(expected_version)
            .map_err(|_| "Failed to parse expected {crate_name:?} version")?;

        if expected_version.major == actual_version.major
            && expected_version.minor == actual_version.minor
        {
            Ok(())
        } else {
            Err(format!(
                "{} version mismatch: expected {}.x, found {}. Please update crate_to_version.",
                crate_name, expected_version.major, expected_version.minor
            ))
        }
    }
}

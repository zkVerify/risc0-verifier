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

use anyhow::{bail, Context};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Header file
    header: PathBuf,
    /// Source files
    sources: Vec<PathBuf>,

    #[arg(
        short,
        long,
        default_value = "false",
        help = "Throw error if header is not valid without change file"
    )]
    check: bool,

    #[arg(
        short,
        long,
        default_value = "false",
        help = "Perform a dry run without change file but dump on stdout"
    )]
    dry_run: bool,

    #[arg(short, long, help = "Glob path for source discover")]
    glob: Option<String>,
}

fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    println!("Header file: {:?}", &cli.header);
    println!("Glob pattern: {:?}", &cli.glob);

    let mut header = String::new();
    let mut h = File::open(&cli.header).context("Unable to open header file")?;
    File::read_to_string(&mut h, &mut header).context("Cannot read header file")?;
    let header_data = HeaderData::from(header.as_str());
    let mut changed = false;

    let mut sources = if let Some(g) = &cli.glob {
        globwalk::glob(g)
            .with_context(|| format!("Cannot parse glob pattern '{}'", g))?
            .map(|p| p.map(|p| p.into_path()))
            .collect::<Result<Vec<_>, _>>()
            .context("Resolve glob path")?
    } else {
        Default::default()
    };
    sources.append(&mut cli.sources.clone());

    for source in sources {
        if source.components().any(|c| c.as_os_str() == "target") {
            continue;
        }
        let mut s = File::open(&source)
            .with_context(|| format!("Unable to open source file '{}'", source.display()))?;
        let mut source_code = String::new();
        File::read_to_string(&mut s, &mut source_code)
            .with_context(|| format!("Cannot read source file {}", source.display()))?;

        let mut source_data = SourceData::from(source_code.as_str());

        if source_data.header.merge(&header_data) {
            changed = true;
            if cli.check {
                println!("*** FILE: {} should be updated", source.display());
                continue;
            }
            let w: Box<dyn Write> = if cli.dry_run {
                println!("============== DRY RUN {} ==============", source.display());
                Box::new(std::io::stdout())
            } else {
                println!("*** UPDATING FILE: {}", source.display());
                Box::new(File::create(&source).with_context(|| {
                    format!("cannot open source file '{}' for write", source.display())
                })?)
            };
            source_data.write(w)?;
        }
    }
    if cli.check && changed {
        bail!("Some file should be updated");
    }
    Ok(())
}

#[derive(Debug)]
struct HeaderData {
    copyrights: Vec<String>,
    spx: String,
    license: String,
}

impl HeaderData {
    fn write(&self, mut w: impl Write) -> Result<(), anyhow::Error> {
        self.write_copyrights(&mut w).context("write copyright")?;
        write_comment_line(&mut w)?;
        self.write_spx(&mut w).context("write spx")?;
        write_comment_line(&mut w)?;
        self.write_license(&mut w).context("write license")?;
        Ok(())
    }

    fn merge(&mut self, other: &HeaderData) -> bool {
        self.merge_copyrights(&other.copyrights)
            && self.merge_spx(&other.spx)
            && self.merge_license(&other.license)
    }

    fn read<'a>(lines: impl Iterator<Item = &'a str>) -> (Self, impl Iterator<Item = &'a str>) {
        let mut lines = lines.peekable();
        let empty_re = regex::Regex::new(r"^(//)?\s*$").unwrap();
        let header_re = regex::Regex::new(r"^//(\s+.*)?$").unwrap();
        let not_header_re = regex::Regex::new(r"^(//[/!])|#$").unwrap();
        let copyright_re = regex::Regex::new(r"^//\s+(Copyright\s.+)").unwrap();
        let spx_re = regex::Regex::new(r"^//\s+SPDX-License-Identifier: (.+)").unwrap();

        let copyrights = if lines
            .peek()
            .map(|line| copyright_re.is_match(line))
            .unwrap_or_default()
        {
            (&mut lines)
                .take_while(|line| copyright_re.is_match(line))
                .filter_map(|line| copyright_re.captures(line))
                .map(|c| c[1].to_owned())
                .collect()
        } else {
            Default::default()
        };
        let spx = if lines
            .peek()
            .map(|line| header_re.is_match(line))
            .unwrap_or_default()
        {
            (&mut lines)
                .take_while(|line| header_re.is_match(line))
                .filter_map(|line| spx_re.captures(line))
                .map(|c| c[1].to_owned())
                .next()
                .unwrap_or_default()
        } else {
            Default::default()
        };
        let license = if lines
            .peek()
            .map(|line| header_re.is_match(line))
            .unwrap_or_default()
        {
            (&mut lines)
                .skip_while(|line| {
                    empty_re.is_match(line) || copyright_re.is_match(line) || spx_re.is_match(line)
                })
                .take_while(|line| header_re.is_match(line) && !not_header_re.is_match(line))
                .map(str::to_owned)
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            Default::default()
        };

        (
            HeaderData {
                copyrights,
                spx,
                license,
            },
            lines,
        )
    }

    fn merge_copyrights(&mut self, copyrights: &[String]) -> bool {
        let mut candidate = copyrights.iter().cloned().collect::<Vec<_>>();
        for c in &self.copyrights {
            if !candidate.contains(c) {
                candidate.push(c.clone());
            }
        }
        if self.copyrights != candidate {
            self.copyrights = candidate;
            true
        } else {
            false
        }
    }

    fn merge_spx(&mut self, spx: &str) -> bool {
        if self.spx != spx {
            self.spx = spx.to_owned();
            true
        } else {
            false
        }
    }

    fn merge_license(&mut self, license: &str) -> bool {
        if self.license != license {
            self.license = license.to_owned();
            true
        } else {
            false
        }
    }

    fn write_copyrights(&self, mut w: impl Write) -> Result<(), anyhow::Error> {
        for c in &self.copyrights {
            writeln!(w, "// Copyright {c}")?;
        }
        Ok(())
    }

    fn write_spx(&self, mut w: impl Write) -> Result<(), anyhow::Error> {
        writeln!(w, "// SPDX-License-Identifier: {}", self.spx)?;
        Ok(())
    }

    fn write_license(&self, mut w: impl Write) -> Result<(), anyhow::Error> {
        writeln!(w, "{}", self.license)?;
        Ok(())
    }
}

fn write_comment_line(mut w: impl Write) -> Result<(), anyhow::Error> {
    writeln!(w, "//")?;
    Ok(())
}

fn writeln(mut w: impl Write) -> Result<(), anyhow::Error> {
    writeln!(w, "")?;
    Ok(())
}

impl From<&str> for HeaderData {
    fn from(value: &str) -> Self {
        Self::read(&mut value.lines()).0
    }
}

#[derive(Debug)]
struct SourceData {
    header: HeaderData,
    code_lines: Vec<String>,
}

impl SourceData {
    fn write(&self, mut out: impl Write) -> Result<(), anyhow::Error> {
        self.header.write(&mut out)?;
        write_comment_line(&mut out)?;
        writeln(&mut out)?;
        for line in &self.code_lines {
            writeln!(out, "{}", line).context("write source code")?;
        }
        Ok(())
    }
}

impl From<&str> for SourceData {
    fn from(value: &str) -> Self {
        let (header, lines) = HeaderData::read(value.lines());

        Self {
            header,
            code_lines: lines.map(str::to_owned).collect(),
        }
    }
}

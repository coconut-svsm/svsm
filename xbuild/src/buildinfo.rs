// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Bruno Schaatsbergen <git@bschaatsbergen.com>

use crate::{Args, BuildResult, RecipeParts};
use serde::{Deserialize, Serialize};
use sha2::digest::Output;
use sha2::{Digest, Sha256, Sha384};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const FORMAT: u32 = 1;

/// A file and the hash of its contents.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: PathBuf,
    pub sha256: String,
}

impl Artifact {
    pub fn new(path: &Path) -> BuildResult<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            sha256: hash_file::<Sha256>(path)?,
        })
    }
}

/// The guest firmware embedded in the image. Firmware publishers identify
/// their images by SHA-384, so record that as well.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Firmware {
    pub file: String,
    pub sha256: String,
    pub sha384: String,
}

/// How the launch digest was calculated.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Measure {
    pub platform: String,
    pub native_zero: bool,
    pub check_kvm: bool,
}

/// The source tree the image was built from.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub commit: Option<String>,
    /// Output of `git describe`, from which the kernel's version string is
    /// derived.
    pub describe: Option<String>,
    pub dirty: bool,
}

/// Build options and the tools that were used.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Build {
    pub release: bool,
    pub all_features: bool,
    pub features: Vec<String>,
    pub rustc: Option<String>,
    pub cargo: Option<String>,
    pub cc: Option<String>,
    pub objcopy: Option<String>,
}

/// What went into an IGVM image, and the launch digest that came out.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildInfo {
    pub format: u32,
    pub image: Artifact,
    pub launch_digest: String,
    pub measure: Measure,
    pub source: Source,
    pub recipe: Artifact,
    pub build: Build,
    pub firmware: Option<Firmware>,
    pub components: BTreeMap<String, Artifact>,
}

impl BuildInfo {
    pub fn collect(
        args: &Args,
        recipe: &Path,
        parts: &RecipeParts,
        image: &Path,
        launch_digest: String,
        measure: Measure,
    ) -> BuildResult<Self> {
        let mut components = BTreeMap::new();
        components.insert("kernel".to_string(), Artifact::new(&parts.kernel)?);
        if let Some(bldr) = parts.bldr.as_ref() {
            components.insert("bldr".to_string(), Artifact::new(bldr)?);
        }
        if let Some(stage1) = parts.stage1.as_ref() {
            components.insert("tdx-stage1".to_string(), Artifact::new(stage1)?);
        }
        if let Some(fs) = parts.fs.as_ref() {
            components.insert("fs".to_string(), Artifact::new(fs)?);
        }
        let firmware = match parts.firmware.as_ref() {
            Some(fw) => Some(Firmware {
                file: fw.file_name().unwrap_or_default().to_string_lossy().into(),
                sha256: hash_file::<Sha256>(fw)?,
                sha384: hash_file::<Sha384>(fw)?,
            }),
            None => None,
        };
        Ok(Self {
            format: FORMAT,
            image: Artifact::new(image)?,
            launch_digest,
            measure,
            source: Source::current(),
            recipe: Artifact::new(recipe)?,
            build: Build {
                release: args.release,
                all_features: args.all_features,
                features: args.features.clone(),
                rustc: tool_version("rustc", &["--version"]),
                cargo: tool_version("cargo", &["--version"]),
                cc: tool_version(c_compiler(), &["--version"]),
                objcopy: tool_version("objcopy", &["--version"]),
            },
            firmware,
            components,
        })
    }

    /// The build info file that belongs to `image`.
    pub fn path_for(image: &Path) -> PathBuf {
        let mut name = image.file_name().unwrap_or_default().to_os_string();
        name.push(".buildinfo.json");
        image.with_file_name(name)
    }

    pub fn write(&self, path: &Path) -> BuildResult<()> {
        let mut file = BufWriter::new(File::create(path)?);
        serde_json::to_writer_pretty(&mut file, self)?;
        file.write_all(b"\n")?;
        Ok(())
    }
}

impl Source {
    pub fn current() -> Self {
        let commit = git(&["rev-parse", "HEAD"]);
        let describe = git(&["describe", "--always", "--dirty=+", "--abbrev=12"]);
        let dirty = describe.as_deref().is_some_and(|d| d.ends_with('+'));
        Self {
            commit,
            describe,
            dirty,
        }
    }
}

fn hash_file<D: Digest>(path: &Path) -> BuildResult<String>
where
    Output<D>: fmt::LowerHex,
{
    let data = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(format!("{:x}", D::digest(&data)))
}

/// The first output line of `prog args`, or `None` if it cannot be run.
fn tool_version(prog: &str, args: &[&str]) -> Option<String> {
    first_line(Command::new(prog).args(args))
}

/// The C compiler libtcgtpm/Makefile picks for the host.
fn c_compiler() -> &'static str {
    if std::env::consts::ARCH == "x86_64" {
        "gcc"
    } else {
        "x86_64-linux-gnu-gcc"
    }
}

fn git(args: &[&str]) -> Option<String> {
    first_line(Command::new("git").args(args))
}

fn first_line(cmd: &mut Command) -> Option<String> {
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    stdout.lines().next().map(|l| l.trim().to_string())
}

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

use crate::buildinfo::Measure;
use crate::{Args, BuildResult, HELPERS, RecipeParts, features::Features, run_cmd_checked};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// An IGVM image that was built and measured.
#[derive(Debug)]
pub struct BuiltImage {
    pub path: PathBuf,
    pub launch_digest: String,
    pub measure: Measure,
}

/// Platform flags supported by `igvmbuilder`.
#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum IgvmPlatform {
    Native,
    Vsm,
    Snp,
    Tdp,
}

impl IgvmPlatform {
    /// Get the required string argument to pass to igvmbuilder.
    fn as_arg(&self) -> &str {
        match self {
            Self::Vsm => "--vsm",
            Self::Tdp => "--tdp",
            Self::Snp => "--snp",
            Self::Native => "--native",
        }
    }
}

/// IGVM measure types
#[derive(Debug, Deserialize, Clone, Copy, Default)]
#[serde(rename_all = "lowercase")]
enum IgvmMeasure {
    #[default]
    Print,
}

impl IgvmMeasure {
    /// Get the string command to pass to igvmmeasure.
    fn as_arg(&self) -> &str {
        match self {
            Self::Print => "measure",
        }
    }
}

/// Possible IGVM targets.
#[derive(Clone, Copy, Debug, Deserialize, Hash, PartialEq, Eq)]
enum IgvmTarget {
    #[serde(rename = "qemu")]
    Qemu,
    #[serde(rename = "hyper-v")]
    HyperV,
    #[serde(rename = "vanadium")]
    Vanadium,
}

impl IgvmTarget {
    fn as_arg(&self) -> &str {
        match self {
            Self::Qemu => "qemu",
            Self::HyperV => "hyper-v",
            Self::Vanadium => "vanadium",
        }
    }
}

/// Configuration for a single IGVM target
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
struct IgvmTargetConfig {
    /// Path for output file
    #[serde(default = "IgvmTargetConfig::default_output")]
    output: PathBuf,
    /// See help for `igvmbuilder --policy`
    #[serde(default = "IgvmTargetConfig::default_policy")]
    policy: String,
    /// See help for `igvmbuilder --comport`.
    comport: Option<String>,
    /// Platform flags for igvmbuilder
    #[serde(default = "IgvmTargetConfig::default_platforms")]
    platforms: Vec<IgvmPlatform>,
    /// Main command passed to `igvmmeasure`.
    #[serde(default)]
    measure: IgvmMeasure,
    /// See help for `igvmmeasure --native-zero`.
    #[serde(default)]
    measure_native_zeroes: bool,
    /// See help for `igvmmeasure --check_kvm`.
    #[serde(default)]
    check_kvm: bool,
    /// See help for `igvmbuilder --no_vtom`.
    #[serde(default)]
    no_vtom: bool,
}

impl IgvmTargetConfig {
    fn default_policy() -> String {
        "0x30000".into()
    }

    fn default_output() -> PathBuf {
        "default.json".into()
    }

    fn default_platforms() -> Vec<IgvmPlatform> {
        vec![IgvmPlatform::Snp, IgvmPlatform::Tdp, IgvmPlatform::Vsm]
    }

    fn igvmbuild(
        &self,
        args: &Args,
        target: IgvmTarget,
        parts: &RecipeParts,
        cmd_feats: &mut Features,
    ) -> BuildResult<PathBuf> {
        let output = PathBuf::from_iter(["bin".as_ref(), self.output.as_os_str()]);
        let mut cmd = Command::new(HELPERS.igvmbuilder(args, cmd_feats));
        cmd.arg("--sort")
            .arg("--output")
            .arg(&output)
            .args(["--policy", &self.policy])
            .arg("--kernel")
            .arg(&parts.kernel);
        if let Some(s1) = parts.stage1.as_ref() {
            cmd.arg("--tdx-stage1").arg(s1);
        }
        if let Some(bldr) = parts.bldr.as_ref() {
            cmd.arg("--bldr").arg(bldr);
        }
        if let Some(fw) = parts.firmware.as_ref() {
            cmd.arg("--firmware").arg(fw);
        }
        if let Some(fs) = parts.fs.as_ref() {
            cmd.arg("--filesystem").arg(fs);
        }
        if let Some(comport) = self.comport.as_ref() {
            cmd.arg("--comport").arg(comport);
        }
        if args.verbose {
            cmd.arg("--verbose");
        }
        if self.no_vtom {
            cmd.arg("--no-vtom");
        }
        for plat in self.platforms.iter() {
            cmd.arg(plat.as_arg());
        }
        cmd.arg(target.as_arg());
        run_cmd_checked(cmd, args)?;
        Ok(output)
    }

    /// Measure the image and return the launch digest.
    fn igvmmeasure(
        &self,
        args: &Args,
        bin: &Path,
        cmd_feats: &mut Features,
    ) -> BuildResult<String> {
        let mut cmd = Command::new(HELPERS.igvmmeasure(args, cmd_feats));
        if self.check_kvm {
            cmd.arg("--check-kvm");
        }
        if self.measure_native_zeroes {
            cmd.arg("--native-zero");
        }
        cmd.arg(bin).arg(self.measure.as_arg()).arg("--bare");
        if args.verbose {
            println!("{cmd:?}");
        }
        let output = cmd.stderr(Stdio::inherit()).output()?;
        if !output.status.success() {
            return Err(format!("igvmmeasure failed for {}", bin.display()).into());
        }
        let digest = String::from_utf8(output.stdout)?.trim().to_string();
        if digest.is_empty() || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(
                format!("igvmmeasure printed no launch digest for {}", bin.display()).into(),
            );
        }
        println!("Launch Digest ({}): {digest}", bin.display());
        Ok(digest)
    }

    fn build(
        &self,
        args: &Args,
        target: IgvmTarget,
        parts: &RecipeParts,
        cmd_feats: &mut Features,
    ) -> BuildResult<BuiltImage> {
        let bin = self.igvmbuild(args, target, parts, cmd_feats)?;
        let launch_digest = self.igvmmeasure(args, &bin, cmd_feats)?;
        Ok(BuiltImage {
            path: bin,
            launch_digest,
            measure: Measure {
                platform: "sev-snp".to_string(),
                native_zero: self.measure_native_zeroes,
                check_kvm: self.check_kvm,
            },
        })
    }
}

/// IGVM configuration for a recipe. It consists of a list of
/// hypervisor targets and a configuration for each of them.
#[derive(Debug, Deserialize, Clone)]
pub struct IgvmConfig {
    #[serde(flatten, default)]
    targets: HashMap<IgvmTarget, IgvmTargetConfig>,
}

impl IgvmConfig {
    pub fn build(
        &self,
        args: &Args,
        parts: &RecipeParts,
        cmd_feats: &mut Features,
    ) -> BuildResult<Vec<BuiltImage>> {
        self.targets
            .iter()
            .map(|(target, config)| config.build(args, *target, parts, cmd_feats))
            .collect()
    }
}

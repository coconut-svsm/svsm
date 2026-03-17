// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

use crate::{Args, BuildResult, HELPERS, RecipeParts, features::Features, run_cmd_checked};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

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
        if let Some(s2) = parts.stage2.as_ref() {
            cmd.arg("--stage2").arg(s2);
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
        for plat in self.platforms.iter() {
            cmd.arg(plat.as_arg());
        }
        cmd.arg(target.as_arg());
        run_cmd_checked(cmd, args)?;
        Ok(output)
    }

    fn igvmmeasure(&self, args: &Args, bin: PathBuf, cmd_feats: &mut Features) -> BuildResult<()> {
        let mut cmd = Command::new(HELPERS.igvmmeasure(args, cmd_feats));
        if self.check_kvm {
            cmd.arg("--check-kvm");
        }
        if self.measure_native_zeroes {
            cmd.arg("--native-zero");
        }
        cmd.arg(bin).arg(self.measure.as_arg());
        run_cmd_checked(cmd, args)
    }

    fn build(
        &self,
        args: &Args,
        target: IgvmTarget,
        parts: &RecipeParts,
        cmd_feats: &mut Features,
    ) -> BuildResult<()> {
        let bin = self.igvmbuild(args, target, parts, cmd_feats)?;
        self.igvmmeasure(args, bin, cmd_feats)?;
        Ok(())
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
    ) -> BuildResult<()> {
        for (target, config) in self.targets.iter() {
            config.build(args, *target, parts, cmd_feats)?;
        }
        Ok(())
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

use crate::{
    helpers::HELPERS, run_cmd_checked, Args, BuildResult, BuildTarget, Component, ComponentConfig,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Components for the filesystem image.
#[derive(Debug, Clone, Deserialize)]
pub struct FsConfig {
    modules: HashMap<String, ComponentConfig>,
}

impl FsConfig {
    fn components(&self) -> impl Iterator<Item = Component<&str, &ComponentConfig>> + '_ {
        self.modules
            .iter()
            .map(|(name, conf)| Component::new(name.as_str(), conf))
    }

    /// Builds the filesystem image based on the config's components,
    /// and returns the path to the built image if there were any
    /// files to pack.
    pub fn build(&self, args: &Args, mut dst: PathBuf) -> BuildResult<Option<PathBuf>> {
        if dst.try_exists()? {
            std::fs::remove_dir_all(&dst)?;
        }
        std::fs::create_dir(&dst)?;

        if self.modules.is_empty() {
            return Ok(None);
        }

        // Build all components and copy them to the output path
        for comp in self.components() {
            let bin = comp.build(args, BuildTarget::svsm_user())?;
            let mut dst_file = comp
                .config
                .path
                .as_deref()
                .unwrap_or_else(|| Path::new(comp.name));
            // Pushing an absolute path to a PathBuf will overwrite
            // previous elements, so remove leading slash.
            if dst_file.starts_with("/") {
                dst_file = dst_file.strip_prefix("/").unwrap();
            }
            dst.push(dst_file);
            comp.config.objcopy.copy(&bin, &dst, args)?;
            dst.pop();
        }

        // Now build filesystem image from all components
        let fs = PathBuf::from("bin/svsm-fs.bin");
        let mut cmd = Command::new(HELPERS.packit(args));
        cmd.arg("pack")
            .arg("--input")
            .arg(&dst)
            .arg("--output")
            .arg(&fs);
        run_cmd_checked(cmd, args)?;

        Ok(Some(fs))
    }
}

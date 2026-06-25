// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

use crate::{Args, BuildResult, BuildTarget, Component, ComponentConfig, features::Features};
use packit::PackItArchiveEncoder;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
    pub fn build(
        &self,
        args: &Args,
        dst: PathBuf,
        cmd_feats: &mut Features,
    ) -> BuildResult<Option<PathBuf>> {
        if dst.try_exists()? {
            std::fs::remove_dir_all(&dst)?;
        }
        std::fs::create_dir(&dst)?;

        if self.modules.is_empty() {
            return Ok(None);
        }

        let fs_path = PathBuf::from("bin/svsm-fs.bin");
        let mut fs = std::fs::File::create(&fs_path)?;
        let mut enc = PackItArchiveEncoder::new(&mut fs)?;

        // Build all components and add them to the archive
        for comp in self.components() {
            let bin = comp.build(args, BuildTarget::svsm_user(), cmd_feats)?;
            let mut dst_file = comp
                .config
                .path
                .as_deref()
                .unwrap_or_else(|| Path::new(comp.name));
            // Joining an absolute path to a PathBuf will overwrite
            // previous elements, so remove leading slash.
            if dst_file.starts_with("/") {
                dst_file = dst_file.strip_prefix("/").unwrap();
            }

            let current_dst = dst.join(dst_file);

            if let Some(parent) = current_dst.parent() {
                std::fs::create_dir_all(parent)?;
            }

            comp.config.objcopy.copy(&bin, &current_dst, args)?;

            let filename = dst_file
                .to_str()
                .ok_or_else(|| format!("invalid file name: {}", dst_file.display()))?;
            enc.load_file(filename, &std::fs::File::open(&current_dst)?)?;
        }

        Ok(Some(fs_path))
    }
}

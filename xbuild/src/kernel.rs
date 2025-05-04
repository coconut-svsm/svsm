// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

use crate::{Args, BuildResult, BuildTarget, Component, ComponentConfig};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// Components to build the kernel. It consists of a list of
/// component names and their respective build configurations.
#[derive(Debug, Clone, Deserialize)]
pub struct KernelConfig {
    #[serde(flatten, default)]
    components: HashMap<String, ComponentConfig>,
}

impl KernelConfig {
    fn components(&self) -> impl Iterator<Item = Component<&str, &ComponentConfig>> + '_ {
        self.components
            .iter()
            .map(|(name, conf)| Component::new(name.as_str(), conf))
    }

    pub fn build(&self, args: &Args, mut dst: PathBuf) -> BuildResult<Vec<PathBuf>> {
        if !dst.try_exists()? {
            std::fs::create_dir(&dst)?;
        }

        // Build each component and copy it to the output path
        let mut objs = Vec::new();
        for comp in self.components() {
            // Build the component and objcopy it into bin/
            let bin = comp.build(args, BuildTarget::svsm_kernel())?;
            dst.push(comp.name);
            comp.config.objcopy.copy(&bin, &dst, args)?;
            objs.push(dst.clone());
            dst.pop();
        }
        Ok(objs)
    }
}

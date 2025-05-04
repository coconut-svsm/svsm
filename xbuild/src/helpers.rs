// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

use crate::{Args, BuildTarget, Component, ComponentConfig};
use std::path::PathBuf;
use std::sync::OnceLock;

/// A data structure that lazily builds helper programs.
#[derive(Clone, Debug)]
pub struct Helpers {
    igvmbuilder: OnceLock<PathBuf>,
    igvmmeasure: OnceLock<PathBuf>,
    packit: OnceLock<PathBuf>,
}

impl Helpers {
    const fn new() -> Self {
        Self {
            igvmbuilder: OnceLock::new(),
            igvmmeasure: OnceLock::new(),
            packit: OnceLock::new(),
        }
    }

    pub fn igvmbuilder(&self, args: &Args) -> &PathBuf {
        self.igvmbuilder.get_or_init(|| {
            Component::new_default("igvmbuilder")
                .build(args, BuildTarget::Host)
                .expect("failed to build igvmbuilder")
        })
    }

    pub fn igvmmeasure(&self, args: &Args) -> &PathBuf {
        self.igvmmeasure.get_or_init(|| {
            Component::new_default("igvmmeasure")
                .build(args, BuildTarget::Host)
                .expect("failed to build igvmmeasure")
        })
    }

    pub fn packit(&self, args: &Args) -> &PathBuf {
        self.packit.get_or_init(|| {
            Component::new(
                "packit",
                ComponentConfig {
                    features: Some("cli".into()),
                    ..Default::default()
                },
            )
            .build(args, BuildTarget::Host)
            .expect("failed to build packit")
        })
    }
}

pub static HELPERS: Helpers = Helpers::new();

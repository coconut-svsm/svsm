// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 AMD Inc.
//
// Author: Joerg Roedel <joerg.roedel@amd.com>

use crate::Args;
use std::string::String;

#[derive(Debug)]
pub struct CmdLineFeature {
    raw: String,
    pkg: String,
    feat: String,
    consumed: bool,
}

impl CmdLineFeature {
    pub fn create_from_raw(raw: String) -> Self {
        let spec = raw.clone();
        let (pkg, feat) = if let Some((p, f)) = spec.split_once(':') {
            (p, f)
        } else {
            ("svsm", spec.trim())
        };

        Self {
            raw,
            pkg: String::from(pkg.trim()),
            feat: String::from(feat.trim()),
            consumed: false,
        }
    }

    pub fn consume(&mut self) {
        self.consumed = true;
    }

    pub fn was_consumed(&self) -> bool {
        self.consumed
    }
}

#[derive(Debug)]
pub struct Features {
    list: Vec<CmdLineFeature>,
}

impl Features {
    pub fn create_from_args(args: &Args) -> Self {
        let list = args
            .features
            .iter()
            .map(|f| CmdLineFeature::create_from_raw(String::from(f)))
            .collect();
        Self { list }
    }

    pub fn print_empty_features(&self) {
        for f in &self.list {
            if f.feat.is_empty() {
                eprintln!("WARNING: Empty feature specified: '{}'", f.raw);
            }
        }
    }

    pub fn print_unused_features(&self) {
        for f in &self.list {
            if !f.was_consumed() {
                eprintln!("WARNING: Command line feature not used: '{}'", f.raw);
            }
        }
    }

    pub fn feature_list(&mut self, pkg: &str, mut recipe_features: Vec<String>) -> Vec<String> {
        let mut pkg_features: Vec<String> = self
            .list
            .iter_mut()
            .filter_map(|f| {
                if f.pkg == pkg {
                    f.consume();
                    Some(f.feat.clone())
                } else {
                    None
                }
            })
            .collect();

        pkg_features.append(&mut recipe_features);

        pkg_features
    }
}

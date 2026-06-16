// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Carlos López <clopez@suse.de>

use serde::Deserialize;
use std::path::PathBuf;

/// A subset of the `cargo --message-format=json` schema. Only
/// fields we inspect are modeled, everything else falling back
/// to the `Other` variant.
#[derive(Deserialize)]
#[serde(tag = "reason", rename_all = "kebab-case")]
enum CargoMessage {
    CompilerArtifact {
        target: ArtifactTarget,
        profile: ArtifactProfile,
        executable: Option<PathBuf>,
    },
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct ArtifactTarget {
    name: String,
}

#[derive(Deserialize)]
struct ArtifactProfile {
    test: bool,
}

/// Parse the stdout of `cargo test --no-run --message-format=json` and return
/// the path to the test executable produced for package `pkg`.
///
/// Cargo emits one JSON object per line. Look for the `compiler-artifact`
/// record whose target name matches `pkg`, was built in test mode, and has
/// an `executable` path. If cargo produces several such records (e.g. lib +
/// integration tests) the last one wins.
pub fn find_test_executable(stdout: &[u8], pkg: &str) -> Option<PathBuf> {
    std::str::from_utf8(stdout)
        .ok()?
        .lines()
        .filter_map(|line| serde_json::from_str::<CargoMessage>(line).ok())
        .filter_map(|msg| match msg {
            CargoMessage::CompilerArtifact {
                target,
                profile,
                executable,
            } if target.name == pkg && profile.test => executable,
            _ => None,
        })
        .next_back()
}

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Bruno Schaatsbergen <git@bschaatsbergen.com>

use std::env;
use std::path::{Path, PathBuf};

/// The cargo home directory as cargo resolves it: `CARGO_HOME` if set and
/// not empty, otherwise `$HOME/.cargo`.
fn cargo_home(cwd: &Path) -> Option<PathBuf> {
    match env::var_os("CARGO_HOME").filter(|h| !h.is_empty()) {
        Some(home) => Some(cwd.join(home)),
        None => env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")),
    }
}

fn remap(from: &Path, to: &str) -> String {
    format!("--remap-path-prefix={}={to}", from.display())
}

/// Builds the `--config` value that strips the build paths from the
/// rustflags of `triple`, modelled on cargo's unstable `trim-paths`: the
/// workspace root becomes `.`, registry and git sources lose their
/// `CARGO_HOME` prefix. Unlike `RUSTFLAGS`, `--config` merges with
/// `.cargo/config.toml`.
pub fn cargo_config(triple: &str) -> String {
    let root = env::current_dir().expect("cannot determine the current directory");
    let mut flags = vec![remap(&root, ".")];
    // Later flags win in rustc, so these must come after the root in case
    // CARGO_HOME lives inside the workspace.
    if let Some(home) = cargo_home(&root) {
        flags.push(remap(&home.join("registry").join("src"), ""));
        flags.push(remap(&home.join("git").join("checkouts"), ""));
    }
    // JSON string escapes are valid TOML basic string escapes.
    let flags: Vec<String> = flags
        .iter()
        .map(|f| serde_json::to_string(f).unwrap())
        .collect();
    format!("target.{triple}.rustflags=[{}]", flags.join(","))
}

/// Warn when cargo will ignore the target rustflags, remapping included.
pub fn check_env() {
    for var in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"] {
        if env::var_os(var).is_some() {
            eprintln!("WARNING: {var} is set, build paths are not remapped");
        }
    }
}

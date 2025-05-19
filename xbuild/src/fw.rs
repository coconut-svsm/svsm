// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

use crate::{run_cmd_checked, Args, BuildResult};
use serde::Deserialize;
use std::env::{self, VarError};
use std::path::PathBuf;
use std::process::Command;

/// Guest firmware build configuration
#[derive(Clone, Debug, Deserialize, Default)]
pub struct FirmwareConfig {
    env: Option<String>,
    file: Option<PathBuf>,
    command: Option<Vec<String>>,
}

impl FirmwareConfig {
    fn run_command(&self, args: &Args) -> BuildResult<()> {
        let Some(command) = self.command.as_ref() else {
            return Ok(());
        };
        if args.verbose {
            println!("{:?}", command);
        }
        let prog = command.first().ok_or("firmware: empty command")?;
        let mut cmd = Command::new(prog);
        if let Some(args) = command.get(1..) {
            cmd.args(args);
        }
        run_cmd_checked(cmd, args)
    }

    /// Builds the firmware image based on the parsed configuration
    /// and returns the path to the image, if any.
    pub fn build(&self, args: &Args) -> BuildResult<Option<PathBuf>> {
        // If the config specifies a command, run it
        self.run_command(args)?;

        // If the config specifies a file, that's the output
        if let Some(file) = self.file.as_ref() {
            return Ok(Some(file.into()));
        }

        // If the config specifies an environment variable, return
        // its contents.
        let Some(env) = self.env.as_ref() else {
            return Ok(None);
        };

        match env::var(env) {
            Ok(val) => Ok(Some(val.into())),
            Err(VarError::NotPresent) => Ok(None),
            Err(e) => Err(format!("{env}: {e}").into()),
        }
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com

use clap::Parser;
use memmap2::Mmap;
use packit::{PackItArchiveDecoder, PackItArchiveEncoder, PackItError, PackItFile, PackItResult};
use std::fs;
use std::io::{self, ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

#[macro_export]
macro_rules! ioerr {
    ($k:ident) => {
        io::Error::from(ErrorKind::$k)
    };
    ($k:ident, $e:expr) => {
        io::Error::new(ErrorKind::$k, $e)
    };
}

#[derive(Parser, Debug)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Clone, Debug)]
enum Command {
    /// Pack a directory into an archive
    Pack(PackParams),
    /// Unpack an archive into a directory
    Unpack(UnpackParams),
    /// List files in an archive
    List(ListParams),
}

#[derive(clap::Args, Clone, Debug)]
struct PackParams {
    /// Directory to pack
    #[clap(short, long, value_parser)]
    input: PathBuf,
    /// Output archive
    #[clap(short, long, value_parser)]
    output: PathBuf,
    /// Do not follow symlinks. If set, symlinks will be ignored.
    #[clap(short = 's', long, value_parser)]
    no_symlinks: bool,
    /// Print files as they are archived
    #[clap(short, long, value_parser)]
    verbose: bool,
}

impl PackParams {
    fn run(&self) -> PackItResult<()> {
        let mut dst = fs::File::create(&self.output)?;
        let mut ar = PackItArchiveEncoder::new(&mut dst)?;

        self.process_entries(fs::read_dir(&self.input)?, &mut ar)?;
        dst.sync_all()?;

        Ok(())
    }

    fn process_entry<W: Write>(
        &self,
        entry: &fs::DirEntry,
        ar: &mut PackItArchiveEncoder<W>,
    ) -> PackItResult<()> {
        let path = entry.path();
        let file = fs::File::open(&path)?;
        let meta = file.metadata()?;
        let etype = meta.file_type();

        if etype.is_file() || (etype.is_symlink() && !self.no_symlinks) {
            // Create the destination path inside the archive
            let dst_path = path
                .strip_prefix(&self.input)
                .map_err(|e| ioerr!(InvalidData, e))?
                .to_str()
                .ok_or(PackItError::InvalidFileName)?;

            if self.verbose {
                println!("{} -> {}", path.display(), dst_path);
            }

            // Map the file and write it to the archive
            match meta.len() {
                0 => {
                    // Special case, a zero-length mapping will fail
                    let pfile = PackItFile::new(dst_path, &[])?;
                    ar.write_file(&pfile)?;
                }
                _ => {
                    let file_data = unsafe { Mmap::map(&file) }?;
                    let pfile = PackItFile::new(dst_path, &file_data)?;
                    ar.write_file(&pfile)?;
                }
            }
        } else if etype.is_dir() {
            self.process_entries(fs::read_dir(&path)?, ar)?;
        }

        Ok(())
    }

    fn process_entries<W: Write>(
        &self,
        entries: fs::ReadDir,
        ar: &mut PackItArchiveEncoder<W>,
    ) -> PackItResult<()> {
        let mut entries = entries.collect::<io::Result<Vec<_>>>()?;
        entries.sort_by_cached_key(|e| e.path());
        for entry in entries.iter() {
            self.process_entry(entry, ar)?;
        }
        Ok(())
    }
}

#[derive(clap::Args, Clone, Debug)]
struct UnpackParams {
    /// Input archive to unpack.
    #[clap(short, long, value_parser)]
    input: PathBuf,
    /// Output directory.
    #[clap(short, long, value_parser)]
    output: PathBuf,
    /// Print files as they are unpacked.
    #[clap(short, long, value_parser)]
    verbose: bool,
}

// Check that a path does not go shallow enough to escape a preprended
// base directory
fn verify_path<P: AsRef<Path>>(path: P) -> bool {
    // Depth zero means base directory. If we go below 0 this path
    // points outside the base directory
    let mut depth = 0isize;

    // Get all components and remove the file name
    let mut components = path.as_ref().components();
    let _ = components.next_back();

    for comp in components {
        match comp {
            Component::CurDir | Component::RootDir | Component::Prefix(..) => (),
            Component::Normal(..) => depth += 1,
            Component::ParentDir => depth -= 1,
        }
        if depth < 0 {
            return false;
        }
    }

    true
}

impl UnpackParams {
    fn run(&self) -> PackItResult<()> {
        // Prepare the decoder
        let file = fs::File::open(&self.input)?;
        let mem = unsafe { Mmap::map(&file) }?;
        let dec = PackItArchiveDecoder::load(&mem)?;

        // Create and form the full output path
        fs::DirBuilder::new().create(&self.output)?;
        let outdir = self.output.canonicalize()?;

        for file in dec {
            let file = file?;
            let file_path = Path::new(file.name());

            if !verify_path(file_path) {
                return Err(ioerr!(
                    InvalidData,
                    format!(
                        "File path points outside base directory: {}",
                        file_path.display()
                    )
                )
                .into());
            }

            if let Some(parent) = file_path
                .parent()
                .filter(|p| !p.to_str().unwrap_or("").is_empty())
            {
                // Create path leading to file
                let parent = outdir.join(parent);
                if self.verbose {
                    println!("Directory: {}", parent.display());
                }
                fs::DirBuilder::new().recursive(true).create(&parent)?;

                // Check that there is no escape from the output dir
                assert!(parent.canonicalize().unwrap().starts_with(&outdir));
            }

            let file_path = outdir.join(file_path);
            if self.verbose {
                println!("File: {}", file_path.display());
            }

            // Create and populate file
            fs::File::create(&file_path)?.write_all(file.data())?;
        }

        Ok(())
    }
}

#[derive(clap::Args, Clone, Debug)]
struct ListParams {
    /// Archive to list
    #[clap(short, long, value_parser)]
    input: PathBuf,
}

impl ListParams {
    fn run(&self) -> PackItResult<()> {
        let file = fs::File::open(&self.input)?;
        let mem = unsafe { Mmap::map(&file) }?;
        let dec = PackItArchiveDecoder::load(&mem)?;
        for file in dec {
            let file = file?;
            println!("{} ({} bytes)", file.name(), file.data().len());
        }
        Ok(())
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    let res = match args.command {
        Command::List(p) => p.run(),
        Command::Pack(p) => p.run(),
        Command::Unpack(p) => p.run(),
    };

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_verify_path() {
        assert!(verify_path("a/b/c"));
        assert!(verify_path("/a/b/c"));
        assert!(!verify_path("../a/b/c"));
        assert!(!verify_path("/../a/b/c"));
        assert!(!verify_path("../b/b/c"));
        assert!(!verify_path("/../b/b/c"));
        assert!(verify_path("a/../a/b/c"));
        assert!(verify_path("a/b/../c/d/e"));
        assert!(verify_path("a/b/../../c/d/e"));
        assert!(!verify_path("a/b/../../../c/d/e"));
        assert!(!verify_path("/a/b/../../../c/d/e"));
        assert!(verify_path("a/b/c/d/e"));
        assert!(verify_path("/a/b/c/d/e"));
        assert!(verify_path("a/./c/d/e"));
        assert!(verify_path("/a/./c/d/e"));
        assert!(!verify_path("a/./../../c/d/e"));
        assert!(!verify_path("/a/./../../c/d/e"));
    }
}

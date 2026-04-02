// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

mod features;
mod fs;
mod fw;
mod helpers;
mod igvm;
mod kernel;
mod version;

use crate::{
    features::Features, fs::FsConfig, fw::FirmwareConfig, helpers::HELPERS, igvm::IgvmConfig,
    kernel::KernelConfig, version::generate_release_file,
};
use clap::Parser;
use serde::Deserialize;
use std::borrow::{Borrow, BorrowMut};
use std::boxed::Box;
use std::error::Error;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;

type BuildResult<T> = Result<T, Box<dyn Error>>;

/// A generic component that needs to be built
struct Component<S: AsRef<str>, B: Borrow<ComponentConfig>> {
    /// The name of the component
    name: S,
    /// The configuration to build the component
    config: B,
}

impl<S: AsRef<str>> Component<S, ComponentConfig> {
    fn new_default(name: S) -> Self {
        Self {
            name,
            config: ComponentConfig::default(),
        }
    }
}

impl<S: AsRef<str>, B: Borrow<ComponentConfig>> Component<S, B> {
    /// Create a new component with the given name an configuration.
    const fn new(name: S, config: B) -> Self {
        Self { name, config }
    }

    /// Build the component with the given user arguments and target.
    fn build(
        &self,
        args: &Args,
        target: BuildTarget,
        cmd_feats: &mut Features,
    ) -> BuildResult<PathBuf> {
        println!("Building {}...", self.name.as_ref());
        self.config
            .borrow()
            .build(args, self.name.as_ref(), target, cmd_feats)
    }
}

/// Run a command and check its exit status
fn run_cmd_checked<C: BorrowMut<Command>>(mut cmd: C, args: &Args) -> BuildResult<()> {
    if args.verbose {
        println!("{:?}", cmd.borrow());
    }
    if cmd.borrow_mut().status()?.success() {
        return Ok(());
    }
    Err(std::io::Error::last_os_error().into())
}

/// Build targets for cargo
#[derive(Clone, Copy, Debug)]
enum BuildTarget {
    X8664UnknownNone,
    Host,
}

impl BuildTarget {
    const fn svsm_kernel() -> Self {
        Self::X8664UnknownNone
    }

    const fn svsm_user() -> Self {
        Self::X8664UnknownNone
    }

    /// Get the build target as the triplet string cargo expects, or
    /// `None` if this is the host target.
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::X8664UnknownNone => Some("x86_64-unknown-none"),
            Self::Host => None,
        }
    }
}

/// Available methods to build a component
#[derive(Clone, Copy, Debug, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
enum BuildType {
    #[default]
    Cargo,
    Make,
}

/// Binutils target used in objcopy
#[derive(Clone, Debug, Deserialize)]
struct Objcopy(String);

impl Default for Objcopy {
    fn default() -> Self {
        Self("elf64-x86-64".into())
    }
}

impl Objcopy {
    /// Call `objcopy` with the given input and output files
    fn copy(&self, src: &Path, dst: &Path, args: &Args) -> BuildResult<()> {
        let flags = if args.release {
            "--strip-unneeded"
        } else {
            "--strip-debug"
        };
        let mut cmd = Command::new("objcopy");
        cmd.arg("-O").arg(&self.0).arg(flags).arg(src).arg(dst);
        run_cmd_checked(cmd, args)
    }
}

/// The recipe for a single kernel component (e.g. `tdx-stage1`,
/// `stage2` or `svsm`.
#[derive(Clone, Debug, Deserialize, Default)]
struct ComponentConfig {
    #[serde(rename = "type", default)]
    build_type: BuildType,
    output_file: Option<String>,
    manifest: Option<PathBuf>,
    #[serde(default)]
    features: Option<String>,
    #[serde(default)]
    binary: bool,
    #[serde(default)]
    objcopy: Objcopy,
    path: Option<PathBuf>,
}

impl ComponentConfig {
    /// Build this component with the specified target
    fn build(
        &self,
        args: &Args,
        pkg: &str,
        target: BuildTarget,
        cmd_feats: &mut Features,
    ) -> BuildResult<PathBuf> {
        match self.build_type {
            BuildType::Cargo => self.cargo_build(args, pkg, target, cmd_feats),
            BuildType::Make => self.makefile_build(args, pkg, cmd_feats),
        }
    }

    fn features(&self) -> Vec<String> {
        self.features
            .clone()
            .map(|feat| feat.split(',').map(|f| f.trim().to_string()).collect())
            .unwrap_or_default()
    }

    /// Build this component as a cargo binary
    fn cargo_build(
        &self,
        args: &Args,
        pkg: &str,
        target: BuildTarget,
        cmd_feats: &mut Features,
    ) -> BuildResult<PathBuf> {
        let mut bin = PathBuf::from("target");

        let mut cmd = Command::new("cargo");
        cmd.args([
            "build",
            if self.binary { "--bin" } else { "--package" },
            pkg,
        ]);
        if let Some(triple) = target.as_str() {
            cmd.args(["--target", triple]);
            bin.push(triple);
        };
        if args.all_features {
            cmd.args(["--all-features"]);
        } else {
            let mut features = self.features();
            features.append(&mut cmd_feats.feature_list(pkg));
            if !features.is_empty() {
                cmd.args(["--features", features.join(",").as_str()]);
            }
        }
        if let Some(manifest) = self.manifest.as_ref() {
            cmd.args(["--manifest-path".as_ref(), manifest.as_os_str()]);
        }
        if args.release {
            cmd.arg("--release");
            bin.push("release");
        } else {
            bin.push("debug");
        }
        if args.offline {
            cmd.args(["--offline", "--locked"]);
        }
        if args.verbose {
            cmd.arg("-vv");
        }
        run_cmd_checked(cmd, args)?;

        bin.push(pkg);
        Ok(bin)
    }

    /// Build this component as a Makefile binary.
    fn makefile_build(
        &self,
        args: &Args,
        pkg: &str,
        cmd_feats: &mut Features,
    ) -> BuildResult<PathBuf> {
        let Some(file) = self.output_file.as_ref() else {
            return Err("Cannot build makefile target without output_file".into());
        };
        let mut cmd = Command::new("make");
        cmd.arg(file);
        if args.release {
            cmd.arg("RELEASE=1");
        }
        if args.verbose {
            cmd.arg("V=2");
        }

        // Get feature list
        let mut features = self.features();
        features.append(&mut cmd_feats.feature_list(pkg));
        let env_features = features.join(",");

        // Pass features to Makefile. We don't know if this is a test
        // target, so fill in both environment variables, and let the
        // Makefile use the right one.
        cmd.env("FEATURES", &env_features);
        cmd.env("FEATURES_TEST", &env_features);

        run_cmd_checked(cmd, args)?;
        Ok(PathBuf::from(file))
    }
}

/// A recipe corresponding to a full build.
#[derive(Clone, Debug, Deserialize)]
struct Recipe {
    /// SVSM kernel components
    kernel: KernelConfig,
    /// Guest firmware components
    #[serde(default)]
    firmware: FirmwareConfig,
    /// Guest filesystem components
    fs: FsConfig,
    /// IGVM configuration
    igvm: IgvmConfig,
}

impl Recipe {
    /// Builds the kernel components for this recipe. Returns a
    /// [`RecipePartsBuilder`] that can be used to keep track of
    /// built components for the recipe.
    fn build_kernel(
        &self,
        args: &Args,
        cmd_feats: &mut Features,
    ) -> BuildResult<RecipePartsBuilder> {
        let mut parts = RecipePartsBuilder::new();
        for obj in self.kernel.build(args, PathBuf::from("bin"), cmd_feats)? {
            match obj.file_name().and_then(|s| s.to_str()).unwrap_or_default() {
                "tdx-stage1" => parts.set_stage1(obj),
                "stage2" => parts.set_stage2(obj),
                "svsm" => parts.set_kernel(obj),
                n => eprintln!("WARN: kernel: ignoring unknown component: {n}"),
            }
        }
        Ok(parts)
    }

    /// Builds all the components for this recipe
    fn build(&self, args: &Args, cmd_feats: &mut Features) -> BuildResult<()> {
        // Build kernel, guest firmware and guest filesystem
        let mut parts = self.build_kernel(args, cmd_feats)?;
        if let Some(fw) = self.firmware.build(args)? {
            parts.set_fw(fw);
        }
        if let Some(fs) = self.fs.build(args, PathBuf::from("bin/fs"), cmd_feats)? {
            parts.set_fs(fs);
        }

        // Check that we have all pieces and build the IGVM file
        let parts = parts.build()?;
        self.igvm.build(args, &parts, cmd_feats)?;
        Ok(())
    }
}

/// A helper structure used to keep track of all components built by
/// a recipe.
#[derive(Debug, Default, Clone)]
struct RecipePartsBuilder {
    stage1: Option<PathBuf>,
    stage2: Option<PathBuf>,
    kernel: Option<PathBuf>,
    firmware: Option<PathBuf>,
    fs: Option<PathBuf>,
}

impl RecipePartsBuilder {
    fn new() -> Self {
        Self::default()
    }

    fn set_stage1(&mut self, v: PathBuf) {
        self.stage1 = Some(v);
    }

    fn set_stage2(&mut self, v: PathBuf) {
        self.stage2 = Some(v);
    }

    fn set_kernel(&mut self, v: PathBuf) {
        self.kernel = Some(v)
    }

    fn set_fw(&mut self, v: PathBuf) {
        self.firmware = Some(v);
    }

    fn set_fs(&mut self, v: PathBuf) {
        self.fs = Some(v);
    }

    /// Returns a [`RecipeParts`] if all required components have
    /// been built.
    fn build(self) -> BuildResult<RecipeParts> {
        Ok(RecipeParts {
            stage1: self.stage1,
            stage2: self.stage2,
            kernel: self.kernel.ok_or("kernel: missing main kernel")?,
            firmware: self.firmware,
            fs: self.fs,
        })
    }
}

/// Components built by a recipe. Used by IGVM tools to build the
/// final image.
#[derive(Clone, Debug)]
struct RecipeParts {
    stage1: Option<PathBuf>,
    stage2: Option<PathBuf>,
    kernel: PathBuf,
    firmware: Option<PathBuf>,
    fs: Option<PathBuf>,
}

#[derive(clap::Parser, Debug)]
#[clap(version, about = "SVSM build tool")]
struct Args {
    /// Perform a release build (default: false)
    #[clap(short, long, value_parser)]
    release: bool,
    /// Compile all cargo components with all features (default: false)
    #[clap(short, long, value_parser)]
    all_features: bool,
    /// Add more cargo features to specified components, e.g. '-f svsm:attest'.
    /// If component is omitted, it defaults to `svsm`.
    #[clap(
        short,
        long = "feature",
        value_delimiter = ',',
        value_name = "FEATURES"
    )]
    features: Vec<String>,
    /// Enable verbose output (default: false)
    #[clap(short, long, value_parser)]
    verbose: bool,
    /// Perform offline build (default: false)
    #[clap(short, long, value_parser)]
    offline: bool,
    /// Print each recipe before building (default: false)
    #[clap(short, long, value_parser)]
    print_config: bool,
    // Path to the JSON build recipe(s)
    #[clap(required(true))]
    recipes: Vec<PathBuf>,
}

fn check_root_path() -> BuildResult<()> {
    let Ok(root) = std::env::var("CARGO_MANIFEST_DIR") else {
        return Ok(());
    };

    let xbuild = PathBuf::from(root).canonicalize()?;
    let svsm = xbuild.parent().unwrap();
    let current = std::env::current_dir()?.canonicalize()?;
    if current != svsm {
        return Err("xbuild must be run from the root of the SVSM repository".into());
    }
    Ok(())
}

fn main() -> BuildResult<()> {
    check_root_path()?;

    let args = Args::parse();
    let mut features = Features::create_from_args(&args);

    features.print_empty_features();

    generate_release_file();

    for filename in args.recipes.iter() {
        let f = File::open(filename)?;
        let recipe = serde_json::from_reader::<_, Recipe>(f)?;
        if args.print_config {
            println!("{}: {recipe:#?}", filename.display());
        }
        recipe.build(&args, &mut features)?;
    }

    features.print_unused_features();

    Ok(())
}

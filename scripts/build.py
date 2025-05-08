#!/usr/bin/env python3
#

import subprocess
import argparse
import platform
import shutil
import json
import os
import sys

SUPPORTED_IGVM_TARGETS=["qemu", "hyper-v", "vanadium"]

class CargoRunner:
    """
    A class for running cargo to build specific packages from the workspace.
    """

    def __init__(self, package):
        self.package = package
        self.output_file = package
        self.binary = False
        self.features = []
        self.release = False
        self.target = None
        self.manifest = None
        self.offline = False
        self.verbose = False

    def set_package(self, package):
        """
        Sets the package to build.
        """
        self.package = package

    def set_output_file(self, output_file):
        """
        Sets an alternative build output file name.
        """
        self.output_file = output_file

    def enable_binary(self):
        """
        Builds a binary instead of a package (--package vs. --bin)
        """
        self.binary = True

    def add_feature(self, feature):
        """
        Adds a feature to build with.
        """
        self.features.append(feature)

    def enable_release(self):
        """
        Sets whether to build in release mode.
        """
        self.release = True

    def set_target(self, target):
        """
        Sets the target to build for.
        """
        self.target = target

    def set_manifest(self, manifest):
        """
        Sets the manifest to build with.
        """
        self.manifest = manifest

    def enable_offline(self):
        """
        Enable offline builds.
        """
        self.offline = True

    def enable_verbose(self):
        """
        Enable verbosity build output
        """
        self.verbose = True

    def execute(self):
        """
        Executes the cargo command.
        """
        if self.package is None:
            raise ValueError("Package not set")

        command = ["cargo", "build"]
        if self.verbose:
            command.append("-vv")
        if self.binary:
            command.extend(["--bin", self.package])
        else:
            command.extend(["--package", self.package])

        if self.offline:
            command.extend(["--locked", "--offline"])
        if self.features:
            command.extend(["--features", ",".join(self.features)])
        if self.manifest:
            command.extend(["--manifest-path", self.manifest])
        if self.release:
            command.append("--release")
        if self.target:
            command.extend(["--target", self.target])

        if self.verbose:
            print(command)
        subprocess.run(command, check=True)

    def get_binary_path(self):
        """
        Gets the path of the resulting binary.
        """
        target_dir = "target"
        if self.target:
            target_dir = os.path.join(target_dir, self.target)
        binary_dir = os.path.join(target_dir, "release" if self.release else "debug")
        binary = os.path.join(binary_dir, self.output_file)
        if not os.path.isfile(binary):
            binary = os.path.join(binary_dir, self.package)
        return binary

def parse_components(recipe):
    """
    Parse a recipe for a single kernel component like tdx-stage1, stage2 or svsm.

    Args:
      recipe: A build data structure from a parsed JSON document.

    Returns:
      A sanitized dictionary with component-related build parameters.
    """
    kernel_config = {}

    for package, settings in recipe.items():
        kernel_config[package] = {
            "type": settings.get("type", "cargo"),
            "file": settings.get("output_file", None),
            "manifest": settings.get("manifest", None),
            "features": settings.get("features", "").split(),
            "binary": settings.get("binary", False),
            "objcopy": settings.get("objcopy", get_svsm_elf_target()),
            "path": settings.get("path", None),
        }

    return kernel_config

def kernel_recipe(config):
    """
    Parses the JSON configuration for kernel components.

    Args:
      json_data: A Python dictionary representing the configuration.

    Returns:
      A dictionary with parsed build settings for each component.
    """

    kernel_json = config.get("kernel", {})

    return parse_components(kernel_json)


def parse_igvm_config(target, config):
    """
    Parses parameters for a single IGVM file to build.

    Args:
      config: A Python dictionary from a parsed JSON document.

    Returns:
      A sanitized dictionary with IGVM build parameters.
    """
    igvm_config = {
        "policy": config.get("policy", "0x30000"),
        "target": target,
        "output": config.get("output", "default.json"),
        "comport": config.get("comport", None),
        "platforms": config.get("platforms", ["snp", "tdp", "vsm"]),
        "measure": config.get("measure", "print"),
        "measure-native-zeroes": config.get("measure-native-zeroes", False),
        "check-kvm": config.get("check-kvm", False),
    }

    return igvm_config

def igvm_recipe(config):
    """
    Parses parameters for all IGVM files to build

    Args:
      config: A Python dictionary from a parsed JSON document. The keys of the
              dictionary are the hypervisor targets and the values point to
              dictionaries with per-target IGVM parameters.

    Returns:
      A sanitized dictionary with per-target IGVM build parameters.
    """
    igvm_json = config.get("igvm", {})

    igvm_targets = {}
    for target, config in igvm_json.items():
        if target not in SUPPORTED_IGVM_TARGETS:
            raise ValueError(f"Unknown IGVM target: {target}")
        igvm_targets[target] = parse_igvm_config(target, config)

    return igvm_targets

def firmware_recipe(config):
    """
    Parse a parameters for retrieving the firmware.

    Args:
      config: A Python dictionary from a parsed JSON document.

    Returns:
      A sanitized dictionary with firmware build/retrieval parameters.
    """
    firmware_json = config.get("firmware", {})

    firmware_config = {
        "env": firmware_json.get("env", None),
        "file": firmware_json.get("file", None),
        "command": firmware_json.get("command", None),
    }

    if firmware_config["command"] and not isinstance(firmware_config["command"], list):
        raise ValueError("Value of firmware.command must be a JSON array")

    return firmware_config

def fs_recipe(config):
    """
    Parse a parameters for retrieving the file-system image

    Args:
      config: A Python dictionary from a parsed JSON document.

    Returns:
      A sanitized dictionary with parameters for building the file-system
      image.
    """
    fs_json = config.get("fs", {})

    fs_config = {
        "modules": parse_components(fs_json.get("modules", {})),
    }
    return fs_config

def read_recipe(file_path):
    """
    Reads a JSON file and parses its content.

    Args:
      file_path: Path to the JSON file.

    Returns:
      A Python dictionary representing the parsed JSON data.
    """
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data

def get_host_target():
    """
    Returns the Rust target for building the helper utilities (like igvmbuilder
    and igvmmeasure).
    """
    return "x86_64-unknown-linux-gnu"

def get_svsm_kernel_target():
    """
    Returns the Rust target for building the helper utilities (like igvmbuilder
    and igvmmeasure).
    """
    return "x86_64-unknown-none"

def get_svsm_user_target():
    """
    Returns the Rust target for building the user-space components which are
    packaged into the SVSM file-system image.
    """
    return "x86_64-unknown-none"

def get_svsm_elf_target():
    """
    Returns the binutils target used in objcopy when copying the SVSM kernel
    ELF file.
    """
    return "elf64-x86-64"

def objcopy_kernel(binary_path, target_path, elf_target, args):
    """
    Execute objcopy to prepare a binary for packaging into the IGVM file.

    Args:
      binary_path: File path to source binary.
      target_path: File path where copied binary is stored.
      elf_target: Binary target to use for the output file.
      args: A structure initialized from command line options.
    """
    command = ["objcopy", "-O", elf_target, "--strip-unneeded"]
    command.append(binary_path)
    command.append(target_path)
    if args.verbose:
        print(command)
    subprocess.run(command, check=True)

def cargo_build(package, config, target, args):
    """
    Run a single build step using cargo.

    Args:
      package: Name of the workspace package or binary to build.
      config: A Python dictionary carrying the cargo specific build options.
      target: Rust target to build for.
      args: A structure initialized from command line options.

    Returns:
      Path to the binary built with cargo.
    """
    runner = CargoRunner(package)
    runner.set_target(target)
    for feature in config.get("features", []):
        runner.add_feature(feature)
    if config.get("binary"):
        runner.enable_binary()
    if config.get("file"):
        runner.set_output_file(config.get("file"))
    if config.get("manifest"):
        runner.set_manifest(config.get("manifest"))
    if args.release:
        runner.enable_release()
    if args.verbose:
        runner.enable_verbose()
    if args.offline:
        runner.enable_offline()

    runner.execute()

    return runner.get_binary_path()

def make_build(package, config, args):
    """
    Run a single build step using GNU Make.

    Args:
      package: Name of the package to build.
      config: A Python dictionary carrying the make specific build options.
      args: A structure initialized from command line options.

    Returns:
      Path to the make target which was built.
    """
    if config["file"]:
        command = ["make", config["file"]]
        if args.release:
            command.append("RELEASE=1")
        if args.verbose:
            command.append("V=2")
            print(command)
        subprocess.run(command, check=True)
        return config["file"]
    else:
        raise ValueError("Build type make in package {} requires an 'output_file' attribute".format(package));

def recipe_build(recipe, target, args):
    """
    Takes a list of package build recipes and builds them one by one.

    Args:
      recipe: A Python dictionary with package name as the key and another
              dictionary with build options as their value.
      target: Rust target to use for cargo builds
      args: A structure initialized from command line options.

    Returns:
      A Python dictionary with package names as key and paths to built binaries
      as value.
    """
    binaries = {}
    for package, config in recipe.items():
        print("Building {}...".format(package))
        build_type = config.get("type", "cargo")
        if build_type == "cargo":
            binary = cargo_build(package, config, target, args)
        elif build_type == "make":
            binary = make_build(package, config, args)
        else:
            raise ValueError("Unknown build type: {}".format(build_type))

        binaries[package] = binary
        
    return binaries

def build_helpers(args):
    """
    Build the tooling needed to create the IGVM file and its components.
    Currently it takes care of building the igvmbuilder and the igvmmeasure tool.

    Args:
      args: A structure initialized from command line options.

    Returns:
      A Python dictionary with build names as key and paths to their binaries
      as value.
    """
    helpers = {
        "igvmbuilder": {},
        "igvmmeasure": {},
        "packit": { "features": ["cli"] }
    }
    return recipe_build(helpers, get_host_target(), args)

def build_kernel_parts(k_recipe, args):
    """
    Build all parts needed for the COCONUT kernel as specified in the JSON file.

    Args:
      k_recipe: A Python dictionary with the build options for each kernel part.
      args: A structure initialized from command line options.

    Returns:
      A Python dictionary with kernel parts as key and paths to theor binary
      files as value.
    """
    parts = {}
    binaries = recipe_build(k_recipe, get_svsm_kernel_target(), args)
    for binary, source_path in binaries.items():
        bin_target = k_recipe[binary].get("objcopy", get_svsm_elf_target());
        target_path = "bin/{}".format(binary)
        objcopy_kernel(source_path, target_path, bin_target, args)
        parts[binary] = target_path

    return parts

def build_firmware(args, firmware_config):
    """
    Retrieves and/or builds the firmware to package into the IGVM file.

    Args:
      args: A structure initialized from command line options.
      firmware_config: A Python dictionary with options on how to
                       build/retrieve the firmware.

    Returns:
      Path to the firmware file to package or None.
    """
    if firmware_config["command"]:
        if args.verbose:
            print(firmware_config["command"])
        subprocess.run(firmware_config["command"], check=True)
    if firmware_config["file"]:
        return firmware_config["file"]
    elif firmware_config["env"]:
        return os.getenv(firmware_config["env"])
    else:
        return None

def build_fs_image(args, fs_config, helpers):
    """
    Builds the user-space binaries for the file-system image and packs them up
    into an image file.

    Args:
      args: A structure initialized from command line options.
      fs_config: A Python dictionary with options about which user-space
                 modules to build and where to place them in the file-system
                 image.
      helpers: A Python dictionary with the helper tools to use, as returned by
               build_helpers().

    Returns:
      Path to the file-system image.
    """
    fs_path = "bin/fs"
    if os.path.exists(fs_path):
        print("File-system image path already exists ... deleting")
        shutil.rmtree(fs_path)
    os.mkdir(fs_path)

    m_recipe = fs_config.get("modules")
    if len(m_recipe) == 0:
        return None

    binaries = recipe_build(m_recipe, get_svsm_user_target(), args)
    for binary, source_path in binaries.items():
        bin_target = m_recipe[binary].get("objcopy", get_svsm_elf_target());
        fs_binary = m_recipe[binary].get("path", binary)
        target_path = "{}/{}".format(fs_path, fs_binary)
        objcopy_kernel(source_path, target_path, bin_target, args)

    fs_image_file = "bin/svsm-fs.bin"

    # Run PackIt to create the image file
    command = [ helpers["packit"], "pack", "--input", fs_path, "--output", fs_image_file ]
    subprocess.run(command, check=True)

    return fs_image_file

def build_igvm_files(args, helpers, igvm_config, parts_config):
    """
    Iterates over the IGVM specifications and builds the hypervisor soecific
    IGVM files.

    Args:
      args: A structure initialized from command line options.
      helpers: A Python dictionary with the helper tools to use, as returned by
               build_helpers().
      igvm_config: A Python dictionary with targets as keys and specific build
                   parameter dictionaries as values.
      parts_config: A Python dictionary with information about the COCONUT
                    kernel parts and firmware to include in all IGVM files.
      
    """
    for target, config in igvm_config.items():
        build_igvm_file_one(args, helpers, config, parts_config)

def build_igvm_file_one(args, helpers, igvm_config, parts_config):
    """
    Takes the collected information and binaries and builds one hypervisor
    specific IGVM file. It will also invoke igvmmeasure to calculate the
    expected launch measurement.

    Args:
      args: A structure initialized from command line options.
      helpers: A Python dictionary with the helper tools to use, as returned by
               build_helpers().
      igvm_config: A Python dictionary with all necessary information and
                   parameters to build the IGVM file.
      parts_config: A Python dictionary with information about the COCONUT
                    kernel parts and firmware to include in all IGVM files.
    """

    output_path = "bin/{}".format(igvm_config["output"]);

    ###################################################################
    # IGVMBUILDER Command
    ###################################################################
    command = [
        helpers["igvmbuilder"],
        "--sort",
        "--output", output_path,
        "--policy", igvm_config["policy"],
        "--stage2", parts_config["stage2"],
        "--kernel", parts_config["kernel"]
    ]

    if parts_config["tdx-stage1"]:
        command.extend(["--tdx-stage1", parts_config["tdx-stage1"]])

    if igvm_config["comport"]:
        command.extend(["--comport", igvm_config["comport"]])

    for platform in igvm_config["platforms"]:
        if platform == "native":
            command.append("--native")
        elif platform == "vsm":
            command.append("--vsm")
        elif platform == "snp":
            command.append("--snp")
        elif platform == "tdp":
            command.append("--tdp")
        else:
            raise ValueError("Unknown IGVM platform type: {}".format(platform))

    if parts_config["firmware"]:
        command.extend(["--firmware", parts_config["firmware"]])

    if parts_config["fs"]:
        command.extend(["--filesystem", parts_config["fs"]])

    command.append(igvm_config["target"])

    # Run igvmbuilder
    if args.verbose:
        print(command)
    subprocess.run(command, check=True)

    ###################################################################
    # IGVMMEASURE Command
    ###################################################################
    command = [ helpers["igvmmeasure"] ]
    if igvm_config["check-kvm"]:
        command.append("--check-kvm")
    if igvm_config["measure-native-zeroes"]:
        command.append("--native-zero")

    command.append(output_path)

    if igvm_config["measure"] == "print":
        command.append("measure")
    else:
        raise ValueError("Unknown measure type {}".format(igvm_config["measure"]))

    # Run igvmmeasure
    if args.verbose:
        print(command)
    subprocess.run(command, check=True)

def build_one(recipe, helpers, args):
    """
    Builds all required components and generates the IGVM output file. From the
    generated file it calculates and prints the expected launch measurement.

    Args:
      recipe: File path to the JSON build recipe.
      helpers: Dictionary pointing to helper binaries.
      args: A structure initialized from command line options.
    """

    # Load and parse JSON file with the build recipe.
    config = read_recipe(recipe)

    # Retrieve build configurations
    k_recipe = kernel_recipe(config)
    igvm_config = igvm_recipe(config)
    firmware_config = firmware_recipe(config)
    fs_config = fs_recipe(config)

    # Build all parts of the COCONUT kernel
    kernel_parts = build_kernel_parts(k_recipe, args)

    parts_cfg = {}

    parts_cfg["stage2"] = kernel_parts.get("stage2")
    parts_cfg["kernel"] = kernel_parts.get("svsm")
    parts_cfg["tdx-stage1"] = kernel_parts.get("tdx-stage1", None)

    # Build/Retrieve firmware to include into IGVM file
    parts_cfg["firmware"] = build_firmware(args, firmware_config)

    # Build user-space file-system image
    parts_cfg["fs"] = build_fs_image(args, fs_config, helpers)

    # Create the IGVM file
    build_igvm_files(args, helpers, igvm_config, parts_cfg)

def build(args):
    """
    Main build function. It builds the helpers and then calls build_one for
    each passed recipe.

    Args:
      args: A structure initialized from command line options.

    Returns:
        True on successful build
        False on failue
    """
	# Create output directory if it does not exist yet.
    if not os.path.exists("bin"):
        os.mkdir("bin")

    try:
        # Build required helpers
        helpers = build_helpers(args)

        for recipe in args.recipe:
            build_one(recipe, helpers, args)

    except FileNotFoundError as f:
        print(f"Error: {recipe}: {f}")
        return False
    except json.JSONDecodeError as e:
        print(f"Error: {recipe}: {e}")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error: {recipe}: {e}")
        return False
    except ValueError as verr:
        print(f"Error: {recipe}: {verr}")
        return False

    return True

def parse_arguments():
    """Parses command-line arguments."""

    parser = argparse.ArgumentParser(description="Build tool for COCONUT-SVSM.")
    parser.add_argument(
        "-r",
        "--release",
        action="store_true",
        help="Perform a release build (default: debug)"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "-o",
        "--offline",
        action="store_true",
        help="Perform an offline build"
    )
    parser.add_argument(
        "recipe",
	nargs="+",
        metavar="RECIPE", 
        help="Path to the JSON build recipe file"
    )
    return parser.parse_args()

if __name__ == "__main__":
    sys.exit(os.EX_OK if build(parse_arguments()) else os.EX_SOFTWARE)


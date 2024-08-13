// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;
use std::fs::metadata;

use igvm_defs::PAGE_SIZE_4K;

use crate::cmd_options::{CmdOptions, Hypervisor};
use crate::firmware::Firmware;
use crate::igvm_builder::{COMPATIBILITY_MASK, TDP_COMPATIBILITY_MASK};

#[derive(Debug, Copy, Clone)]
pub struct GpaRange {
    start: u64,
    end: u64,
    size: u64,
}

impl GpaRange {
    fn new(start: u64, size: u64) -> Result<Self, Box<dyn Error>> {
        if (start & 0xfff) != 0 {
            return Err("Range is not page aligned".into());
        }
        let page_size = (size + (PAGE_SIZE_4K - 1)) & !(PAGE_SIZE_4K - 1);
        Ok(Self {
            start,
            end: start + page_size,
            size,
        })
    }

    fn new_page(start: u64) -> Result<Self, Box<dyn Error>> {
        Self::new(start, PAGE_SIZE_4K)
    }

    pub fn get_start(&self) -> u64 {
        self.start
    }

    pub fn get_end(&self) -> u64 {
        self.end
    }
    pub fn get_size(&self) -> u64 {
        self.size
    }
}

#[derive(Debug)]
pub struct GpaMap {
    pub stage1_image: GpaRange,
    pub low_memory: GpaRange,
    pub stage2_stack: GpaRange,
    pub stage2_image: GpaRange,
    pub stage2_free: GpaRange,
    pub secrets_page: GpaRange,
    pub cpuid_page: GpaRange,
    pub kernel_elf: GpaRange,
    pub kernel_fs: GpaRange,
    pub igvm_param_block: GpaRange,
    pub general_params: GpaRange,
    pub memory_map: GpaRange,
    pub guest_context: GpaRange,
    pub kernel: GpaRange,
    pub vmsa: GpaRange,
}

impl GpaMap {
    pub fn new(
        options: &CmdOptions,
        firmware: &Option<Box<dyn Firmware>>,
    ) -> Result<Self, Box<dyn Error>> {
        //   0x000000-0x00EFFF: zero-filled (must be pre-validated)
        //   0x00F000-0x00FFFF: initial stage 2 stack page
        //   0x010000-0x0nnnnn: stage 2 image
        //   0x0nnnnn-0x09DFFF: zero-filled (must be pre-validated)
        //   0x09E000-0x09EFFF: Secrets page
        //   0x09F000-0x09FFFF: CPUID page
        //   0x100000-0x1nnnnn: kernel
        //   0x1nnnnn-0x1nnnnn: filesystem
        //   0x1nnnnn-0x1nnnnn: IGVM parameter block
        //   0x1nnnnn-0x1nnnnn: general and memory map parameter pages
        //   0xFFnn0000-0xFFFFFFFF: [TDX stage 1 +] OVMF firmware (QEMU only, if specified)

        let stage1_image = if let Some(stage1) = &options.tdx_stage1 {
            if COMPATIBILITY_MASK.contains(TDP_COMPATIBILITY_MASK) {
                // Obtain the length of the binary file
                let stage1_len = Self::get_metadata(stage1)?.len();
                // TDX stage1 must be located to end at 4GB
                GpaRange::new((1u64 << 32) - stage1_len, stage1_len)?
            } else {
                return Err("TDP platform must be specified when using --tdx-stage1".into());
            }
        } else {
            GpaRange::new(0, 0)?
        };

        // Obtain the lengths of the binary files
        let stage2_len = Self::get_metadata(&options.stage2)?.len() as usize;
        let kernel_elf_len = Self::get_metadata(&options.kernel)?.len() as usize;
        let kernel_fs_len = if let Some(fs) = &options.filesystem {
            metadata(fs)?.len() as usize
        } else {
            0
        };

        let stage2_image = GpaRange::new(0x10000, stage2_len as u64)?;

        // Calculate the firmware range
        let firmware_range = if let Some(firmware) = firmware {
            let fw_start = firmware.get_fw_info().start as u64;
            let fw_size = firmware.get_fw_info().size as u64;
            GpaRange::new(fw_start, fw_size)?
        } else {
            GpaRange::new(0, 0)?
        };

        let kernel_address = match options.hypervisor {
            Hypervisor::Qemu => {
                // Plan to load the kernel image at a base address of 1 MB unless it must
                // be relocated due to firmware.
                1 << 20
            }
            Hypervisor::HyperV => {
                // Load the kernel image after the firmware, but now lower than
                // 1 MB.
                let firmware_end = firmware_range.get_end();
                let addr_1mb = 1 << 20;
                if firmware_end < addr_1mb {
                    addr_1mb
                } else {
                    firmware_end
                }
            }
        };
        let kernel_elf = GpaRange::new(kernel_address, kernel_elf_len as u64)?;
        let kernel_fs = GpaRange::new(kernel_elf.get_end(), kernel_fs_len as u64)?;

        // Calculate the kernel size and base.
        let kernel = match options.hypervisor {
            Hypervisor::Qemu => {
                // Place the kernel area at 512 GB with a size of 16 MB.
                GpaRange::new(0x0000008000000000, 0x01000000)?
            }
            Hypervisor::HyperV => {
                // Place the kernel area at 64 MB with a size of 16 MB.
                GpaRange::new(0x04000000, 0x01000000)?
            }
            Hypervisor::Vanadium => {
                // Place the kernel area at 8TiB-2GiB with a size of 16 MB.
                GpaRange::new(0x7ff80000000, 0x01000000)?
            }
        };

        let igvm_param_block = GpaRange::new_page(kernel_fs.get_end())?;
        let general_params = GpaRange::new_page(igvm_param_block.get_end())?;
        let memory_map = GpaRange::new_page(general_params.get_end())?;
        let guest_context = if let Some(firmware) = firmware {
            if firmware.get_guest_context().is_some() {
                // Locate the guest context after the memory map parameter page
                GpaRange::new_page(memory_map.get_end())?
            } else {
                GpaRange::new(0, 0)?
            }
        } else {
            GpaRange::new(0, 0)?
        };

        let vmsa = match options.hypervisor {
            Hypervisor::Qemu | Hypervisor::Vanadium => {
                // VMSA address is currently hardcoded in kvm
                GpaRange::new_page(0xFFFFFFFFF000)?
            }
            Hypervisor::HyperV => GpaRange::new_page(kernel.end - PAGE_SIZE_4K)?,
        };

        let gpa_map = Self {
            stage1_image,
            low_memory: GpaRange::new(0, 0xf000)?,
            stage2_stack: GpaRange::new_page(0xf000)?,
            stage2_image,
            stage2_free: GpaRange::new(stage2_image.get_end(), 0x9e000 - &stage2_image.get_end())?,
            secrets_page: GpaRange::new_page(0x9e000)?,
            cpuid_page: GpaRange::new_page(0x9f000)?,
            kernel_elf,
            kernel_fs,
            igvm_param_block,
            general_params,
            memory_map,
            guest_context,
            kernel,
            vmsa,
        };
        if options.verbose {
            println!("GPA Map: {gpa_map:#X?}");
        }
        Ok(gpa_map)
    }

    pub fn get_metadata(path: &String) -> Result<std::fs::Metadata, Box<dyn Error>> {
        let meta = metadata(path).map_err(|e| {
            eprintln!("Failed to access {}", path);
            e
        })?;
        Ok(meta)
    }
}

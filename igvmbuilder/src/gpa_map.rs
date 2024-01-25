// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;
use std::fs::metadata;

use igvm_defs::PAGE_SIZE_4K;

use crate::cmd_options::{CmdOptions, Hypervisor};

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
    pub firmware: GpaRange,
    pub kernel: GpaRange,
    pub vmsa: GpaRange,
}

impl GpaMap {
    pub fn new(options: &CmdOptions) -> Result<Self, Box<dyn Error>> {
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
        //   0xFFnn0000-0xFFFFFFFF: OVMF firmware (QEMU only, if specified)

        // Obtain the lengths of the binary files
        let stage2_len = metadata(&options.stage2)?.len() as usize;
        let kernel_elf_len = metadata(&options.kernel)?.len() as usize;
        let kernel_fs_len = if let Some(fs) = &options.filesystem {
            metadata(fs)?.len() as usize
        } else {
            0
        };

        let stage2_image = GpaRange::new(0x10000, stage2_len as u64)?;

        // Plan to load the kernel image at a base address of 1 MB unless it must
        // be relocated due to firmware.
        let kernel_address = 1 << 20;
        // TODO: If Hyper-V then parse the firmware and determine if the kernel
        // address changes. Also calculate vtom from firmware

        let kernel_elf = GpaRange::new(kernel_address, kernel_elf_len as u64)?;
        let kernel_fs = GpaRange::new(kernel_elf.end, kernel_fs_len as u64)?;

        // Calculate the firmware range
        let firmware = if let Some(firmware) = &options.firmware {
            match options.hypervisor {
                Hypervisor::QEMU => {
                    // OVMF must be located to end at 4GB.
                    let len = metadata(firmware)?.len() as usize;
                    if len > 0xffffffff {
                        return Err("OVMF firmware is too large".into());
                    }
                    GpaRange::new((0xffffffff - len + 1) as u64, len as u64)?
                }
                Hypervisor::HyperV => return Err("Hyper-V firmware not yet implemented".into()),
            }
        } else {
            GpaRange::new(0, 0)?
        };

        // Calculate the kernel size and base.
        let kernel = match options.hypervisor {
            Hypervisor::QEMU => {
                // Place the kernel area at 512 GB with a size of 16 MB.
                GpaRange::new(0x0000008000000000, 0x01000000)?
            }
            Hypervisor::HyperV => {
                // Place the kernel area at 64 MB with a size of 16 MB.
                GpaRange::new(0x04000000, 0x01000000)?
            }
        };
        let gpa_map = Self {
            low_memory: GpaRange::new(0, 0xf000)?,
            stage2_stack: GpaRange::new_page(0xf000)?,
            stage2_image,
            stage2_free: GpaRange::new(stage2_image.end, 0x9e000 - &stage2_image.end)?,
            secrets_page: GpaRange::new_page(0x9e000)?,
            cpuid_page: GpaRange::new_page(0x9f000)?,
            kernel_elf,
            kernel_fs,
            igvm_param_block: GpaRange::new_page(kernel_elf.end)?,
            general_params: GpaRange::new_page(kernel_elf.end + PAGE_SIZE_4K)?,
            memory_map: GpaRange::new_page(kernel_elf.end + 2 * PAGE_SIZE_4K)?,
            firmware,
            kernel,
            vmsa: GpaRange::new_page(kernel.start)?,
        };
        if options.verbose {
            println!("GPA Map: {gpa_map:#X?}");
        }
        Ok(gpa_map)
    }
}

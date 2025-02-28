// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;
use std::fs::metadata;

use bootlib::kernel_launch::{
    CPUID_PAGE, SECRETS_PAGE, STAGE2_BASE, STAGE2_STACK_END, STAGE2_START,
};
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
    pub base_addr: u64,
    pub stage1_image: GpaRange,
    pub stage2_stack: GpaRange,
    pub stage2_image: GpaRange,
    pub secrets_page: GpaRange,
    pub cpuid_page: GpaRange,
    pub kernel_elf: GpaRange,
    pub kernel_fs: GpaRange,
    pub igvm_param_block: GpaRange,
    pub general_params: GpaRange,
    pub memory_map: GpaRange,
    pub madt: GpaRange,
    pub guest_context: GpaRange,
    // The kernel region represents the maximum allowable size. The hypervisor may request that it
    // be smaller to save memory on smaller machine shapes. However, the entire region should not
    // overlap any other regions.
    pub kernel: GpaRange,
    pub vmsa: GpaRange,
    pub init_page_tables: GpaRange,
}

impl GpaMap {
    pub fn new(
        options: &CmdOptions,
        firmware: &Option<Box<dyn Firmware>>,
    ) -> Result<Self, Box<dyn Error>> {
        //   0x010000-0x010FFF: initial page tables for VSM platforms
        //   0x800000-0x804FFF: zero-filled (must be pre-validated)
        //   0x805000-0x805FFF: initial stage 2 stack page
        //   0x806000-0x806FFF: Secrets page
        //   0x807000-0x807FFF: CPUID page
        //   0x808000-0x8nnnnn: stage 2 image
        //   0x8nnnnn-0x8nnnnn: kernel
        //   0x8nnnnn-0x8nnnnn: filesystem
        //   0x8nnnnn-0x8nnnnn: IGVM parameter block
        //   0x8nnnnn-0x8nnnnn: general and memory map parameter pages
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

        let stage2_image = GpaRange::new(STAGE2_START.into(), stage2_len as u64)?;

        // The kernel image is loaded beyond the end of the stage2 image,
        // rounded up to a 4 KB boundary.
        let kernel_address = stage2_image.get_end().next_multiple_of(0x1000);
        let kernel_elf = GpaRange::new(kernel_address, kernel_elf_len as u64)?;
        let kernel_fs = GpaRange::new(kernel_elf.get_end(), kernel_fs_len as u64)?;

        // Choose the kernel base and maximum size.
        let kernel = match options.hypervisor {
            Hypervisor::Qemu => {
                // Place the kernel area below 512 GB with a maximum size of 16 MB.
                GpaRange::new(0x0000007fff000000, 0x01000000)?
            }
            Hypervisor::HyperV => {
                // Place the kernel area at 64 MB with a maximum size of 16 MB.
                GpaRange::new(0x04000000, 0x01000000)?
            }
            Hypervisor::Vanadium => {
                // Place the kernel area at 8TiB-2GiB with a maximum size of 2 GiB.
                GpaRange::new(0x7ff80000000, 0x80000000)?
            }
        };

        let igvm_param_block = GpaRange::new_page(kernel_fs.get_end())?;
        let general_params = GpaRange::new_page(igvm_param_block.get_end())?;
        let madt_size = match options.hypervisor {
            Hypervisor::HyperV | Hypervisor::Vanadium => PAGE_SIZE_4K,
            Hypervisor::Qemu => 0,
        };
        let madt = GpaRange::new(general_params.get_end(), madt_size)?;
        let memory_map = GpaRange::new_page(madt.get_end())?;
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
            base_addr: STAGE2_BASE.into(),
            stage1_image,
            stage2_stack: GpaRange::new_page(STAGE2_STACK_END.into())?,
            stage2_image,
            secrets_page: GpaRange::new_page(SECRETS_PAGE.into())?,
            cpuid_page: GpaRange::new_page(CPUID_PAGE.into())?,
            kernel_elf,
            kernel_fs,
            igvm_param_block,
            general_params,
            memory_map,
            madt,
            guest_context,
            kernel,
            vmsa,
            init_page_tables: GpaRange::new(0x10000, 2 * PAGE_SIZE_4K)?,
        };
        if options.verbose {
            println!("GPA Map: {gpa_map:#X?}");
        }
        Ok(gpa_map)
    }

    pub fn get_metadata(path: &String) -> Result<std::fs::Metadata, Box<dyn Error>> {
        let meta = metadata(path).inspect_err(|_| {
            eprintln!("Failed to access {}", path);
        })?;
        Ok(meta)
    }
}

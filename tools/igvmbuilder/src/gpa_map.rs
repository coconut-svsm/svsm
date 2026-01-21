// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;
use std::fs::metadata;

use bootdefs::kernel_launch::CPUID_PAGE;
use bootdefs::kernel_launch::STAGE2_BASE;
use bootdefs::kernel_launch::STAGE2_MAXLEN;
use bootdefs::kernel_launch::STAGE2_STACK_PAGE;
use bootdefs::kernel_launch::STAGE2_START;

use igvm_defs::PAGE_SIZE_4K;

use crate::boot_params::BootParamLayout;
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
    pub cpuid_page: GpaRange,
    pub kernel_fs: GpaRange,
    pub boot_param_block: GpaRange,
    pub boot_param_layout: BootParamLayout,
    // The kernel region represents the maximum allowable size. The hypervisor may request that it
    // be smaller to save memory on smaller machine shapes. However, the entire region should not
    // overlap any other regions.
    pub kernel: GpaRange,
    pub kernel_min_size: u32,
    pub kernel_max_size: u32,
    pub vmsa: GpaRange,
    pub vmsa_in_kernel_range: bool,
    pub init_page_tables: GpaRange,
}

impl GpaMap {
    pub fn new(
        options: &CmdOptions,
        firmware: &Option<Box<dyn Firmware>>,
    ) -> Result<Self, Box<dyn Error>> {
        //   0x00D000-0x00EFFF: initial page tables for SIPI stub
        //   0x00F000-0x00FFFF: SIPI stub
        //   0x800000-0x805FFF: zero-filled (must be pre-validated)
        //   0x806000-0x806FFF: initial stage 2 stack page
        //   0x806000-0x806FFF: Secrets page
        //   0x807000-0x807FFF: CPUID page
        //   0x808000-0x8nnnnn: stage 2 image
        //   0x8nnnnn-0x8nnnnn: IGVM parameter block
        //   0x8nnnnn-0x8nnnnn: general and memory map parameter pages
        //   0x8nnnnn-0x8nnnnn: filesystem
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
            if COMPATIBILITY_MASK.contains(TDP_COMPATIBILITY_MASK) {
                return Err("TDP platform requires --tdx-stage1".into());
            }
            GpaRange::new(0, 0)?
        };

        // Choose the kernel base and maximum size.
        let kernel = match options.hypervisor {
            Hypervisor::Qemu => {
                // Place the kernel area at 512 GB with a maximum size of 16 MB.
                GpaRange::new(0x0000008000000000, 0x01000000)?
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
        // Give the kernel at least 16 MiB
        let kernel_min_size = 0x1000000;
        // Make sure that kernel max size is page-aligned
        let kernel_max_size = u32::try_from(kernel.get_end() - kernel.get_start())?;
        if let Some(firmware) = firmware {
            let fw_info = firmware.get_fw_info();
            let fw_start = fw_info.start as u64;
            let fw_end = fw_start + fw_info.size as u64;
            let kernel_start = kernel.get_start();
            let kernel_max_end = kernel_start + kernel_max_size as u64;
            if fw_start < kernel_max_end && fw_end > kernel_start {
                return Err("Firmware region overlaps kernel region".into());
            }
        }

        // Determine the layout of the boot parameters.
        let boot_param_layout = BootParamLayout::new(firmware.is_some());

        // If stage2 is present, then get its size and configure the data it
        // requires.
        let (stage2_image, stage2_stack, boot_param_block, kernel_fs_start) =
            if let Some(ref stage2) = options.stage2 {
                let stage2_len = Self::get_metadata(stage2)?.len() as usize;
                if stage2_len > STAGE2_MAXLEN as usize {
                    return Err(format!(
                        "Stage2 binary size ({stage2_len:#x}) exceeds limit: {STAGE2_MAXLEN:#x}"
                    )
                    .into());
                }

                let stage2_image = GpaRange::new(STAGE2_START.into(), stage2_len as u64)?;
                let boot_param_block = GpaRange::new(
                    stage2_image.get_end(),
                    boot_param_layout.total_size() as u64,
                )?;
                (
                    stage2_image,
                    GpaRange::new_page(STAGE2_STACK_PAGE.into())?,
                    boot_param_block,
                    boot_param_block.get_end(),
                )
            } else {
                let stage2_image = GpaRange::new(STAGE2_BASE.into(), 0)?;
                (
                    stage2_image,
                    stage2_image,
                    GpaRange::new(0, 0)?,
                    stage2_image.get_start(),
                )
            };

        // Obtain the length of the kernel filesystem.
        let kernel_fs_len = if let Some(fs) = &options.filesystem {
            metadata(fs)?.len() as usize
        } else {
            0
        };

        // The kernel filesystem is placed after all other images so it can
        // mark the end of the valid stage2 memory area.
        let kernel_fs = GpaRange::new(kernel_fs_start, kernel_fs_len as u64)?;

        let (vmsa, vmsa_in_kernel_range) = match options.hypervisor {
            Hypervisor::Qemu | Hypervisor::Vanadium => {
                // VMSA address is currently hardcoded in kvm
                (GpaRange::new_page(0xFFFFFFFFF000)?, false)
            }
            Hypervisor::HyperV => (GpaRange::new_page(kernel.end - PAGE_SIZE_4K)?, true),
        };

        let gpa_map = Self {
            base_addr: STAGE2_BASE.into(),
            stage1_image,
            stage2_stack,
            stage2_image,
            cpuid_page: GpaRange::new_page(CPUID_PAGE.into())?,
            kernel_fs,
            boot_param_block,
            boot_param_layout,
            kernel,
            kernel_min_size,
            kernel_max_size,
            vmsa,
            vmsa_in_kernel_range,
            init_page_tables: GpaRange::new(0x10000, 2 * PAGE_SIZE_4K)?,
        };
        if options.verbose {
            println!("GPA Map: {gpa_map:#X?}");
        }
        Ok(gpa_map)
    }

    pub fn get_metadata(path: &String) -> Result<std::fs::Metadata, Box<dyn Error>> {
        let meta = metadata(path).inspect_err(|_| {
            eprintln!("Failed to access {path}");
        })?;
        Ok(meta)
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;
use std::fs::metadata;

use bootdefs::kernel_launch::BLDR_BASE;
use bootdefs::kernel_launch::BLDR_STACK_SIZE;
use bootdefs::kernel_launch::KERNEL_FS_BASE;

use igvm_defs::PAGE_SIZE_4K;

use crate::boot_params::BootParamLayout;
use crate::cmd_options::{CmdOptions, Hypervisor};
use crate::firmware::Firmware;
use crate::igvm_builder::COMPATIBILITY_MASK;
use crate::igvm_builder::TDP_COMPATIBILITY_MASK;

pub const INIT_PT_COUNT: usize = 4;

#[derive(Debug, Copy, Clone)]
pub struct GpaRange {
    start: u64,
    end: u64,
    size: u64,
    page_count: u64,
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
            page_count: page_size / PAGE_SIZE_4K,
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

    pub fn get_page_count(&self) -> u64 {
        self.page_count
    }
}

#[derive(Debug)]
struct GpaLayoutInfo {
    bldr_image: GpaRange,
    bldr_stack: GpaRange,
    init_page_tables: GpaRange,
    cpuid_page: u64,
    bldr_end: u64,
}

#[derive(Debug)]
pub struct GpaMap {
    pub stage1_image: GpaRange,
    pub bldr_stack: GpaRange,
    pub bldr_image: GpaRange,
    pub bldr_end: u64,
    pub cpuid_page: u64,
    pub kernel_fs: GpaRange,
    pub boot_param_layout: BootParamLayout,
    // The kernel region represents the maximum allowable size. The hypervisor may request that it
    // be smaller to save memory on smaller machine shapes. However, the entire region should not
    // overlap any other regions.
    pub kernel: GpaRange,
    pub kernel_min_size: u32,
    pub kernel_max_size: u32,
    pub ap_start_context_addr: u32,
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
        //   0x010000-0x01nnnn: boot loader image
        //   0x01nnnn-0x01nnnn: boot loader stack pages
        //   0x01nnnn-0x01nnnn: boot loader page tables
        //   0x01nnnn-0x01nnnn: CPUID page
        //   0x800000-0x8nnnnn: filesystem
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
        let (kernel_base, kernel_max_size) = match options.hypervisor {
            Hypervisor::Qemu => {
                // Place the kernel area at 512 GB with a maximum size of 16 MB.
                (0x0000008000000000, 0x01000000)
            }
            Hypervisor::HyperV => {
                // Place the kernel area at 64 MB with a maximum size of 16 MB.
                (0x04000000, 0x01000000)
            }
            Hypervisor::Vanadium => {
                // Place the kernel area at 8TiB-2GiB with a maximum size of 2 GiB.
                (0x7ff80000000, 0x80000000)
            }
        };
        // Give the kernel at least 16 MiB
        let kernel_min_size = 0x1000000;
        if let Some(firmware) = firmware {
            let fw_info = firmware.get_fw_info();
            let fw_start = fw_info.start as u64;
            let fw_end = fw_start + fw_info.size as u64;
            let kernel_max_end = kernel_base + kernel_max_size as u64;
            if fw_start < kernel_max_end && fw_end > kernel_base {
                return Err("Firmware region overlaps kernel region".into());
            }
        }

        // Determine the layout of the boot parameters.
        let include_guest_context = match firmware {
            Some(fw) => fw.get_guest_context().is_some(),
            None => false,
        };
        let boot_param_layout = BootParamLayout::new(include_guest_context);

        // If a boot loader is present, then get its size and configure the
        // data it requires.
        let gpa_layout_info = if let Some(bldr) = options.bldr.as_ref() {
            let bldr_len = Self::get_metadata(bldr)?.len() as usize;
            let bldr_image = GpaRange::new(BLDR_BASE.into(), bldr_len as u64)?;
            let bldr_stack = GpaRange::new(bldr_image.get_end(), BLDR_STACK_SIZE as u64)?;
            let init_page_tables =
                GpaRange::new(bldr_stack.get_end(), INIT_PT_COUNT as u64 * PAGE_SIZE_4K)?;
            let cpuid_page = init_page_tables.get_end();
            GpaLayoutInfo {
                bldr_image,
                bldr_stack,
                init_page_tables,
                cpuid_page,
                bldr_end: cpuid_page + PAGE_SIZE_4K,
            }
        } else {
            let empty_range = GpaRange::new(0, 0)?;
            GpaLayoutInfo {
                bldr_image: empty_range,
                bldr_stack: empty_range,
                init_page_tables: empty_range,
                cpuid_page: 0,
                bldr_end: 0,
            }
        };

        if let Some(firmware) = firmware {
            let fw_info = firmware.get_fw_info();
            let fw_start = fw_info.start as u64;
            if gpa_layout_info.bldr_end > fw_start {
                return Err("Boot loader overlaps firmware image".into());
            }
        }

        // Obtain the length of the kernel filesystem.
        let kernel_fs_len = if let Some(fs) = &options.filesystem {
            metadata(fs)?.len() as usize
        } else {
            0
        };

        // The kernel filesystem is placed after all other images so it can
        // mark the end of the valid boot loader memory area.
        let kernel_fs = GpaRange::new(KERNEL_FS_BASE as u64, kernel_fs_len as u64)?;

        let (vmsa, vmsa_in_kernel_range) = match options.hypervisor {
            Hypervisor::Qemu | Hypervisor::Vanadium => {
                // VMSA address is currently hardcoded in kvm
                (GpaRange::new_page(0xFFFFFFFFF000)?, false)
            }
            Hypervisor::HyperV => (
                GpaRange::new_page(kernel_base + kernel_min_size - PAGE_SIZE_4K)?,
                true,
            ),
        };

        let gpa_map = Self {
            stage1_image,
            bldr_stack: gpa_layout_info.bldr_stack,
            bldr_image: gpa_layout_info.bldr_image,
            bldr_end: gpa_layout_info.bldr_end,
            cpuid_page: gpa_layout_info.cpuid_page,
            kernel_fs,
            boot_param_layout,
            kernel: GpaRange::new(kernel_base, kernel_min_size)?,
            kernel_min_size: kernel_min_size.try_into().unwrap(),
            kernel_max_size,
            vmsa,
            vmsa_in_kernel_range,
            init_page_tables: gpa_layout_info.init_page_tables,
            // The first page of the boot loader stack can be used as an AP
            // start context location.  If there is no boot loader stack, then
            // zero signifies the lack of an AP start context.
            ap_start_context_addr: gpa_layout_info.bldr_stack.get_start().try_into().unwrap(),
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

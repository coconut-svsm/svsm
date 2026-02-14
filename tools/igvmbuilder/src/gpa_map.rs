// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;
use std::fs::metadata;

use bootdefs::kernel_launch::BLDR_BASE;
use bootdefs::kernel_launch::BLDR_MAXLEN;
use bootdefs::kernel_launch::BLDR_STACK_PAGE;
use bootdefs::kernel_launch::BLDR_START;
use bootdefs::kernel_launch::CPUID_PAGE;
use bootdefs::kernel_launch::SIPI_STUB_GPA;
use bootdefs::kernel_launch::SIPI_STUB_PT_GPA;

use igvm_defs::PAGE_SIZE_4K;

use crate::boot_params::BootParamLayout;
use crate::cmd_options::{CmdOptions, Hypervisor};
use crate::firmware::Firmware;
use crate::igvm_builder::ANY_NATIVE_COMPATIBILITY_MASK;
use crate::igvm_builder::COMPATIBILITY_MASK;
use crate::igvm_builder::TDP_COMPATIBILITY_MASK;

pub const LOWMEM_PT_START: u64 = 0x10000;
pub const LOWMEM_PT_COUNT: usize = 4;

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
    kernel_fs_start: u64,
}

#[derive(Debug)]
pub struct GpaMap {
    pub base_addr: u64,
    pub stage1_image: GpaRange,
    pub bldr_stack: GpaRange,
    pub bldr_image: GpaRange,
    pub cpuid_page: GpaRange,
    pub kernel_fs: GpaRange,
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
    pub sipi_stub: GpaRange,
    pub sipi_compat_mask: u32,
}

impl GpaMap {
    pub fn new(
        options: &CmdOptions,
        firmware: &Option<Box<dyn Firmware>>,
    ) -> Result<Self, Box<dyn Error>> {
        //   0x00D000-0x00EFFF: initial page tables for SIPI stub
        //   0x00F000-0x00FFFF: SIPI stub
        //   0x800000-0x805FFF: zero-filled (must be pre-validated)
        //   0x806000-0x806FFF: initial boot loader stack page
        //   0x807000-0x807FFF: CPUID page
        //   0x808000-0x8nnnnn: boot loader image
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
            if bldr_len > BLDR_MAXLEN as usize {
                return Err(format!(
                    "Boot loader binary size ({bldr_len:#x}) exceeds limit: {BLDR_MAXLEN:#x}"
                )
                .into());
            }

            let bldr_image = GpaRange::new(BLDR_START.into(), bldr_len as u64)?;
            GpaLayoutInfo {
                bldr_image,
                bldr_stack: GpaRange::new_page(BLDR_STACK_PAGE.into())?,
                kernel_fs_start: bldr_image.get_end(),
                init_page_tables: GpaRange::new(
                    LOWMEM_PT_START,
                    LOWMEM_PT_COUNT as u64 * PAGE_SIZE_4K,
                )?,
            }
        } else {
            let bldr_image = GpaRange::new(BLDR_BASE.into(), 0)?;
            GpaLayoutInfo {
                bldr_image,
                bldr_stack: bldr_image,
                kernel_fs_start: bldr_image.get_end(),
                init_page_tables: GpaRange::new(0, 0)?,
            }
        };
        // Obtain the length of the kernel filesystem.
        let kernel_fs_len = if let Some(fs) = &options.filesystem {
            metadata(fs)?.len() as usize
        } else {
            0
        };

        // The kernel filesystem is placed after all other images so it can
        // mark the end of the valid boot loader memory area.
        let kernel_fs = GpaRange::new(gpa_layout_info.kernel_fs_start, kernel_fs_len as u64)?;

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

        // If the target includes a non-isolated platform, then insert the
        // SIPI startup stub.  Also include the SIPI stub with TDX since it is
        // used for AP startup.
        let sipi_compat_mask = ANY_NATIVE_COMPATIBILITY_MASK | TDP_COMPATIBILITY_MASK;
        let sipi_stub = if COMPATIBILITY_MASK.contains(sipi_compat_mask) {
            GpaRange::new(
                SIPI_STUB_PT_GPA as u64,
                SIPI_STUB_GPA as u64 + PAGE_SIZE_4K - SIPI_STUB_PT_GPA as u64,
            )?
        } else {
            GpaRange::new(0, 0)?
        };

        let gpa_map = Self {
            base_addr: BLDR_BASE.into(),
            stage1_image,
            bldr_stack: gpa_layout_info.bldr_stack,
            bldr_image: gpa_layout_info.bldr_image,
            cpuid_page: GpaRange::new_page(CPUID_PAGE.into())?,
            kernel_fs,
            boot_param_layout,
            kernel: GpaRange::new(kernel_base, kernel_min_size)?,
            kernel_min_size: kernel_min_size.try_into().unwrap(),
            kernel_max_size,
            sipi_stub,
            sipi_compat_mask,
            vmsa,
            vmsa_in_kernel_range,
            init_page_tables: gpa_layout_info.init_page_tables,
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

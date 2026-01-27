// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes};

// The SIPI stub is placed immediately below the stage 2 heap.
pub const SIPI_STUB_GPA: u32 = 0xF000;

// Two pages below the SIPI stub are used for low memory page tables.
pub const SIPI_STUB_PT_GPA: u32 = 0xD000;

// The first 640 KB of RAM (low memory)
pub const LOWMEM_END: u32 = 0xA0000;

pub const STAGE2_HEAP_START: u32 = 0x10000; // 64 KB
pub const STAGE2_HEAP_END: u32 = LOWMEM_END; // 640 KB
pub const STAGE2_BASE: u32 = 0x800000; // Start of stage2 area excluding heap
pub const STAGE2_STACK_END: u32 = STAGE2_BASE;
pub const STAGE2_STACK_PAGE: u32 = 0x805000;
pub const STAGE2_INFO_SZ: u32 = size_of::<Stage2LaunchInfo>() as u32;
pub const STAGE2_STACK: u32 = STAGE2_STACK_PAGE + 0x1000 - STAGE2_INFO_SZ;
pub const SECRETS_PAGE: u32 = 0x806000;
pub const CPUID_PAGE: u32 = 0x807000;
// Stage2 is loaded at 8 MB + 32 KB
pub const STAGE2_START: u32 = 0x808000;
pub const STAGE2_MAXLEN: u32 = 0x8D0000 - STAGE2_START;

#[derive(Copy, Clone, Debug, Immutable, IntoBytes)]
#[repr(C)]
pub struct KernelLaunchInfo {
    /// Start of the kernel in physical memory.
    pub kernel_region_phys_start: u64,
    /// Exclusive end of the kernel in physical memory.
    pub kernel_region_phys_end: u64,
    pub heap_area_phys_start: u64, // Start of trailing heap area within the physical memory region.
    pub heap_area_page_count: u64,
    pub heap_area_allocated: u64,
    pub kernel_region_virt_start: u64,
    pub heap_area_virt_start: u64, // Start of virtual heap area mapping.
    pub kernel_fs_start: u64,
    pub kernel_fs_end: u64,
    pub stage2_start: u64,
    pub cpuid_page: u64,
    pub secrets_page: u64,
    pub boot_params_virt_addr: u64,
    pub kernel_symtab_start: u64,
    pub kernel_symtab_len: u64,
    pub kernel_strtab_start: u64,
    pub kernel_strtab_len: u64,
    pub vtom: u64,
    pub kernel_page_table_vaddr: u64,
    pub debug_serial_port: u16,
    pub vmsa_in_kernel_heap: bool,
    pub use_alternate_injection: bool,
    pub suppress_svsm_interrupts: bool,
    pub _reserved: [bool; 3],
}

pub const INITIAL_KERNEL_STACK_WORDS: usize = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug, Immutable, IntoBytes)]
pub struct InitialKernelStack {
    // These fields are referenced by assembly and must remain in this order
    // unless the kernel start function is updated to match.
    pub _reserved: [u64; 512 - INITIAL_KERNEL_STACK_WORDS],
    pub paging_root: u64,
    pub launch_info_vaddr: u64,
    pub stack_limit: u64,
}

// Stage 2 launch info from stage1
// The layout has to match the order in which the parts are pushed to the stack
// in stage1.rs
#[derive(IntoBytes, Immutable, Default, Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Stage2LaunchInfo {
    pub platform_type: u32,
    pub cpuid_page: u32,
    pub secrets_page: u32,
    pub kernel_pml4e_index: u32,

    pub kernel_page_tables_base: u64,
    pub kernel_pt_pages: u64,
    pub kernel_boot_params_addr: u64,
    pub kernel_cpuid_addr: u64,
    pub kernel_secrets_addr: u64,

    pub kernel_entry: u64,
    pub kernel_stack: u64,
    pub kernel_pdpt_paddr: u64,
    pub kernel_launch_info: u64,

    pub stage2_end: u32,
    pub kernel_fs_start: u32,
    pub kernel_fs_end: u32,
    pub boot_params: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
pub struct ApStartContext {
    // All fields of this context must remain in the same order because they
    // are referenced from assembly.
    pub cr0: usize,
    pub cr3: usize,
    pub cr4: usize,
    pub efer: usize,
    pub start_rip: usize,
    pub rsp: usize,
    pub initial_rip: usize,
    pub transition_cr3: u32,
    pub context_size: u32,
}

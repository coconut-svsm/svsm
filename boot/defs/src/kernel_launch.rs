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
pub const BLDR_BASE: u32 = 0x800000; // Start of boot loader area excluding heap
pub const BLDR_STACK_END: u32 = BLDR_BASE;
pub const BLDR_STACK_PAGE: u32 = 0x806000;
pub const BLDR_INFO_SZ: u32 = size_of::<BldrLaunchInfo>() as u32;
pub const BLDR_STACK: u32 = BLDR_STACK_PAGE + 0x1000 - BLDR_INFO_SZ;
pub const CPUID_PAGE: u32 = 0x807000;
// Stage2 is loaded at 8 MB + 32 KB
pub const BLDR_START: u32 = 0x808000;
pub const BLDR_MAXLEN: u32 = 0x8D0000 - BLDR_START;

#[derive(Copy, Clone, Debug, Immutable, IntoBytes)]
#[repr(C)]
pub struct KernelLaunchInfo {
    /// Start of the kernel in physical memory.
    pub kernel_region_phys_start: u64,
    /// Exclusive end of the kernel in physical memory.
    pub kernel_region_phys_end: u64,
    pub heap_area_offset: u64, // physical offset to kernel heap
    pub heap_area_allocated: u64,
    pub kernel_region_virt_start: u64,
    pub kernel_direct_map_vaddr: u64,
    pub kernel_fs_start: u64,
    pub kernel_fs_end: u64,
    pub bldr_start: u64,
    pub cpuid_page: u64,
    pub secrets_page: u64,
    pub idt_vaddr: u64,
    pub boot_params_virt_addr: u64,
    pub kernel_symtab_start: u64,
    pub kernel_symtab_len: u64,
    pub kernel_strtab_start: u64,
    pub kernel_strtab_len: u64,
    pub vtom: u64,
    pub kernel_page_table_vaddr: u64,
    pub lowmem_page_table_paddr: u32,
    pub lowmem_page_table_count: u32,
    pub debug_serial_port: u16,
    pub vmsa_in_kernel_heap: bool,
    pub use_alternate_injection: bool,
    pub suppress_svsm_interrupts: bool,
    pub lowmem_validated: bool,
    pub _reserved: [bool; 2],
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

// This structure describes the parameters passed to the boot loader.
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct BldrLaunchInfo {
    pub kernel_pdpt_paddr: u64,
    pub kernel_launch_info: u64,
    pub kernel_entry: u64,
    pub kernel_stack: u64,
    pub kernel_pt_paddr: u64,
    pub kernel_pt_count: u64,
    pub page_table_map_vaddr: u64,
    pub page_table_start: u32,
    pub page_table_end: u32,
    pub page_table_root: u32,
    pub cpuid_addr: u32,
    pub platform_type: u32,
    pub c_bit_position: u32,
    pub kernel_pml4e_index: u32,
    pub _reserved: u32,
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

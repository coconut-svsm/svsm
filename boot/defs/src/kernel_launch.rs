// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use zerocopy::{FromBytes, Immutable, IntoBytes};

pub const BLDR_BASE: u32 = 0x10000; // Start of boot loader area: 64 KB
pub const BLDR_STACK_SIZE: u32 = 0x6000; // Size of boot loader stack: 24 KB
pub const KERNEL_FS_BASE: u32 = 0x800000; // start of kernel filesystem: 8 MB

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
    pub bldr_end: u64,
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
    pub ap_start_context_addr: u32,
    pub debug_serial_port: u16,
    pub vmsa_in_kernel_heap: bool,
    pub use_alternate_injection: bool,
    pub suppress_svsm_interrupts: bool,
    pub _reserved: [bool; 7],
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
    pub ap_start_context_addr: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes)]
pub struct ApStartContext {
    pub cr0: usize,
    pub cr3: usize,
    pub cr4: usize,
    pub efer: usize,
    pub start_rip: usize,
    pub rsp: usize,
    pub initial_rip: usize,
}

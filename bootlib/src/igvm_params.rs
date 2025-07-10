// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

//! This crate provides definitions of IGVM parameters to be parsed by
//! COCONUT-SVSM to determine its configuration.

use zerocopy::{Immutable, IntoBytes};

/// The IGVM parameter page is an unmeasured page containing individual
/// parameters that are provided by the host loader.
#[repr(C, packed)]
#[derive(IntoBytes, Clone, Copy, Debug, Default)]
pub struct IgvmParamPage {
    /// The number of vCPUs that are configured for the guest VM.
    pub cpu_count: u32,

    /// The environment informatiom supplied to describe the execution
    /// environment.  This is defined as a u32 and is converted to an
    /// IgvmEnvironmentInfo when it is used.
    pub environment_info: u32,
}

/// An entry that represents an area of pre-validated memory defined by the
/// firmware in the IGVM file.
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Clone, Copy, Debug, Default)]
pub struct IgvmParamBlockFwMem {
    /// The base physical address of the prevalidated memory region.
    pub base: u32,

    /// The length of the prevalidated memory region in bytes.
    pub size: u32,
}

/// The portion of the IGVM parameter block that describes metadata about
/// the firmware image embedded in the IGVM file.
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Clone, Copy, Debug, Default)]
pub struct IgvmParamBlockFwInfo {
    /// The guest physical address of the start of the guest firmware. The
    /// permissions on the pages in the firmware range are adjusted to the guest
    /// VMPL. If this field is zero then no firmware is launched after
    /// initialization is complete.
    pub start: u32,

    /// The size of the guest firmware in bytes. If the firmware size is zero then
    /// no firmware is launched after initialization is complete.
    pub size: u32,

    /// Indicates that the initial location of firmware is at the base of
    /// memory and will not be loaded into the ROM range.
    pub in_low_memory: u8,

    #[doc(hidden)]
    pub _reserved: [u8; 7],

    /// The guest physical address at which the firmware expects to find the
    /// secrets page.
    pub secrets_page: u32,

    /// The guest physical address at which the firmware expects to find the
    /// calling area page.
    pub caa_page: u32,

    /// The guest physical address at which the firmware expects to find the
    /// CPUID page.
    pub cpuid_page: u32,

    /// The guest physical address of the IGVM memory map consumed by the
    /// guest firmware.
    pub memory_map_page: u32,

    /// The number of pages reserved for the IGVM memory map consumed by the
    /// guest firmware.
    pub memory_map_page_count: u32,

    /// The number of prevalidated memory regions defined by the firmware.
    pub prevalidated_count: u32,

    /// The prevalidated memory regions defined by the firmware.
    pub prevalidated: [IgvmParamBlockFwMem; 8],
}

/// The IGVM parameter block is a measured page constructed by the IGVM file
/// builder which describes where the additional IGVM parameter information
/// has been placed into the guest address space.
#[repr(C, packed)]
#[derive(IntoBytes, Immutable, Clone, Copy, Debug, Default)]
pub struct IgvmParamBlock {
    /// The total size of the parameter area, beginning with the parameter
    /// block itself and including any additional parameter pages which follow.
    pub param_area_size: u32,

    /// The offset, in bytes, from the base of the parameter block to the base
    /// of the parameter page.
    pub param_page_offset: u32,

    /// The offset, in bytes, from the base of the parameter block to the base
    /// of the host-supplied MADT.
    pub madt_offset: u32,

    /// The size, in bytes, of the MADT area.
    pub madt_size: u32,

    /// The offset, in bytes, from the base of the parameter block to the base
    /// of the memory map (which is in IGVM format).
    pub memory_map_offset: u32,

    /// The offset, in bytes, of the guest context, or zero if no guest
    /// context is present.
    pub guest_context_offset: u32,

    /// The port number of the serial port to use for debugging.
    pub debug_serial_port: u16,

    /// Indicates whether the guest can support alternate injection.
    pub use_alternate_injection: u8,

    /// Indicates whether SVSM should suppress interrupts when running on SEV-SNP.
    pub suppress_svsm_interrupts_on_snp: u8,

    /// Indicates whether SVSM can assume that the qemu testdev device exists to assist testing.
    pub has_qemu_testdev: u8,

    /// Indicates whether SVSM should use an IO port to read the qemu FwCfg.
    pub has_fw_cfg_port: u8,

    /// Indicates whether SVSM can use "IORequest"s to assist with testing.
    pub has_test_iorequests: u8,

    #[doc(hidden)]
    pub _reserved: [u8; 1],

    /// Metadata containing information about the firmware image embedded in the
    /// IGVM file.
    pub firmware: IgvmParamBlockFwInfo,

    /// The number of bytes for the stage1 bootloader
    pub stage1_size: u32,

    #[doc(hidden)]
    pub _reserved2: u32,

    /// The guest physical address of the base of the stage1 bootloader
    pub stage1_base: u64,

    /// The amount of space that must be reserved at the base of the kernel
    /// memory region (e.g. for VMSA contents).
    pub kernel_reserved_size: u32,

    /// The guest physical address of the base of the kernel memory region.
    pub kernel_base: u64,

    /// The minimum size to allocate for the kernel in bytes. If the hypervisor supplies a memory
    /// region in the memory map that starts at kernel_base and is larger, that size will be used
    /// instead.
    pub kernel_min_size: u32,

    /// The maximum size to allocate for the kernel in bytes. If the hypervisor supplies a memory
    /// region in the memory map that starts at kernel_base and is larger, this maximum size will
    /// be used instead.
    pub kernel_max_size: u32,

    /// The value of vTOM used by the guest, or zero if not used.
    pub vtom: u64,
}

const _: () = {
    // Assert that the reserved fields are properly aligning the rest of the fields.
    assert!(core::mem::offset_of!(IgvmParamBlock, firmware) % 4 == 0);
    assert!(core::mem::offset_of!(IgvmParamBlock, stage1_base) % 8 == 0);
};

/// The IGVM context page is a measured page that is used to specify the start
/// context for the guest VMPL.  If present, it overrides the processor state
/// initialized at reset.
#[derive(IntoBytes, Immutable, Copy, Debug, Clone, Default)]
#[repr(C, packed)]
pub struct IgvmGuestContext {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub gdt_base: u64,
    pub gdt_limit: u32,
    pub code_selector: u16,
    pub data_selector: u16,
    pub rip: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

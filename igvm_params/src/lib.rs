// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

//! This crate provides definitions of IGVM parameters to be parsed by
//! COCONUT-SVSM to determine its configuration.  It is provided as a separate
//! crate since the same definitions must be known to the utility that
//! constructs the IGVM file.

#![no_std]

/// The IGVM parameter page is an unmeasured page containing individual
/// parameters that are provided by the host loader.
#[repr(C, packed)]
#[derive(Clone, Debug)]
pub struct IgvmParamPage {
    /// The number of vCPUs that are configured for the guest VM.
    pub cpu_count: u32,

    /// The environment informatiom supplied to describe the execution
    /// environment.  This is defined as a u32 and is converted to an
    /// IgvmEnvironmentInfo when it is used.
    pub environment_info: u32,
}

/// The IGVM parameter block is a measured page constructed by the IGVM file
/// builder which describes where the additional IGVM parameter information
/// has been placed into the guest address space.
#[repr(C, packed)]
#[derive(Clone, Debug)]
pub struct IgvmParamBlock {
    /// The total size of the parameter area, beginning with the parameter
    /// block itself and including any additional parameter pages which follow.
    pub param_area_size: u32,

    /// The offset, in bytes, from the base of the parameter block to the base
    /// of the parameter page.
    pub param_page_offset: u32,

    /// The offset, in bytes, from the base of the parameter block to the base
    /// of the memory map (which is in IGVM format).
    pub memory_map_offset: u32,

    /// The guest physical address of the CPUID page.
    pub cpuid_page: u32,

    /// The guest physical address of the secrets page.
    pub secrets_page: u32,

    /// The port number of the serial port to use for debugging.
    pub debug_serial_port: u16,

    _reserved: u16,

    /// The guest physical address of the start of the guest firmware. The
    /// permissions on the pages in the firmware range are adjusted to the guest
    /// VMPL. If this field is zero then no firmware is launched after
    /// initialization is complete.
    pub fw_start: u32,

    /// The number of pages of guest firmware. If the firmware size is zero then
    /// no firmware is launched after initialization is complete.
    pub fw_size: u32,

    /// The guest physical address of the page that contains metadata that
    /// corresponds to the firmware. The SVSM expects the page to contain
    /// metadata in the format defined by OVMF. If this field is zero but
    /// a firmware range has been provided then the firmware is launched
    /// without parsing any metadata.
    pub fw_metadata: u32,

    _reserved2: u32,

    /// The amount of space that must be reserved at the base of the kernel
    /// memory region (e.g. for VMSA contents).
    pub kernel_reserved_size: u32,

    /// The number of bytes in the kernel memory region.
    pub kernel_size: u32,

    /// The guest physical address of the base of the kernel memory region.
    pub kernel_base: u64,
}

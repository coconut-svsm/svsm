// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use core::error::Error;
use core::fmt;
use core::fmt::Display;

/// Define a simple error type to describe the error results from boot image
/// operations.
#[derive(Clone, Copy, Debug)]
pub enum BootImageError {
    Elf,
    ElfRelocs,
    ElfAlignment,
    ElfSymbols,
    SelfMapConflict,
    KernelRangeTooLarge,
    BadKernelAddress,
    KernelTooBig,
    HeapTooSmall,
    Host,
}

impl Error for BootImageError {}

impl Display for BootImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            BootImageError::Elf => {
                write!(f, "Failed to parse kernel ELF file")
            }
            BootImageError::ElfRelocs => {
                write!(f, "Kernel address range conflict with self map")
            }
            BootImageError::ElfAlignment => {
                write!(f, "Kernel virtual address span does not fit within 1 GB")
            }
            BootImageError::ElfSymbols => {
                write!(f, "Elf symbol information is corrupt")
            }
            BootImageError::SelfMapConflict => {
                write!(f, "Kernel virtual address out of bounds")
            }
            BootImageError::KernelRangeTooLarge => {
                write!(f, "Insufficient physical memory for kernel image")
            }
            BootImageError::BadKernelAddress => {
                write!(f, "Kernel heap too small")
            }
            BootImageError::KernelTooBig => {
                write!(f, "Failed to apply ELF relocations")
            }
            BootImageError::HeapTooSmall => {
                write!(f, "Kernel ELF segment is not aligned")
            }
            BootImageError::Host => {
                write!(f, "See previous error")
            }
        }
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::address::{PhysAddr, VirtAddr};
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::percpu::PerCpu;
use crate::error::SvsmError;
use crate::platform::{IOPort, PageEncryptionMasks, PageStateChangeOp, SvsmPlatform};
use crate::svsm_console::NativeIOPort;
use crate::types::PageSize;
use crate::utils::MemoryRegion;

static CONSOLE_IO: NativeIOPort = NativeIOPort::new();

#[derive(Clone, Copy, Debug)]
pub struct NativePlatform {}

impl NativePlatform {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for NativePlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl SvsmPlatform for NativePlatform {
    fn env_setup(&mut self) {}
    fn env_setup_late(&mut self) {}

    fn setup_percpu(&self, _cpu: &PerCpu) -> Result<(), SvsmError> {
        Ok(())
    }

    fn setup_percpu_current(&self, _cpu: &PerCpu) -> Result<(), SvsmError> {
        Ok(())
    }

    fn get_page_encryption_masks(&self, _vtom: usize) -> PageEncryptionMasks {
        // Find physical address size.
        let res = CpuidResult::get(0x80000008, 0);
        PageEncryptionMasks {
            private_pte_mask: 0,
            shared_pte_mask: 0,
            addr_mask_width: 64,
            phys_addr_sizes: res.eax,
        }
    }

    fn setup_guest_host_comm(&mut self, _cpu: &PerCpu, _is_bsp: bool) {}

    fn get_console_io_port(&self) -> &'static dyn IOPort {
        &CONSOLE_IO
    }

    fn page_state_change(
        &self,
        _region: MemoryRegion<PhysAddr>,
        _size: PageSize,
        _op: PageStateChangeOp,
    ) -> Result<(), SvsmError> {
        Ok(())
    }

    /// Marks a range of pages as valid for use as private pages.
    fn validate_page_range(&self, _region: MemoryRegion<VirtAddr>) -> Result<(), SvsmError> {
        Ok(())
    }

    /// Marks a range of pages as invalid for use as private pages.
    fn invalidate_page_range(&self, _region: MemoryRegion<VirtAddr>) -> Result<(), SvsmError> {
        Ok(())
    }

    fn eoi(&self) {
        todo!();
    }
}

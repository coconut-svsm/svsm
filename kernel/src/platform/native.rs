// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::cpu::cpuid::CpuidResult;
use crate::cpu::percpu::PerCpu;
use crate::platform::{IOPort, PageEncryptionMasks, PhysAddr, SvsmError, SvsmPlatform, VirtAddr};
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

    fn setup_percpu(&self, _cpu: &mut PerCpu) -> Result<(), SvsmError> {
        Ok(())
    }

    fn setup_percpu_current(&self, _cpu: &mut PerCpu) -> Result<(), SvsmError> {
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

    fn setup_guest_host_comm(&mut self, _cpu: &mut PerCpu, _is_bsp: bool) {}

    fn get_console_io_port(&self) -> &'static dyn IOPort {
        &CONSOLE_IO
    }

    fn page_state_change(
        &self,
        _start: PhysAddr,
        _end: PhysAddr,
        _size: PageSize,
        _make_private: bool,
    ) -> Result<(), SvsmError> {
        Ok(())
    }

    fn pvalidate_range(
        &self,
        _region: MemoryRegion<VirtAddr>,
        _valid: bool,
    ) -> Result<(), SvsmError> {
        Ok(())
    }
}

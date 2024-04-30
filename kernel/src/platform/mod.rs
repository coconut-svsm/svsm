// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::address::{PhysAddr, VirtAddr};
use crate::cpu::percpu::PerCpu;
use crate::error::SvsmError;
use crate::io::IOPort;
use crate::platform::native::NativePlatform;
use crate::platform::snp::SnpPlatform;
use crate::sev::PvalidateOp;
use crate::types::PageSize;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use crate::utils::MemoryRegion;

use bootlib::platform::SvsmPlatformType;

pub mod native;
pub mod snp;

pub static SVSM_PLATFORM: ImmutAfterInitCell<SvsmPlatformCell> = ImmutAfterInitCell::uninit();

#[derive(Clone, Copy, Debug)]
pub struct PageEncryptionMasks {
    pub private_pte_mask: usize,
    pub shared_pte_mask: usize,
    pub addr_mask_width: u32,
    pub phys_addr_sizes: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum PageStateChangeOp {
    Private,
    Shared,
    Psmash,
    Unsmash,
}

/// This defines a platform abstraction to permit the SVSM to run on different
/// underlying architectures.
pub trait SvsmPlatform {
    /// Performs basic early initialization of the runtime environment.
    fn env_setup(&mut self);

    /// Performs initialization of the platform runtime environment after
    /// console logging has been initialized.
    fn env_setup_late(&mut self);

    /// Completes initialization of a per-CPU object during construction.
    fn setup_percpu(&self, cpu: &mut PerCpu) -> Result<(), SvsmError>;

    /// Completes initialization of a per-CPU object on the target CPU.
    fn setup_percpu_current(&self, cpu: &mut PerCpu) -> Result<(), SvsmError>;

    /// Determines the paging encryption masks for the current architecture.
    fn get_page_encryption_masks(&self, vtom: usize) -> PageEncryptionMasks;

    /// Establishes state required for guest/host communication.
    fn setup_guest_host_comm(&mut self, cpu: &mut PerCpu, is_bsp: bool);

    /// Obtains a console I/O port reference.
    fn get_console_io_port(&self) -> &'static dyn IOPort;

    /// Performs a page state change between private and shared states.
    fn page_state_change(
        &self,
        region: MemoryRegion<PhysAddr>,
        size: PageSize,
        op: PageStateChangeOp,
    ) -> Result<(), SvsmError>;

    /// Marks a page as valid or invalid as a private page.
    fn pvalidate_range(
        &self,
        region: MemoryRegion<VirtAddr>,
        op: PvalidateOp,
    ) -> Result<(), SvsmError>;

    /// Perform an EOI of the current interrupt.
    fn eoi(&self);
}

//FIXME - remove Copy trait
#[derive(Clone, Copy, Debug)]
pub enum SvsmPlatformCell {
    Snp(SnpPlatform),
    Native(NativePlatform),
}

impl SvsmPlatformCell {
    pub fn new(platform_type: SvsmPlatformType) -> Self {
        match platform_type {
            SvsmPlatformType::Native => SvsmPlatformCell::Native(NativePlatform::new()),
            SvsmPlatformType::Snp => SvsmPlatformCell::Snp(SnpPlatform::new()),
        }
    }

    pub fn as_dyn_ref(&self) -> &dyn SvsmPlatform {
        match self {
            SvsmPlatformCell::Native(platform) => platform,
            SvsmPlatformCell::Snp(platform) => platform,
        }
    }

    pub fn as_mut_dyn_ref(&mut self) -> &mut dyn SvsmPlatform {
        match self {
            SvsmPlatformCell::Native(platform) => platform,
            SvsmPlatformCell::Snp(platform) => platform,
        }
    }
}

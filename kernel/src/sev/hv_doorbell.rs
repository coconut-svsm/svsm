// SPDX-License-Identifier: MIT OR Apache-2.0 Copyright (c) Microsoft Corporation
// Author: Jon Lange (jlange@microsoft.com)

use crate::address::VirtAddr;
use crate::error::SvsmError;
use crate::mm::page_visibility::{make_page_private, make_page_shared};
use crate::mm::virt_to_phys;
use crate::sev::ghcb::GHCB;

use core::sync::atomic::AtomicU8;

#[repr(C)]
#[derive(Debug)]
pub struct HVDoorbell {
    pub vector: AtomicU8,
    pub flags: AtomicU8,
    pub no_eoi_required: AtomicU8,
    reserved: u8,
}

impl HVDoorbell {
    pub fn init(vaddr: VirtAddr, ghcb: &mut GHCB) -> Result<(), SvsmError> {
        // The #HV doorbell page must be private before it can be used.
        make_page_shared(vaddr)?;

        // Register the #HV doorbell page using the GHCB protocol.
        let paddr = virt_to_phys(vaddr);
        ghcb.register_hv_doorbell(paddr).map_err(|e| {
            // Return the page to a private state.
            make_page_private(vaddr).expect("Failed to restore page visibility");
            e
        })?;

        Ok(())
    }
}

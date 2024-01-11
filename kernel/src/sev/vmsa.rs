// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::utils::{rmp_adjust, RMPFlags};
use crate::address::{Address, VirtAddr};
use crate::error::SvsmError;
use crate::mm::alloc::{allocate_pages, free_page};
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::zero_mem_region;

use cpuarch::vmsa::VMSA;

pub const VMPL_MAX: usize = 4;

pub fn allocate_new_vmsa(vmpl: RMPFlags) -> Result<VirtAddr, SvsmError> {
    assert!(vmpl.bits() < (VMPL_MAX as u64));

    // Make sure the VMSA page is not 2M aligned. Some hardware generations
    // can't handle this properly.
    let mut vmsa_page = allocate_pages(0)?;
    if vmsa_page.is_aligned(PAGE_SIZE_2M) {
        free_page(vmsa_page);
        vmsa_page = allocate_pages(1)?;
        if vmsa_page.is_aligned(PAGE_SIZE_2M) {
            vmsa_page = vmsa_page + PAGE_SIZE;
        }
    }

    zero_mem_region(vmsa_page, vmsa_page + PAGE_SIZE);

    if let Err(e) = rmp_adjust(vmsa_page, RMPFlags::VMSA | vmpl, PageSize::Regular) {
        free_page(vmsa_page);
        return Err(e);
    }
    Ok(vmsa_page)
}

pub fn free_vmsa(vaddr: VirtAddr) {
    rmp_adjust(vaddr, RMPFlags::RWX | RMPFlags::VMPL0, PageSize::Regular)
        .expect("Failed to free VMSA page");
    free_page(vaddr);
}

pub trait VMSAControl {
    fn enable(&mut self);
    fn disable(&mut self);
}

impl VMSAControl for VMSA {
    fn enable(&mut self) {
        self.efer |= 1u64 << 12;
    }

    fn disable(&mut self) {
        self.efer &= !(1u64 << 12);
    }
}

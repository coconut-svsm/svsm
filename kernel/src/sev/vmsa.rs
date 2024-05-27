// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::utils::{rmp_adjust, RMPFlags};
use crate::address::{Address, PhysAddr};
use crate::error::SvsmError;
use crate::mm::pagebox::{PageBox, RawPageBox};
use crate::mm::virt_to_phys;
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use cpuarch::vmsa::VMSA;

pub const VMPL_MAX: usize = 4;

/// A page allocation for a VMSA. When dropped, the backing memory will be
/// `RMPADJUST`-ed for VMPL 0.
#[derive(Debug)]
pub struct VmsaPage(PageBox<VMSA>);

impl VmsaPage {
    /// Allocates a new VMSA for the given VPML.
    pub fn new(vmpl: RMPFlags) -> Result<Self, SvsmError> {
        assert!(vmpl.bits() < (VMPL_MAX as u64));

        let mut page = RawPageBox::new(0)?;
        // Make sure the VMSA page is not 2M aligned. Some hardware generations
        // can't handle this properly.
        while page.vaddr().is_aligned(PAGE_SIZE_2M) {
            // Allocate a new page before dropping the previous one
            let new_page = RawPageBox::new(0)?;
            page = new_page;
        }

        // SAFETY: we allocated an order 0 (4k) page, so memory must be valid.
        unsafe { page.as_mut_ptr().write_bytes(0, PAGE_SIZE) };
        rmp_adjust(page.vaddr(), RMPFlags::VMSA | vmpl, PageSize::Regular)?;

        // SAFETY: a `VMSA` fits within an order 0 (4k) page.
        let vmsa = unsafe { PageBox::from_raw(page) };
        Ok(Self(vmsa))
    }

    /// Retrieves the physical address of this VMSA.
    #[inline]
    pub fn paddr(&self) -> PhysAddr {
        virt_to_phys(self.0.as_raw().vaddr())
    }

    /// Leaks the allocation for this VMSA, ensuring it never gets freed.
    pub fn leak(self) -> &'static mut VMSA {
        let mut vmsa = ManuallyDrop::new(self);
        let ptr = core::ptr::from_mut(&mut vmsa);
        // SAFETY: this pointer will never be freed because of ManuallyDrop,
        // so we can create a static mutable reference. We go through a raw
        // pointer to promote the lifetime to static.
        unsafe { &mut *ptr }
    }
}

impl Deref for VmsaPage {
    type Target = VMSA;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl DerefMut for VmsaPage {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}

impl Drop for VmsaPage {
    fn drop(&mut self) {
        let vaddr = self.0.as_raw().vaddr();
        rmp_adjust(vaddr, RMPFlags::RWX | RMPFlags::VMPL0, PageSize::Regular)
            .expect("Failed to adjust RMP for VMSA page");
    }
}

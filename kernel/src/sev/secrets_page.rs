// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::VirtAddr;
use crate::locking::{RWLock, ReadLockGuard, WriteLockGuard};
use crate::protocols::core::CORE_PROTOCOL_VERSION_MAX;
use crate::sev::vmsa::VMPL_MAX;
use crate::types::GUEST_VMPL;

extern crate alloc;
use alloc::boxed::Box;
use core::ops::{Deref, DerefMut};
use core::ptr;

pub const VMPCK_SIZE: usize = 32;

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct SecretsPage {
    version: u32,
    gctxt: u32,
    fms: u32,
    reserved_00c: u32,
    gosvw: [u8; 16],
    vmpck: [[u8; VMPCK_SIZE]; VMPL_MAX],
    reserved_0a0: [u8; 96],
    vmsa_tweak_bmp: [u64; 8],
    svsm_base: u64,
    svsm_size: u64,
    svsm_caa: u64,
    svsm_max_version: u32,
    svsm_guest_vmpl: u8,
    reserved_15d: [u8; 3],
    tsc_factor: u32,
    reserved_164: [u8; 3740],
}

impl SecretsPage {
    pub const fn new() -> Self {
        Self {
            version: 0,
            gctxt: 0,
            fms: 0,
            reserved_00c: 0,
            gosvw: [0; 16],
            vmpck: [[0; VMPCK_SIZE]; VMPL_MAX],
            reserved_0a0: [0; 96],
            vmsa_tweak_bmp: [0; 8],
            svsm_base: 0,
            svsm_size: 0,
            svsm_caa: 0,
            svsm_max_version: 0,
            svsm_guest_vmpl: 0,
            reserved_15d: [0; 3],
            tsc_factor: 0,
            reserved_164: [0; 3740],
        }
    }

    /// Copy secrets page's content pointed by a [`VirtAddr`]
    ///
    /// # Safety
    ///
    /// The caller should verify that `source` points to mapped memory whose
    /// size is at least the size of the [`SecretsPage`] structure.
    pub unsafe fn copy_from(&mut self, source: VirtAddr) {
        let from = source.as_ptr::<SecretsPage>();

        // SAFETY: demanded to the caller
        unsafe {
            from.copy_to(ptr::from_mut(self), 1);
        }
    }

    /// Copy a secrets page's content to memory pointed by a [`VirtAddr`]
    ///
    /// # Safety
    ///
    /// The caller should verify that `target` points to mapped memory whose
    /// size is at least the size of the [`SecretsPage`] structure.
    ///
    /// The caller should verify not to corrupt arbitrary memory, as this function
    /// doesn't make any checks in that regard.
    pub unsafe fn copy_to(&self, target: VirtAddr) {
        let to = target.as_mut_ptr::<SecretsPage>();

        // SAFETY: demanded to the caller
        unsafe {
            to.copy_from(ptr::from_ref(self), 1);
        }
    }

    pub fn copy_for_vmpl(&self, vmpl: usize) -> Box<SecretsPage> {
        // SAFETY: the new box is uninitialized so data can be copied into it,
        // which will complete the initialization process and make it ready for
        // use.  This unsafe copy pattern is used to eliminate the need for a
        // temporary stack copy of the secrets page.
        let mut sp = unsafe {
            let mut sp_uninit = Box::new_uninit();
            // The Box is explicitly dereferenced here so there is no ambiguity
            // that the as_mut_ptr() call applies to the inner MaybeUninit and
            // not to the Box itself.
            ptr::from_ref(self).copy_to_nonoverlapping((*sp_uninit).as_mut_ptr(), 1);
            sp_uninit.assume_init()
        };

        for idx in 0..vmpl {
            sp.clear_vmpck(idx);
        }

        sp
    }

    pub fn set_svsm_data(&mut self, base: u64, size: u64, caa_addr: u64) {
        self.svsm_base = base;
        self.svsm_size = size;
        self.svsm_caa = caa_addr;
        self.svsm_max_version = CORE_PROTOCOL_VERSION_MAX;
        self.svsm_guest_vmpl = GUEST_VMPL as u8;
    }

    pub fn get_vmpck(&self, idx: usize) -> [u8; VMPCK_SIZE] {
        self.vmpck[idx]
    }

    pub fn is_vmpck_clear(&self, idx: usize) -> bool {
        self.vmpck[idx].iter().all(|e| *e == 0)
    }

    pub fn clear_vmpck(&mut self, idx: usize) {
        self.vmpck[idx].iter_mut().for_each(|e| *e = 0);
    }
}

impl Default for SecretsPage {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SecretsPageRef {
    secrets_page: Option<&'static mut SecretsPage>,
}

impl SecretsPageRef {
    const fn new() -> Self {
        Self { secrets_page: None }
    }
}

impl Deref for SecretsPageRef {
    type Target = SecretsPage;
    fn deref(&self) -> &SecretsPage {
        self.secrets_page.as_ref().unwrap()
    }
}

impl DerefMut for SecretsPageRef {
    fn deref_mut(&mut self) -> &mut SecretsPage {
        self.secrets_page.as_mut().unwrap()
    }
}

static SECRETS_PAGE: RWLock<SecretsPageRef> = RWLock::new(SecretsPageRef::new());

pub fn secrets_page() -> Option<ReadLockGuard<'static, SecretsPageRef>> {
    let guard = SECRETS_PAGE.lock_read();
    // Clippy wants to turn the match statement below into a map call, but
    // doing so doesn't wokr without violating either copy or borrow rules,
    // since the result of the match isn't the contents of the option but
    // is the lock guard itself.
    #[allow(clippy::manual_map)]
    match guard.secrets_page {
        None => None,
        Some(_) => Some(guard),
    }
}

pub fn secrets_page_mut() -> Option<WriteLockGuard<'static, SecretsPageRef>> {
    let guard = SECRETS_PAGE.lock_write();
    // Clippy wants to turn the match statement below into a map call, but
    // doing so doesn't wokr without violating either copy or borrow rules,
    // since the result of the match isn't the contents of the option but
    // is the lock guard itself.
    #[allow(clippy::manual_map)]
    match guard.secrets_page {
        None => None,
        Some(_) => Some(guard),
    }
}

/// # Safety
/// The caller is required to supply a valid virtual address that points to a
/// secrets page that will remain allocated in the static lifetime.
pub unsafe fn initialize_secrets_page(addr: VirtAddr) {
    // SAFETY: the caller takes responsibility for the correctness of the
    // virtual address.
    let secrets_page = unsafe { &mut *addr.as_mut_ptr::<SecretsPage>() };
    let mut secrets_cell = SECRETS_PAGE.lock_write();
    assert!(secrets_cell.secrets_page.is_none());
    *secrets_cell = SecretsPageRef {
        secrets_page: Some(secrets_page),
    };
}

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::VirtAddr;
use crate::error::SvsmError;
use crate::locking::{RWLock, ReadLockGuard, WriteLockGuard};
use crate::mm::GlobalBox;
use crate::sev::vmsa::VMPL_MAX;
use crate::types::GUEST_VMPL;

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
        SecretsPage {
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

    pub fn copy_from(&mut self, source: VirtAddr) {
        let from = source.as_ptr::<SecretsPage>();

        unsafe {
            *self = *from;
        }
    }

    pub fn copy_to(&self, target: VirtAddr) {
        let to = target.as_mut_ptr::<SecretsPage>();

        unsafe {
            *to = *self;
        }
    }

    pub fn copy_for_vmpl(&self, vmpl: usize) -> Result<GlobalBox<SecretsPage>, SvsmError> {
        let mut sp = GlobalBox::try_new(*self)?;
        for idx in 0..vmpl {
            sp.clear_vmpck(idx);
        }

        Ok(sp)
    }

    pub fn set_svsm_data(&mut self, base: u64, size: u64, caa_addr: u64) {
        self.svsm_base = base;
        self.svsm_size = size;
        self.svsm_caa = caa_addr;
        self.svsm_max_version = 1;
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

static SECRETS_PAGE: RWLock<SecretsPage> = RWLock::new(SecretsPage::new());

pub fn secrets_page() -> ReadLockGuard<'static, SecretsPage> {
    SECRETS_PAGE.lock_read()
}

pub fn secrets_page_mut() -> WriteLockGuard<'static, SecretsPage> {
    SECRETS_PAGE.lock_write()
}

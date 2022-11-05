// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::VirtAddr;

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct SecretsPage {
    version: u32,
    gctxt: u32,
    fms: u32,
    reserved_00c: u32,
    gosvw: [u8; 16],
    vmpck0: [u8; 32],
    vmpck1: [u8; 32],
    vmpck2: [u8; 32],
    vmpck3: [u8; 32],
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

pub fn copy_secrets_page(target: &mut SecretsPage, source: VirtAddr) {
    let table = source as *const SecretsPage;

    unsafe {
        *target = *table;
    }
}

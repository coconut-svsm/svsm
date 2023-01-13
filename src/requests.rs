// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::cpu::percpu::{this_cpu_mut, this_cpu};

const _SVSM_REQ_CORE_REMAP_CA : u32 = 0;
const _SVSM_REQ_CORE_PVALIDATE : u32 = 1;
const _SVSM_REQ_CORE_CREATE_VCPU : u32 = 2;
const _SVSM_REQ_CORE_DELETE_VCPU : u32 = 3;
const _SVSM_REQ_CORE_DEPOSIT_MEM : u32 = 4;
const _SVSM_REQ_CORE_WITHDRAW_MEM : u32 = 5;
const _SVSM_REQ_CORE_QUERY_PROTOCOL : u32 = 6;
const _SVSM_REQ_CIRE_CONFIGURE_VTOM : u32 = 7;

pub fn request_loop() {
    let result = this_cpu().get_caa_addr();
    let vmsa = this_cpu_mut().vmsa(1);

    // Clear EFER.SVME in guest VMSA
    vmsa.disable();

    if let None = result {
        log::info!("No CAA mapped - bailing out");
        return;
    }

    let caa_addr = result.unwrap();

    let pending = caa_addr as *mut u8;

    unsafe {
        log::info!("Call pending: {}", *pending);
    }

    let rax = vmsa.rax;
    let protocol : u32 = (rax >> 32) as u32;
    let request : u32 = (rax & 0xffff_ffff) as u32;
    let gpa = vmsa.rcx;

    log::info!("Protocol: {} Request: {} RCX: {:#018x}", protocol, request, gpa);
}

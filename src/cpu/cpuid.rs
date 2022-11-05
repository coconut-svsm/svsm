// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::VirtAddr;
use crate::CPUID_PAGE;

const SNP_CPUID_MAX_COUNT: usize = 64;

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct SnpCpuidFn {
    eax_in: u32,
    ecx_in: u32,
    xcr0_in: u64,
    xss_in: u64,
    eax_out: u32,
    ebx_out: u32,
    ecx_out: u32,
    edx_out: u32,
    reserved_1: u64,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct SnpCpuidTable {
    count: u32,
    reserved_1: u32,
    reserved_2: u64,
    func: [SnpCpuidFn; SNP_CPUID_MAX_COUNT],
}

pub fn copy_cpuid_table(target: &mut SnpCpuidTable, source: VirtAddr) {
    let table = source as *const SnpCpuidTable;

    unsafe {
        *target = *table;
    }
}

pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub fn cpuid_table_raw(eax: u32, ecx: u32, xcr0: u64, xss: u64) -> Option<CpuidResult> {
    unsafe {
        let count: usize = CPUID_PAGE.count as usize;

        for i in 0..count {
            if eax == CPUID_PAGE.func[i].eax_in
                && ecx == CPUID_PAGE.func[i].ecx_in
                && xcr0 == CPUID_PAGE.func[i].xcr0_in
                && xss == CPUID_PAGE.func[i].xss_in
            {
                return Some(CpuidResult {
                    eax: CPUID_PAGE.func[i].eax_out,
                    ebx: CPUID_PAGE.func[i].ebx_out,
                    ecx: CPUID_PAGE.func[i].ecx_out,
                    edx: CPUID_PAGE.func[i].edx_out,
                });
            }
        }

        None
    }
}

pub fn cpuid_table(eax: u32) -> Option<CpuidResult> {
    cpuid_table_raw(eax, 0, 0, 0)
}

/*
pub fn dump_cpuid_table() {
    unsafe {
        let cpuid : *const SnpCpuidTable = 0x9f000 as *const SnpCpuidTable;
        let count = (*cpuid).count as usize;

        println!("CPUID Table entry count: {}", count);

        for i in 0..count {
            let eax_in = (*cpuid).func[i].eax_in;
            let ecx_in = (*cpuid).func[i].ecx_in;
            let xcr0_in = (*cpuid).func[i].xcr0_in;
            let xss_in = (*cpuid).func[i].xss_in;
            let eax_out = (*cpuid).func[i].eax_out;
            let ebx_out = (*cpuid).func[i].ebx_out;
            let ecx_out = (*cpuid).func[i].ecx_out;
            let edx_out = (*cpuid).func[i].edx_out;
            println!("EAX_IN: {:#010x} ECX_IN: {:#010x} XCR0_IN: {:#010x} XSS_IN: {:#010x} EAX_OUT: {:#010x} EBX_OUT: {:#010x} ECX_OUT: {:#010x} EDX_OUT: {:#010x}",
                    eax_in, ecx_in, xcr0_in, xss_in, eax_out, ebx_out, ecx_out, edx_out);
        }
    }
}
*/

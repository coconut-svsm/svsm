// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::utils::immut_after_init::ImmutAfterInitRef;
use log;

const SNP_CPUID_MAX_COUNT: usize = 64;

static CPUID_PAGE: ImmutAfterInitRef<SnpCpuidTable> = ImmutAfterInitRef::uninit();

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

pub fn register_cpuid_table(table: &'static SnpCpuidTable) {
    CPUID_PAGE
        .init_from_ref(table)
        .expect("Could not initialize CPUID page");
}

pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub fn cpuid_table_raw(eax: u32, ecx: u32, xcr0: u64, xss: u64) -> Option<CpuidResult> {
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

pub fn cpuid_table(eax: u32) -> Option<CpuidResult> {
    cpuid_table_raw(eax, 0, 0, 0)
}

pub fn dump_cpuid_table() {
    let count = CPUID_PAGE.count as usize;

    log::trace!("CPUID Table entry count: {}", count);

    for i in 0..count {
        let eax_in = CPUID_PAGE.func[i].eax_in;
        let ecx_in = CPUID_PAGE.func[i].ecx_in;
        let xcr0_in = CPUID_PAGE.func[i].xcr0_in;
        let xss_in = CPUID_PAGE.func[i].xss_in;
        let eax_out = CPUID_PAGE.func[i].eax_out;
        let ebx_out = CPUID_PAGE.func[i].ebx_out;
        let ecx_out = CPUID_PAGE.func[i].ecx_out;
        let edx_out = CPUID_PAGE.func[i].edx_out;
        log::trace!("EAX_IN: {:#010x} ECX_IN: {:#010x} XCR0_IN: {:#010x} XSS_IN: {:#010x} EAX_OUT: {:#010x} EBX_OUT: {:#010x} ECX_OUT: {:#010x} EDX_OUT: {:#010x}",
                    eax_in, ecx_in, xcr0_in, xss_in, eax_out, ebx_out, ecx_out, edx_out);
    }
}

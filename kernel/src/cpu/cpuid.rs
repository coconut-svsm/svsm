// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::VirtAddr;
use crate::types::PAGE_SIZE;
use crate::utils::immut_after_init::ImmutAfterInitRef;
use cpuarch::snp_cpuid::SnpCpuidTable;

use core::arch::asm;

static CPUID_PAGE: ImmutAfterInitRef<'_, SnpCpuidTable> = ImmutAfterInitRef::uninit();

const _: () = assert!(size_of::<SnpCpuidTable>() <= PAGE_SIZE);

pub fn register_cpuid_table(table: &'static SnpCpuidTable) {
    CPUID_PAGE
        .init_from_ref(table)
        .expect("Could not initialize CPUID page");
}

/// Copy a CPUID page's content to memory pointed to by a [`VirtAddr`]
///
/// # Safety
///
/// The caller should verify that `dst` points to mapped memory whose size is
/// at least 4K. We assert above at compile time that SnpCpuidTable fits within
/// a page, so the write is safe.
///
/// The caller should verify not to corrupt arbitrary memory, as this function
/// doesn't make any checks in that regard.
pub unsafe fn copy_cpuid_table_to(dst: VirtAddr) {
    let start = dst.as_mut_ptr::<u8>();
    // SAFETY: caller must ensure the address is valid and not aliased.
    unsafe {
        // Zero target and copy data
        start.write_bytes(0, PAGE_SIZE);
        start
            .cast::<SnpCpuidTable>()
            .copy_from_nonoverlapping(&*CPUID_PAGE, 1);
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct CpuidLeaf {
    pub cpuid_fn: u32,
    pub cpuid_subfn: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl CpuidLeaf {
    pub fn new(cpuid_fn: u32, cpuid_subfn: u32) -> Self {
        CpuidLeaf {
            cpuid_fn,
            cpuid_subfn,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl CpuidResult {
    pub fn get(cpuid_fn: u32, cpuid_subfn: u32) -> Self {
        let mut result_eax: u32;
        let mut result_ebx: u32;
        let mut result_ecx: u32;
        let mut result_edx: u32;
        // SAFETY: Inline assembly to execute the CPUID instruction which does
        // not change any state. Input registers (EAX, ECX) and output
        // registers (EAX, EBX, ECX, EDX) are safely managed.
        unsafe {
            asm!("push %rbx",
                 "cpuid",
                 "movl %ebx, %edi",
                 "pop %rbx",
                 in("eax") cpuid_fn,
                 in("ecx") cpuid_subfn,
                 lateout("eax") result_eax,
                 lateout("edi") result_ebx,
                 lateout("ecx") result_ecx,
                 lateout("edx") result_edx,
                 options(att_syntax));
        }
        Self {
            eax: result_eax,
            ebx: result_ebx,
            ecx: result_ecx,
            edx: result_edx,
        }
    }
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

pub fn cpuid_table(eax: u32, ecx: u32) -> Option<CpuidResult> {
    cpuid_table_raw(eax, ecx, 0, 0)
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

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::sse::XSAVE_LEGACY_SIZE;
use crate::address::VirtAddr;
use crate::types::PAGE_SIZE;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use cpuarch::snp_cpuid::SnpCpuidTable;

use core::arch::x86_64::CpuidResult;

static CPUID_PAGE: ImmutAfterInitCell<&SnpCpuidTable> = ImmutAfterInitCell::uninit();

const _: () = assert!(size_of::<SnpCpuidTable>() <= PAGE_SIZE);

pub fn register_cpuid_table(table: &'static SnpCpuidTable) {
    CPUID_PAGE
        .init(table)
        .expect("Could not initialize CPUID page");
}

/// Remove XSAVE feature bits from leaf 0xD if the corresponding size
/// subleaf (2-63) is not present in the CPUID page. This prevents
/// enabling a feature in XCR0/XSS whose XSAVE area size cannot be
/// determined.
///
/// Updates as well ECX in subleaf 0, which reports maximum XSAVE
/// area size.
fn filter_xsave_features(table: &mut SnpCpuidTable) {
    // Legacy x87 + SSE are always present
    let mut avail = 3u64;
    let mut max_size = XSAVE_LEGACY_SIZE;

    // Gather available features from ECX={2-63} subleaves
    for e in table.entries() {
        // If the size subleaf is present and reports a non-zero size, the feature
        // can be enabled.
        if e.eax_in == 0xd && e.ecx_in >= 2 && e.ecx_in < 64 && e.eax_out != 0 {
            avail |= 1u64 << e.ecx_in;
            max_size = max_size.max(e.ebx_out + e.eax_out);
        }
    }

    // Now remove the available feature bits from ECX={0,1} subleaves
    for e in table.entries_mut().iter_mut().filter(|e| e.eax_in == 0xd) {
        let (hi, lo) = match e.ecx_in {
            // Subleaf 0: EAX/EDX contain XCR0 features
            0 => (&mut e.edx_out, &mut e.eax_out),
            // Subleaf 1: ECX/EDX contain XSS features
            1 => (&mut e.edx_out, &mut e.ecx_out),
            _ => continue,
        };
        *lo &= avail as u32;
        *hi &= (avail >> 32) as u32;
    }

    // ECX in subleaf ECX=0 indicates maximum XSAVE area size, update it
    // as well
    if let Some(e) = table
        .entries_mut()
        .iter_mut()
        .find(|e| e.eax_in == 0xd && e.ecx_in == 0)
    {
        e.ecx_out = max_size;
    }
}

/// # Safety
/// The caller must specify a valid virtual address to use for CPUID table
/// initialization.
///
/// # Panics
///
/// Panics if the provided address is not aligned to a [`SnpCpuidTable`].
pub unsafe fn init_cpuid_table(addr: VirtAddr) {
    // SAFETY: the caller takes responsibility for the correctness of the
    // virtual address.
    let table = unsafe {
        addr.aligned_mut::<SnpCpuidTable>()
            .expect("Misaligned SNP CPUID table address")
    };

    for func in table.entries_mut() {
        if func.eax_in == 0x8000001f {
            func.eax_out |= 1 << 28;
        }
    }

    filter_xsave_features(table);
    register_cpuid_table(table);
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
            .copy_from_nonoverlapping(*CPUID_PAGE, 1);
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

pub fn cpuid_table(eax: u32, ecx: u32) -> Option<CpuidResult> {
    CPUID_PAGE
        .entries()
        .iter()
        .find(|f| eax == f.eax_in && ecx == f.ecx_in)
        .map(|f| CpuidResult {
            eax: f.eax_out,
            ebx: f.ebx_out,
            ecx: f.ecx_out,
            edx: f.edx_out,
        })
}

pub fn dump_cpuid_table() {
    if let Ok(table) = CPUID_PAGE.try_get_inner() {
        let entries = table.entries();
        log::trace!("CPUID Table entry count: {}", entries.len());

        for func in entries {
            let eax_in = func.eax_in;
            let ecx_in = func.ecx_in;
            let xcr0_in = func.xcr0_in;
            let xss_in = func.xss_in;
            let eax_out = func.eax_out;
            let ebx_out = func.ebx_out;
            let ecx_out = func.ecx_out;
            let edx_out = func.edx_out;
            log::trace!(
                "EAX_IN: {eax_in:#010x} ECX_IN: {ecx_in:#010x} XCR0_IN: {xcr0_in:#010x} XSS_IN: {xss_in:#010x} EAX_OUT: {eax_out:#010x} EBX_OUT: {ebx_out:#010x} ECX_OUT: {ecx_out:#010x} EDX_OUT: {edx_out:#010x}"
            );
        }
    }
}

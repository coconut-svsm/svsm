// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use super::utils::{rmp_adjust, RMPFlags};
use crate::mm::alloc::{allocate_zeroed_page, free_page};
use crate::types::VirtAddr;

pub const VMPL_MAX: usize = 4;

#[repr(C, packed)]
pub struct VMSASegment {
    pub selector: u16,
    pub flags: u16,
    pub limit: u32,
    pub base: u64,
}

#[repr(C, packed)]
pub struct VMSA {
    pub es: VMSASegment,
    pub cs: VMSASegment,
    pub ss: VMSASegment,
    pub ds: VMSASegment,
    pub fs: VMSASegment,
    pub gs: VMSASegment,
    pub gdt: VMSASegment,
    pub ldt: VMSASegment,
    pub idt: VMSASegment,
    pub tr: VMSASegment,
    pub pl0_ssp: u64,
    pub pl1_ssp: u64,
    pub pl2_ssp: u64,
    pub pl3_ssp: u64,
    pub u_cet: u64,
    pub reserved_0c8: u16,
    pub vmpl: u8,
    pub cpl: u8,
    pub reserved_0cc: u32,
    pub efer: u64,
    pub reserved_0d8: [u8; 104],
    pub xss: u64,
    pub cr4: u64,
    pub cr3: u64,
    pub cr0: u64,
    pub dr7: u64,
    pub dr6: u64,
    pub rflags: u64,
    pub rip: u64,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr0_mask: u64,
    pub dr1_mask: u64,
    pub dr2_mask: u64,
    pub dr3_mask: u64,
    pub reserved_1c0: [u8; 24],
    pub rsp: u64,
    pub s_cet: u64,
    pub ssp: u64,
    pub isst_addr: u64,
    pub rax: u64,
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub sfmask: u64,
    pub kernel_gs_base: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub cr2: u64,
    pub reserved_248: [u8; 32],
    pub g_pat: u64,
    pub dbgctl: u64,
    pub br_from: u64,
    pub br_to: u64,
    pub last_excp_from: u64,
    pub last_excp_to: u64,
    pub reserved_298: [u8; 72],
    pub reserved_2e0: u64,
    pub pkru: u32,
    pub reserved_2ec: u32,
    pub guest_tsc_scale: u64,
    pub guest_tsc_offset: u64,
    pub reg_prot_nonce: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub reserved_320: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub reserved_380: [u8; 16],
    pub guest_exitinfo1: u64,
    pub guest_exitinfo2: u64,
    pub guest_exitintinfo: u64,
    pub guest_nrip: u64,
    pub sev_features: u64,
    pub vintr_ctrl: u64,
    pub guest_exit_code: u64,
    pub vtom: u64,
    pub tlb_id: u64,
    pub pcpu_id: u64,
    pub event_inj: u64,
    pub xcr0: u64,
    pub reserved_3f0: [u8; 16],
    pub x87_dp: u64,
    pub mxcsr: u32,
    pub x87_ftw: u16,
    pub x87_fsw: u16,
    pub x87_fcw: u16,
    pub x87_fop: u16,
    pub x87_ds: u16,
    pub x87_cs: u16,
    pub x87_rip: u64,
    pub fpreg_x87: [u8; 80],
    pub fpreg_xmm: [u8; 256],
    pub fpreg_ymm: [u8; 256],
    pub reserved_670: [u8; 2448],
}

impl VMSA {
    pub fn from_virt_addr(v: VirtAddr) -> &'static mut VMSA {
        unsafe {
            let ptr = v as *mut VMSA;
            ptr.as_mut().unwrap()
        }
    }

    pub fn enable(&mut self) {
        self.efer |= 1u64 << 12;
    }

    pub fn disable(&mut self) {
        self.efer &= !(1u64 << 12);
    }
}

pub fn allocate_new_vmsa(vmpl: u64) -> Result<VirtAddr, ()> {
    assert!(vmpl < (VMPL_MAX as u64));
    let vmsa_page = allocate_zeroed_page()?;
    if let Err(_) = rmp_adjust(vmsa_page, RMPFlags::VMSA | vmpl, false) {
        free_page(vmsa_page);
        return Err(());
    }
    Ok(vmsa_page)
}

pub fn free_vmsa(vaddr: VirtAddr) {
    rmp_adjust(vaddr, RMPFlags::RWX | RMPFlags::VMPL0, false).expect("Failed to free VMSA page");
    free_page(vaddr);
}

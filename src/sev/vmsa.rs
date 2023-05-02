// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::utils::{rmp_adjust, RMPFlags};
use crate::address::{Address, VirtAddr};
use crate::error::SvsmError;
use crate::mm::alloc::{allocate_pages, free_page};
use crate::types::{PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::zero_mem_region;

pub const VMPL_MAX: usize = 4;

// AE Exitcodes
// Table 15-35, AMD64 Architecture Programmer’s Manual, Vol. 2
#[repr(u64)]
#[derive(Clone, Copy)]
#[allow(dead_code, non_camel_case_types)]
pub enum GuestVMExit {
    MC = 0x52,
    INTR = 0x60,
    NMI = 0x61,
    SMI = 0x62,
    INIT = 0x63,
    VINTR = 0x64,
    PAUSE = 0x77,
    HLT = 0x78,
    SHUTDOWN = 0x7F,
    EFER_WRITE_TRAP = 0x8F,
    CR0_WRITE_TRAP = 0x90,
    CR1_WRITE_TRAP = 0x91,
    CR2_WRITE_TRAP = 0x92,
    CR3_WRITE_TRAP = 0x93,
    CR4_WRITE_TRAP = 0x94,
    CR5_WRITE_TRAP = 0x95,
    CR6_WRITE_TRAP = 0x96,
    CR7_WRITE_TRAP = 0x97,
    CR8_WRITE_TRAP = 0x98,
    CR9_WRITE_TRAP = 0x99,
    CR10_WRITE_TRAP = 0x9a,
    CR11_WRITE_TRAP = 0x9b,
    CR12_WRITE_TRAP = 0x9c,
    CR13_WRITE_TRAP = 0x9d,
    CR14_WRITE_TRAP = 0x9e,
    CR15_WRITE_TRAP = 0x9f,
    NPF = 0x400,
    VMGEXIT = 0x403,
    INVALID = 0xffffffffffffffff,
    BUSY = 0xfffffffffffffffe,
}

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
    pub guest_exit_code: GuestVMExit,
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
        unsafe { v.as_mut_ptr::<VMSA>().as_mut().unwrap() }
    }

    pub fn enable(&mut self) {
        self.efer |= 1u64 << 12;
    }

    pub fn disable(&mut self) {
        self.efer &= !(1u64 << 12);
    }
}

pub fn allocate_new_vmsa(vmpl: RMPFlags) -> Result<VirtAddr, SvsmError> {
    assert!(vmpl.bits() < (VMPL_MAX as u64));

    // Make sure the VMSA page is not 2M aligned. Some hardware generations
    // can't handle this properly.
    let mut vmsa_page = allocate_pages(0)?;
    if vmsa_page.is_aligned(PAGE_SIZE_2M) {
        free_page(vmsa_page);
        vmsa_page = allocate_pages(1)?;
        if vmsa_page.is_aligned(PAGE_SIZE_2M) {
            vmsa_page = vmsa_page.offset(PAGE_SIZE);
        }
    }

    zero_mem_region(vmsa_page, vmsa_page.offset(PAGE_SIZE));

    if let Err(e) = rmp_adjust(vmsa_page, RMPFlags::VMSA | vmpl, false) {
        free_page(vmsa_page);
        return Err(e);
    }
    Ok(vmsa_page)
}

pub fn free_vmsa(vaddr: VirtAddr) {
    rmp_adjust(vaddr, RMPFlags::RWX | RMPFlags::VMPL0, false).expect("Failed to free VMSA page");
    free_page(vaddr);
}

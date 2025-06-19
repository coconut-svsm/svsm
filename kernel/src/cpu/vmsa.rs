// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::VirtAddr;
use crate::hyperv;
use crate::sev::status::{sev_flags, SEVStatusFlags};
use crate::types::{GUEST_VMPL, SVSM_CS, SVSM_CS_ATTRIBUTES, SVSM_DS, SVSM_DS_ATTRIBUTES};
use cpuarch::vmsa::{VMSASegment, VMSA};

use super::gdt::GLOBAL_GDT;
use super::idt::GLOBAL_IDT;

pub fn svsm_code_segment() -> hyperv::HvSegmentRegister {
    hyperv::HvSegmentRegister {
        selector: SVSM_CS,
        attributes: SVSM_CS_ATTRIBUTES,
        limit: 0xffff_ffff,
        base: 0,
    }
}

pub fn svsm_data_segment() -> hyperv::HvSegmentRegister {
    hyperv::HvSegmentRegister {
        selector: SVSM_DS,
        attributes: SVSM_DS_ATTRIBUTES,
        limit: 0xffff_ffff,
        base: 0,
    }
}

pub fn svsm_gdt_segment() -> hyperv::HvTableRegister {
    let (base, limit) = GLOBAL_GDT.base_limit();
    hyperv::HvTableRegister {
        limit,
        base,
        ..Default::default()
    }
}

pub fn svsm_idt_segment() -> hyperv::HvTableRegister {
    let (base, limit) = GLOBAL_IDT.base_limit();
    hyperv::HvTableRegister {
        limit,
        base,
        ..Default::default()
    }
}

impl From<hyperv::HvSegmentRegister> for VMSASegment {
    fn from(segment: hyperv::HvSegmentRegister) -> Self {
        Self {
            selector: segment.selector,
            flags: (segment.attributes & 0xFF) | ((segment.attributes & 0xF000) >> 4),
            limit: segment.limit,
            base: segment.base,
        }
    }
}

impl From<hyperv::HvTableRegister> for VMSASegment {
    fn from(table: hyperv::HvTableRegister) -> Self {
        Self {
            selector: 0,
            flags: 0,
            limit: table.limit as u32,
            base: table.base,
        }
    }
}

pub fn init_svsm_vmsa(vmsa: &mut VMSA, vtom: u64, context: &hyperv::HvInitialVpContext) {
    vmsa.es = context.es.into();
    vmsa.cs = context.cs.into();
    vmsa.ss = context.ss.into();
    vmsa.ds = context.ds.into();
    vmsa.fs = context.fs.into();
    vmsa.gs = context.gs.into();
    vmsa.tr = context.tr.into();

    vmsa.gdt = context.gdtr.into();
    vmsa.idt = context.idtr.into();

    vmsa.rip = context.rip;
    vmsa.rsp = context.rsp;
    vmsa.rflags = context.rflags;

    vmsa.cr0 = context.cr0;
    vmsa.cr3 = context.cr3;
    vmsa.cr4 = context.cr4;
    vmsa.efer = context.efer;

    vmsa.g_pat = context.pat;

    vmsa.dr6 = 0xffff0ff0;
    vmsa.dr7 = 0x400;
    vmsa.xcr0 = 1;
    vmsa.mxcsr = 0x1f80;
    vmsa.x87_ftw = 0x5555;
    vmsa.x87_fcw = 0x0040;
    vmsa.vmpl = 0;
    vmsa.vtom = vtom;

    vmsa.sev_features = sev_flags().as_sev_features();
}

fn real_mode_code_segment(rip: u64) -> VMSASegment {
    VMSASegment {
        selector: 0xf000,
        base: rip & 0xffff_0000u64,
        limit: 0xffff,
        flags: 0x9b,
    }
}
fn real_mode_data_segment() -> VMSASegment {
    VMSASegment {
        selector: 0,
        flags: 0x93,
        limit: 0xFFFF,
        base: 0,
    }
}

fn real_mode_sys_seg(flags: u16) -> VMSASegment {
    VMSASegment {
        selector: 0,
        base: 0,
        limit: 0xffff,
        flags,
    }
}

pub fn vmsa_ref_from_vaddr(vaddr: VirtAddr) -> &'static VMSA {
    unsafe { vaddr.as_ptr::<VMSA>().as_ref().unwrap() }
}

pub fn vmsa_mut_ref_from_vaddr(vaddr: VirtAddr) -> &'static mut VMSA {
    unsafe { vaddr.as_mut_ptr::<VMSA>().as_mut().unwrap() }
}

pub fn init_guest_vmsa(v: &mut VMSA, rip: u64, alternate_injection: bool) {
    v.cr0 = 0x6000_0010;
    v.rflags = 0x2;
    v.rip = rip & 0xffff;
    v.cs = real_mode_code_segment(rip);
    v.ds = real_mode_data_segment();
    v.es = real_mode_data_segment();
    v.fs = real_mode_data_segment();
    v.gs = real_mode_data_segment();
    v.ss = real_mode_data_segment();
    v.gdt = real_mode_sys_seg(0);
    v.idt = real_mode_sys_seg(0);
    v.ldt = real_mode_sys_seg(0x82);
    v.tr = real_mode_sys_seg(0x8b);
    v.dr6 = 0xffff_0ff0;
    v.dr7 = 0x0400;
    v.g_pat = 0x0007040600070406u64;
    v.xcr0 = 1;
    v.mxcsr = 0x1f80;
    v.x87_ftw = 0x5555;
    v.x87_fcw = 0x0040;

    v.vmpl = GUEST_VMPL as u8;

    let mut sev_status = sev_flags();

    // Ensure that guest VMSAs do not enable restricted injection.
    sev_status.remove(SEVStatusFlags::REST_INJ);

    // Enable alternate injection if requested.
    if alternate_injection {
        sev_status.insert(SEVStatusFlags::ALT_INJ);
    }

    v.sev_features = sev_status.as_sev_features();
}

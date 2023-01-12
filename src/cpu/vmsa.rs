// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::sev::vmsa::{VMSASegment, VMSA};
use crate::types::{SVSM_CS, SVSM_CS_FLAGS, SVSM_DS, SVSM_DS_FLAGS};

use super::control_regs::{read_cr0, read_cr3, read_cr4};
use super::efer::read_efer;
use super::gdt::gdt_base_limit;
use super::idt::idt_base_limit;
use super::msr::read_msr;

fn svsm_code_segment() -> VMSASegment {
    VMSASegment {
        selector: SVSM_CS,
        flags: SVSM_CS_FLAGS,
        limit: 0xffff_ffff,
        base: 0,
    }
}

fn svsm_data_segment() -> VMSASegment {
    VMSASegment {
        selector: SVSM_DS,
        flags: SVSM_DS_FLAGS,
        limit: 0xffff_ffff,
        base: 0,
    }
}

fn svsm_gdt_segment() -> VMSASegment {
    let (base, limit) = gdt_base_limit();
    VMSASegment {
        selector: 0,
        flags: 0,
        limit: limit,
        base: base,
    }
}

fn svsm_idt_segment() -> VMSASegment {
    let (base, limit) = idt_base_limit();
    VMSASegment {
        selector: 0,
        flags: 0,
        limit: limit,
        base: base,
    }
}

pub fn init_svsm_vmsa(vmsa: *mut VMSA) {
    let v = unsafe { vmsa.as_mut().unwrap() };

    v.es = svsm_data_segment();
    v.cs = svsm_code_segment();
    v.ss = svsm_data_segment();
    v.ds = svsm_data_segment();
    v.fs = svsm_data_segment();
    v.gs = svsm_data_segment();
    v.gdt = svsm_gdt_segment();
    v.idt = svsm_idt_segment();

    v.cr0 = read_cr0().bits();
    v.cr3 = read_cr3() as u64;
    v.cr4 = read_cr4().bits();
    v.efer = read_efer().bits();

    v.rflags = 0x2;
    v.dr6 = 0xffff0ff0;
    v.dr7 = 0x400;
    v.g_pat = 0x0007040600070406u64;
    v.xcr0 = 1;
    v.mxcsr = 0x1f80;
    v.x87_ftw = 0x5555;
    v.x87_fcw = 0x0040;
    v.vmpl = 0;

    v.sev_features = read_msr(0xc0010131) >> 2;
}

fn real_mode_code_segment(rip : u64) -> VMSASegment {
    VMSASegment{
        selector: 0xf000,
        base: rip & 0xffff_0000u64,
        limit: 0xffff,
        flags: 0x9b,
    }
}
fn real_mode_data_segment() -> VMSASegment {
    VMSASegment {
        selector : 0,
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
        flags: flags,
    }
}

pub fn init_guest_vmsa(vmsa: *mut VMSA, rip : u64) {
    let v = unsafe { vmsa.as_mut().unwrap() };

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

    v.vmpl = 1;
    v.sev_features = read_msr(0xc0010131) >> 2;
}

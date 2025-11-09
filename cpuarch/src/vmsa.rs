// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![allow(non_camel_case_types)]

use bitfield_struct::bitfield;
use zerocopy::FromBytes;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, FromBytes, PartialEq)]
#[allow(dead_code)]
pub struct GuestVMExit(u64);

impl Default for GuestVMExit {
    #[inline]
    fn default() -> Self {
        Self::INVALID
    }
}

// AE Exitcodes
// Table 15-35, AMD64 Architecture Programmer’s Manual, Vol. 2
impl GuestVMExit {
    pub const MC: Self = Self(0x52);
    pub const INTR: Self = Self(0x60);
    pub const NMI: Self = Self(0x61);
    pub const SMI: Self = Self(0x62);
    pub const INIT: Self = Self(0x63);
    pub const VINTR: Self = Self(0x64);
    pub const PAUSE: Self = Self(0x77);
    pub const HLT: Self = Self(0x78);
    pub const SHUTDOWN: Self = Self(0x7F);
    pub const EFER_WRITE_TRAP: Self = Self(0x8F);
    pub const CR0_WRITE_TRAP: Self = Self(0x90);
    pub const CR1_WRITE_TRAP: Self = Self(0x91);
    pub const CR2_WRITE_TRAP: Self = Self(0x92);
    pub const CR3_WRITE_TRAP: Self = Self(0x93);
    pub const CR4_WRITE_TRAP: Self = Self(0x94);
    pub const CR5_WRITE_TRAP: Self = Self(0x95);
    pub const CR6_WRITE_TRAP: Self = Self(0x96);
    pub const CR7_WRITE_TRAP: Self = Self(0x97);
    pub const CR8_WRITE_TRAP: Self = Self(0x98);
    pub const CR9_WRITE_TRAP: Self = Self(0x99);
    pub const CR10_WRITE_TRAP: Self = Self(0x9a);
    pub const CR11_WRITE_TRAP: Self = Self(0x9b);
    pub const CR12_WRITE_TRAP: Self = Self(0x9c);
    pub const CR13_WRITE_TRAP: Self = Self(0x9d);
    pub const CR14_WRITE_TRAP: Self = Self(0x9e);
    pub const CR15_WRITE_TRAP: Self = Self(0x9f);
    pub const NPF: Self = Self(0x400);
    pub const VMGEXIT: Self = Self(0x403);
    pub const INVALID: Self = Self(0xffffffffffffffff);
    pub const BUSY: Self = Self(0xfffffffffffffffe);
}

#[bitfield(u64)]
#[derive(FromBytes)]
pub struct VIntrCtrl {
    pub v_tpr: u8,
    pub v_irq: bool,
    pub vgif: bool,
    pub int_shadow: bool,
    pub v_nmi: bool,
    pub v_nmi_mask: bool,
    #[bits(3)]
    _rsvd_15_13: u8,
    #[bits(4)]
    pub v_intr_prio: u8,
    pub v_ign_tpr: bool,
    #[bits(5)]
    _rsvd_25_21: u8,
    v_nmi_enable: bool,
    #[bits(5)]
    _rsvd_31_27: u8,
    pub v_intr_vector: u8,
    #[bits(23)]
    _rsvd_62_40: u32,
    pub busy: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VmsaEventType {
    Interrupt = 0,
    NMI = 2,
    Exception = 3,
    SoftwareInterrupt = 4,
}

impl VmsaEventType {
    const fn into_bits(self) -> u64 {
        self as _
    }
    const fn from_bits(value: u64) -> Self {
        match value {
            2 => Self::NMI,
            3 => Self::Exception,
            4 => Self::SoftwareInterrupt,
            _ => Self::Interrupt,
        }
    }
}

#[bitfield(u64)]
#[derive(FromBytes)]
pub struct VmsaEventInject {
    pub vector: u8,
    #[bits(3)]
    pub event_type: VmsaEventType,
    pub error_code_valid: bool,
    #[bits(19)]
    _rsvd_30_12: u32,
    pub valid: bool,
    pub error_code: u32,
}

#[repr(C, packed)]
#[derive(Debug, Default, Clone, Copy, FromBytes)]
pub struct VMSASegment {
    pub selector: u16,
    pub flags: u16,
    pub limit: u32,
    pub base: u64,
}

#[repr(C, packed)]
#[derive(Debug, FromBytes)]
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
    pub guest_exitintinfo: VmsaEventInject,
    pub guest_nrip: u64,
    pub sev_features: u64,
    pub vintr_ctrl: VIntrCtrl,
    pub guest_exit_code: GuestVMExit,
    pub vtom: u64,
    pub tlb_id: u64,
    pub pcpu_id: u64,
    pub event_inj: VmsaEventInject,
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
    pub lbr_stack: [u8; 256],
    pub lbr_select: u64,
    pub ibs_fetch_ctl: u64,
    pub ibs_fetch_linaddr: u64,
    pub ibs_op_ctl: u64,
    pub ibs_op_rip: u64,
    pub ibs_op_data: u64,
    pub ibs_op_data2: u64,
    pub ibs_op_data3: u64,
    pub ibs_dc_linaddr: u64,
    pub bp_ibstgt_rip: u64,
    pub ic_ibs_extd_ctl: u64,
    pub reserved_7c8: [u8; 2104],
}

const _: () = assert!(core::mem::size_of::<VMSA>() == 0x1000);

impl Default for VMSA {
    fn default() -> Self {
        VMSA {
            es: Default::default(),
            cs: Default::default(),
            ss: Default::default(),
            ds: Default::default(),
            fs: Default::default(),
            gs: Default::default(),
            gdt: Default::default(),
            ldt: Default::default(),
            idt: Default::default(),
            tr: Default::default(),
            pl0_ssp: Default::default(),
            pl1_ssp: Default::default(),
            pl2_ssp: Default::default(),
            pl3_ssp: Default::default(),
            u_cet: Default::default(),
            reserved_0c8: Default::default(),
            vmpl: Default::default(),
            cpl: Default::default(),
            reserved_0cc: Default::default(),
            efer: Default::default(),
            reserved_0d8: [0u8; 104],
            xss: Default::default(),
            cr4: Default::default(),
            cr3: Default::default(),
            cr0: Default::default(),
            dr7: Default::default(),
            dr6: Default::default(),
            rflags: Default::default(),
            rip: Default::default(),
            dr0: Default::default(),
            dr1: Default::default(),
            dr2: Default::default(),
            dr3: Default::default(),
            dr0_mask: Default::default(),
            dr1_mask: Default::default(),
            dr2_mask: Default::default(),
            dr3_mask: Default::default(),
            reserved_1c0: [0u8; 24],
            rsp: Default::default(),
            s_cet: Default::default(),
            ssp: Default::default(),
            isst_addr: Default::default(),
            rax: Default::default(),
            star: Default::default(),
            lstar: Default::default(),
            cstar: Default::default(),
            sfmask: Default::default(),
            kernel_gs_base: Default::default(),
            sysenter_cs: Default::default(),
            sysenter_esp: Default::default(),
            sysenter_eip: Default::default(),
            cr2: Default::default(),
            reserved_248: [0u8; 32],
            g_pat: Default::default(),
            dbgctl: Default::default(),
            br_from: Default::default(),
            br_to: Default::default(),
            last_excp_from: Default::default(),
            last_excp_to: Default::default(),
            reserved_298: [0u8; 72],
            reserved_2e0: Default::default(),
            pkru: Default::default(),
            reserved_2ec: Default::default(),
            guest_tsc_scale: Default::default(),
            guest_tsc_offset: Default::default(),
            reg_prot_nonce: Default::default(),
            rcx: Default::default(),
            rdx: Default::default(),
            rbx: Default::default(),
            reserved_320: Default::default(),
            rbp: Default::default(),
            rsi: Default::default(),
            rdi: Default::default(),
            r8: Default::default(),
            r9: Default::default(),
            r10: Default::default(),
            r11: Default::default(),
            r12: Default::default(),
            r13: Default::default(),
            r14: Default::default(),
            r15: Default::default(),
            reserved_380: [0u8; 16],
            guest_exitinfo1: Default::default(),
            guest_exitinfo2: Default::default(),
            guest_exitintinfo: Default::default(),
            guest_nrip: Default::default(),
            sev_features: Default::default(),
            vintr_ctrl: Default::default(),
            guest_exit_code: Default::default(),
            vtom: Default::default(),
            tlb_id: Default::default(),
            pcpu_id: Default::default(),
            event_inj: Default::default(),
            xcr0: Default::default(),
            reserved_3f0: [0u8; 16],
            x87_dp: Default::default(),
            mxcsr: Default::default(),
            x87_ftw: Default::default(),
            x87_fsw: Default::default(),
            x87_fcw: Default::default(),
            x87_fop: Default::default(),
            x87_ds: Default::default(),
            x87_cs: Default::default(),
            x87_rip: Default::default(),
            fpreg_x87: [0u8; 80],
            fpreg_xmm: [0u8; 256],
            fpreg_ymm: [0u8; 256],
            lbr_stack: [0; 256],
            lbr_select: Default::default(),
            ibs_fetch_ctl: Default::default(),
            ibs_fetch_linaddr: Default::default(),
            ibs_op_ctl: Default::default(),
            ibs_op_rip: Default::default(),
            ibs_op_data: Default::default(),
            ibs_op_data2: Default::default(),
            ibs_op_data3: Default::default(),
            ibs_dc_linaddr: Default::default(),
            bp_ibstgt_rip: Default::default(),
            ic_ibs_extd_ctl: Default::default(),
            reserved_7c8: [0u8; 2104],
        }
    }
}

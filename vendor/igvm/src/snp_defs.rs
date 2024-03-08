// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! AMD SEV-SNP specific definitions.

use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

/// Virtual Event Injection
/// Defined by the following union in C:
/// ```ignore
/// typedef union _SEV_EVENT_INJECT_INFO
/// {
///     UINT64 AsUINT64;
///     struct
///     {
///         UINT64  Vector:8;
///         UINT64  InterruptionType:3;     // Use SEV_INTR_TYPE_*
///         UINT64  DeliverErrorCode:1;
///         UINT64  Reserved1:19;
///         UINT64  Valid:1;
///         UINT64  ErrorCode:32;
///     };
/// } SEV_EVENT_INJECT_INFO, *PSEV_EVENT_INJECT_INFO;
/// ```
#[repr(transparent)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct SevEventInjectInfo(pub u64);

/// A X64 selector register.
#[repr(C)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct SevSelector {
    pub selector: u16,
    pub attrib: u16,
    pub limit: u32,
    pub base: u64,
}

/// A X64 XMM register.
#[repr(C)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct SevXmmRegister {
    pub low: u64,
    pub high: u64,
}

/// SEV feature information.
/// Defined by the following union in C:
///```ignore
/// union
/// {
///     UINT64  SevFeatures;
///     struct
///     {
///         UINT64  SevFeatureSNP                   : 1;
///         UINT64  SevFeatureVTOM                  : 1;
///         UINT64  SevFeatureReflectVC             : 1;
///         UINT64  SevFeatureRestrictInjection     : 1;
///         UINT64  SevFeatureAlternateInjection    : 1;
///         UINT64  SevFeatureDebugSwap             : 1;
///         UINT64  SevFeaturePreventHostIBS        : 1;
///         UINT64  SevFeatureSNPBTBIsolation       : 1;
///         UINT64  SevFeatureResrved2              : 56;
///     };
/// };
///```
#[bitfield_struct::bitfield(u64)]
#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct SevFeatures {
    pub snp: bool,
    pub vtom: bool,
    pub reflect_vc: bool,
    pub restrict_injection: bool,
    pub alternate_injection: bool,
    pub debug_swap: bool,
    pub prevent_host_ibs: bool,
    pub snp_btb_isolation: bool,
    #[bits(56)]
    _unused: u64,
}

/// SEV Virtual interrupt control
/// Defined by the following union in C:
///```ignore
/// union
/// {
///     UINT64  VIntrCtrl;
/// #define SEV_VINTR_GUEST_BUSY_BIT        63
///     struct
///     {
///         UINT64  VIntrTPR        : 8;
///         UINT64  VIntrIRQ        : 1;
///         UINT64  VIntrGIF        : 1;
///         UINT64  VIntrShadow     : 1;
///         UINT64  VIntrReserved1  : 5;
///         UINT64  VIntrPrio       : 4;
///         UINT64  VIntrIgnoreTPR  : 1;
///         UINT64  VIntrReserved2  : 11;
///         UINT64  VIntrVector     : 8;
///         UINT64  VIntrReserved3  : 23;
///         UINT64  VIntrGuestBusy  : 1;
///     };
/// };
///```
#[repr(transparent)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct SevVirtualInterruptControl(pub u64);

/// SEV VMSA structure representing CPU state
#[repr(C)]
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct SevVmsa {
    // Selector Info
    pub es: SevSelector,
    pub cs: SevSelector,
    pub ss: SevSelector,
    pub ds: SevSelector,
    pub fs: SevSelector,
    pub gs: SevSelector,

    // Descriptor Table Info
    pub gdtr: SevSelector,
    pub ldtr: SevSelector,
    pub idtr: SevSelector,
    pub tr: SevSelector,

    // CET
    pub pl0_ssp: u64,
    pub pl1_ssp: u64,
    pub pl2_ssp: u64,
    pub pl3_ssp: u64,
    pub u_cet: u64,

    // Reserved, MBZ
    pub vmsa_reserved1: [u8; 2],

    // Virtual Machine Privilege Level
    pub vmpl: u8,

    // CPL
    pub cpl: u8,

    // Reserved, MBZ
    pub vmsa_reserved2: u32,

    // EFER
    pub efer: u64,

    // Reserved, MBZ
    pub vmsa_reserved3: [u32; 26],

    // XSS (offset 0x140)
    pub xss: u64,

    // Control registers
    pub cr4: u64,
    pub cr3: u64,
    pub cr0: u64,

    // Debug registers
    pub dr7: u64,
    pub dr6: u64,

    // RFLAGS
    pub rflags: u64,

    // RIP
    pub rip: u64,

    // Additional saved debug registers
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,

    // Debug register address masks
    pub dr0_addr_mask: u64,
    pub dr1_addr_mask: u64,
    pub dr2_addr_mask: u64,
    pub dr3_addr_mask: u64,

    // Reserved, MBZ
    pub vmsa_reserved4: [u64; 3],

    // RSP
    pub rsp: u64,

    // CET
    pub s_cet: u64,
    pub ssp: u64,
    pub interrupt_ssp_table_addr: u64,

    // RAX
    pub rax: u64,

    // SYSCALL config registers
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub sfmask: u64,

    // KernelGsBase
    pub kernel_gs_base: u64,

    // SYSENTER config registers
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_epi: u64,

    // CR2
    pub cr2: u64,

    // Reserved, MBZ
    pub vmsa_reserved5: [u64; 4],

    // PAT
    pub pat: u64,

    // LBR MSRs
    pub dbgctl: u64,
    pub last_branch_from_ip: u64,
    pub last_branch_to_ip: u64,
    pub last_excp_from_ip: u64,
    pub last_excp_to_ip: u64,

    // Reserved, MBZ
    pub vmsa_reserved6: [u64; 9],

    // Speculation control MSR
    pub spec_ctrl: u64,

    // Reserved, MBZ
    pub vmsa_reserved7: [u32; 8],

    // GPRs
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub vmsa_reserved8: u64, // MBZ
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

    // Reserved, MBZ
    pub vmsa_reserved9: [u64; 2],

    // Exit information following an automatic #VMEXIT
    pub exit_info1: u64,
    pub exit_info2: u64,
    pub exit_int_info: u64,

    // Software scratch register
    pub next_rip: u64,

    // SEV feature information
    pub sev_features: SevFeatures,

    // Virtual interrupt control
    pub v_intr_cntrl: SevVirtualInterruptControl,

    // Guest exiting error code
    pub guest_error_code: u64,

    // Virtual top of memory
    pub virtual_tom: u64,

    // TLB control.  Writing a zero to PCPU_ID will force a full TLB
    // invalidation upon the next entry.
    pub tlb_id: u64,
    pub pcpu_id: u64,

    // Event injection
    pub event_inject: SevEventInjectInfo,

    // XCR0
    pub xcr0: u64,

    // X87 state save valid bitmap
    pub xsave_valid_bitmap: [u8; 16],

    // X87 save state
    pub x87dp: u64,
    pub mxcsr: u32,
    pub x87_ftw: u16,
    pub x87_fsw: u16,
    pub x87_fcw: u16,
    pub x87_op: u16,
    pub x87_ds: u16,
    pub x87_cs: u16,
    pub x87_rip: u64,

    // NOTE: Zerocopy doesn't support arrays of 80 size yet. Waiting on const generics?
    //       Split into chunks, as no code uses this field yet.
    // x87_registers: [u8; 80],
    pub x87_registers1: [u8; 32],
    pub x87_registers2: [u8; 32],
    pub x87_registers3: [u8; 16],

    // XMM registers
    pub xmm_registers: [SevXmmRegister; 16],

    // YMM high registers
    pub ymm_registers: [SevXmmRegister; 16],
}

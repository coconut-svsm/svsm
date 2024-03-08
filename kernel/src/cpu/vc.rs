// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::idt::common::X86ExceptionContext;
use crate::cpu::cpuid::{cpuid_table_raw, CpuidLeaf};
use crate::cpu::ghcb::current_ghcb;
use crate::cpu::insn::{insn_fetch, Instruction};
use crate::debug::gdbstub::svsm_gdbstub::handle_debug_exception;
use crate::error::SvsmError;
use crate::sev::ghcb::{GHCBIOSize, GHCB};
use core::fmt;

pub const SVM_EXIT_EXCP_BASE: usize = 0x40;
pub const SVM_EXIT_LAST_EXCP: usize = 0x5f;
pub const SVM_EXIT_CPUID: usize = 0x72;
pub const SVM_EXIT_IOIO: usize = 0x7b;
pub const X86_TRAP_DB: usize = 0x01;
pub const X86_TRAP: usize = SVM_EXIT_EXCP_BASE + X86_TRAP_DB;

#[derive(Clone, Copy, Debug)]
pub struct VcError {
    pub rip: usize,
    pub code: usize,
    pub error_type: VcErrorType,
}

#[derive(Clone, Copy, Debug)]
pub enum VcErrorType {
    Unsupported,
    DecodeFailed,
    UnknownCpuidLeaf,
}

impl From<VcError> for SvsmError {
    fn from(e: VcError) -> Self {
        Self::Vc(e)
    }
}

impl fmt::Display for VcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unhandled #VC exception ")?;
        match self.error_type {
            VcErrorType::Unsupported => {
                write!(f, "unsupported #VC exception")?;
            }
            VcErrorType::DecodeFailed => {
                write!(f, "invalid instruction")?;
            }
            VcErrorType::UnknownCpuidLeaf => {
                write!(f, "unknown CPUID leaf")?;
            }
        }
        write!(
            f,
            " RIP: {:#018x}: error code: {:#018x}",
            self.rip, self.code
        )
    }
}

pub fn stage2_handle_vc_exception_no_ghcb(ctx: &mut X86ExceptionContext) {
    let err = ctx.error_code;
    let rip = ctx.frame.rip;

    let insn = vc_decode_insn(ctx).expect("Could not decode instructions");

    match err {
        SVM_EXIT_CPUID => handle_cpuid(ctx).expect("Could not handle CPUID #VC exception"),
        _ => {
            panic!(
                "Unsupported #VC exception RIP {:#018x} error code: {:#018x}",
                rip, err,
            )
        }
    }

    vc_finish_insn(ctx, &insn);
}

pub fn stage2_handle_vc_exception(ctx: &mut X86ExceptionContext) {
    let err = ctx.error_code;
    let rip = ctx.frame.rip;

    /*
     * To handle NAE events, we're supposed to reset the VALID_BITMAP field of the GHCB.
     * This is currently only relevant for IOIO handling. This field is currently reset in
     * the ioio_{in,ou} methods but it would be better to move the reset out of the different
     * handlers.
     */
    let mut ghcb = current_ghcb();

    let insn = vc_decode_insn(ctx).expect("Could not decode instructions");

    match err {
        SVM_EXIT_CPUID => handle_cpuid(ctx).expect("Could not handle CPUID #VC exception"),
        SVM_EXIT_IOIO => {
            handle_ioio(ctx, &mut ghcb, &insn).expect("Could not handle IOIO #VC exception")
        }
        _ => {
            panic!(
                "Unsupported #VC exception RIP {:#018x} error code: {:#018x}",
                rip, err
            );
        }
    }

    vc_finish_insn(ctx, &insn);
}

pub fn handle_vc_exception(ctx: &mut X86ExceptionContext) {
    let error_code = ctx.error_code;
    let rip = ctx.frame.rip;

    /*
     * To handle NAE events, we're supposed to reset the VALID_BITMAP field of the GHCB.
     * This is currently only relevant for IOIO handling. This field is currently reset in
     * the ioio_{in,ou} methods but it would be better to move the reset out of the different
     * handlers.
     */
    let mut ghcb = current_ghcb();

    let insn = vc_decode_insn(ctx).expect("Could not decode instruction");

    match error_code {
        // If the gdb stub is enabled then debugging operations such as single stepping
        // will cause either an exception via DB_VECTOR if the DEBUG_SWAP sev_feature is
        // clear, or a VC exception with an error code of X86_TRAP if set.
        X86_TRAP => handle_debug_exception(ctx, ctx.vector),
        SVM_EXIT_CPUID => handle_cpuid(ctx).expect("Could not handle CPUID #VC exception"),
        SVM_EXIT_IOIO => {
            handle_ioio(ctx, &mut ghcb, &insn).expect("Could not handle IOIO #VC exception")
        }
        _ => {
            panic!(
                "Unsupported #VC exception RIP {:#018x} error code: {:#018x}",
                rip, error_code
            )
        }
    }

    vc_finish_insn(ctx, &insn);
}

fn handle_cpuid(ctx: &mut X86ExceptionContext) -> Result<(), SvsmError> {
    /*
     * Section 2.3.1 GHCB MSR Protocol in SEV-ES Guest-Hypervisor Communication Block
     * Standardization Rev. 2.02.
     * For SEV-ES/SEV-SNP, we can use the CPUID table already defined and populated with
     * firmware information.
     * We choose for now not to call the hypervisor to perform CPUID, since it's no trusted.
     * Since GHCB is not needed to handle CPUID with the firmware table, we can call the handler
     * very soon in stage 2.
     */

    snp_cpuid(ctx)
}

fn snp_cpuid(ctx: &mut X86ExceptionContext) -> Result<(), SvsmError> {
    let mut leaf = CpuidLeaf::new(ctx.regs.rax as u32, ctx.regs.rcx as u32);

    let Some(ret) = cpuid_table_raw(leaf.cpuid_fn, leaf.cpuid_subfn, 0, 0) else {
        return Err(SvsmError::Vc(VcError {
            rip: ctx.frame.rip,
            code: ctx.error_code,
            error_type: VcErrorType::UnknownCpuidLeaf,
        }));
    };

    leaf.eax = ret.eax;
    leaf.ebx = ret.ebx;
    leaf.ecx = ret.ecx;
    leaf.edx = ret.edx;

    ctx.regs.rax = leaf.eax as usize;
    ctx.regs.rbx = leaf.ebx as usize;
    ctx.regs.rcx = leaf.ecx as usize;
    ctx.regs.rdx = leaf.edx as usize;

    Ok(())
}

fn vc_finish_insn(ctx: &mut X86ExceptionContext, insn: &Instruction) {
    ctx.frame.rip += insn.len()
}

fn handle_ioio(
    ctx: &mut X86ExceptionContext,
    ghcb: &mut GHCB,
    insn: &Instruction,
) -> Result<(), SvsmError> {
    let port: u16 = (ctx.regs.rdx & 0xffff) as u16;
    let out_value: u64 = ctx.regs.rax as u64;

    match insn.opcode[0] {
        0x6C..=0x6F | 0xE4..=0xE7 => Err(SvsmError::Vc(VcError {
            rip: ctx.frame.rip,
            code: ctx.error_code,
            error_type: VcErrorType::Unsupported,
        })),
        0xEC => {
            let ret = ghcb.ioio_in(port, GHCBIOSize::Size8)?;
            ctx.regs.rax = (ret & 0xff) as usize;
            Ok(())
        }
        0xED => {
            let (size, mask) = match insn.prefixes {
                Some(prefix) if prefix.nb_bytes > 0 => (GHCBIOSize::Size16, u16::MAX as u64),
                _ => (GHCBIOSize::Size32, u32::MAX as u64),
            };

            let ret = ghcb.ioio_in(port, size)?;
            ctx.regs.rax = (ret & mask) as usize;
            Ok(())
        }
        0xEE => ghcb.ioio_out(port, GHCBIOSize::Size8, out_value),
        0xEF => {
            let mut size: GHCBIOSize = GHCBIOSize::Size32;
            if let Some(prefix) = insn.prefixes {
                // this is always true at the moment
                if prefix.nb_bytes > 0 {
                    // outw instruction has a 0x66 operand-size prefix for word-sized operands.
                    size = GHCBIOSize::Size16;
                }
            }

            ghcb.ioio_out(port, size, out_value)
        }
        _ => Err(SvsmError::Vc(VcError {
            rip: ctx.frame.rip,
            code: ctx.error_code,
            error_type: VcErrorType::DecodeFailed,
        })),
    }
}

fn vc_decode_insn(ctx: &X86ExceptionContext) -> Result<Instruction, SvsmError> {
    if !vc_decoding_needed(ctx.error_code) {
        return Ok(Instruction::default());
    }

    // TODO: the instruction fetch will likely to be handled differently when
    // #VC exception will be raised from CPL > 0.
    // TODO: handle invalid RIPs with exception fixup
    // SAFETY: safe if [rip;rip+MAX_INSN_SIZE] doesn't overlap with an unmapped page
    let insn_raw = unsafe { insn_fetch(ctx.frame.rip as *const u8) };

    let mut insn = Instruction::new(insn_raw);
    insn.decode()?;

    Ok(insn)
}

fn vc_decoding_needed(error_code: usize) -> bool {
    !(SVM_EXIT_EXCP_BASE..=SVM_EXIT_LAST_EXCP).contains(&error_code)
}

#[cfg(test)]
mod tests {
    use crate::cpu::msr::{rdtsc, rdtscp, read_msr, write_msr, RdtscpOut};
    use crate::cpu::percpu::this_cpu_mut;
    use crate::sev::ghcb::GHCB;
    use crate::sev::utils::{get_dr7, raw_vmmcall, set_dr7};
    use core::arch::asm;
    use core::arch::x86_64::__cpuid_count;

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_has_memory_encryption_info_cpuid() {
        const CPUID_EXTENDED_FUNCTION_INFO: u32 = 0x8000_0000;
        const CPUID_MEMORY_ENCRYPTION_INFO: u32 = 0x8000_001F;
        let extended_info = unsafe { __cpuid_count(CPUID_EXTENDED_FUNCTION_INFO, 0) };
        assert!(extended_info.eax >= CPUID_MEMORY_ENCRYPTION_INFO);
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_has_amd_cpuid() {
        const CPUID_VENDOR_INFO: u32 = 0;

        let vendor_info = unsafe { __cpuid_count(CPUID_VENDOR_INFO, 0) };

        let vendor_name_bytes = [vendor_info.ebx, vendor_info.edx, vendor_info.ecx]
            .map(|v| v.to_le_bytes())
            .concat();

        assert_eq!(core::str::from_utf8(&vendor_name_bytes), Ok("AuthenticAMD"));
    }

    const GHCB_FILL_TEST_VALUE: u8 = b'1';

    fn fill_ghcb_with_test_data() {
        let ghcb = this_cpu_mut().ghcb_unsafe();
        unsafe {
            // The count param is 1 to only write one ghcb's worth of data
            core::ptr::write_bytes(ghcb, GHCB_FILL_TEST_VALUE, 1);
        }
    }

    fn verify_ghcb_was_altered() {
        let ghcb = this_cpu_mut().ghcb_unsafe();
        let ghcb_bytes =
            unsafe { core::slice::from_raw_parts(ghcb.cast::<u8>(), core::mem::size_of::<GHCB>()) };
        assert!(ghcb_bytes.iter().any(|v| *v != GHCB_FILL_TEST_VALUE));
    }

    // Calls `f` with an assertion that it ended up altering the ghcb.
    fn verify_ghcb_gets_altered<R, F>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        fill_ghcb_with_test_data();
        let result = f();
        verify_ghcb_was_altered();
        result
    }

    const TESTDEV_ECHO_LAST_PORT: u16 = 0xe0;

    fn inb(port: u16) -> u8 {
        unsafe {
            let ret: u8;
            asm!("inb %dx, %al", in("dx") port, out("al") ret, options(att_syntax));
            ret
        }
    }
    fn inb_from_testdev_echo() -> u8 {
        unsafe {
            let ret: u8;
            asm!("inb $0xe0, %al", out("al") ret, options(att_syntax));
            ret
        }
    }

    fn outb(port: u16, value: u8) {
        unsafe { asm!("outb %al, %dx", in("al") value, in("dx") port, options(att_syntax)) }
    }

    fn outb_to_testdev_echo(value: u8) {
        unsafe { asm!("outb %al, $0xe0", in("al") value, options(att_syntax)) }
    }

    fn inw(port: u16) -> u16 {
        unsafe {
            let ret: u16;
            asm!("inw %dx, %ax", in("dx") port, out("ax") ret, options(att_syntax));
            ret
        }
    }
    fn inw_from_testdev_echo() -> u16 {
        unsafe {
            let ret: u16;
            asm!("inw $0xe0, %ax", out("ax") ret, options(att_syntax));
            ret
        }
    }

    fn outw(port: u16, value: u16) {
        unsafe { asm!("outw %ax, %dx", in("ax") value, in("dx") port, options(att_syntax)) }
    }

    fn outw_to_testdev_echo(value: u16) {
        unsafe { asm!("outw %ax, $0xe0", in("ax") value, options(att_syntax)) }
    }

    fn inl(port: u16) -> u32 {
        unsafe {
            let ret: u32;
            asm!("inl %dx, %eax", in("dx") port, out("eax") ret, options(att_syntax));
            ret
        }
    }
    fn inl_from_testdev_echo() -> u32 {
        unsafe {
            let ret: u32;
            asm!("inl $0xe0, %eax", out("eax") ret, options(att_syntax));
            ret
        }
    }

    fn outl(port: u16, value: u32) {
        unsafe { asm!("outl %eax, %dx", in("eax") value, in("dx") port, options(att_syntax)) }
    }

    fn outl_to_testdev_echo(value: u32) {
        unsafe { asm!("outl %eax, $0xe0", in("eax") value, options(att_syntax)) }
    }

    fn rep_outsw(port: u16, data: &[u16]) {
        unsafe {
            asm!("rep outsw", in("dx") port, in("rsi") data.as_ptr(), in("rcx") data.len(), options(att_syntax))
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_port_io_8() {
        const TEST_VAL: u8 = 0x12;
        verify_ghcb_gets_altered(|| outb(TESTDEV_ECHO_LAST_PORT, TEST_VAL));
        assert_eq!(
            TEST_VAL,
            verify_ghcb_gets_altered(|| inb(TESTDEV_ECHO_LAST_PORT))
        );
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_port_io_16() {
        const TEST_VAL: u16 = 0x4321;
        verify_ghcb_gets_altered(|| outw(TESTDEV_ECHO_LAST_PORT, TEST_VAL));
        assert_eq!(
            TEST_VAL,
            verify_ghcb_gets_altered(|| inw(TESTDEV_ECHO_LAST_PORT))
        );
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_port_io_32() {
        const TEST_VAL: u32 = 0xabcd1234;
        verify_ghcb_gets_altered(|| outl(TESTDEV_ECHO_LAST_PORT, TEST_VAL));
        assert_eq!(
            TEST_VAL,
            verify_ghcb_gets_altered(|| inl(TESTDEV_ECHO_LAST_PORT))
        );
    }

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "Currently unhandled by #VC handler"]
    fn test_port_io_8_hardcoded() {
        const TEST_VAL: u8 = 0x12;
        verify_ghcb_gets_altered(|| outb_to_testdev_echo(TEST_VAL));
        assert_eq!(TEST_VAL, verify_ghcb_gets_altered(inb_from_testdev_echo));
    }

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "Currently unhandled by #VC handler"]
    fn test_port_io_16_hardcoded() {
        const TEST_VAL: u16 = 0x4321;
        verify_ghcb_gets_altered(|| outw_to_testdev_echo(TEST_VAL));
        assert_eq!(TEST_VAL, verify_ghcb_gets_altered(inw_from_testdev_echo));
    }

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "Currently unhandled by #VC handler"]
    fn test_port_io_32_hardcoded() {
        const TEST_VAL: u32 = 0xabcd1234;
        verify_ghcb_gets_altered(|| outl_to_testdev_echo(TEST_VAL));
        assert_eq!(TEST_VAL, verify_ghcb_gets_altered(inl_from_testdev_echo));
    }

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "Currently unhandled by #VC handler"]
    fn test_port_io_string_16_get_last() {
        const TEST_DATA: &[u16] = &[0x1234, 0x5678, 0x9abc, 0xdef0];
        verify_ghcb_gets_altered(|| rep_outsw(TESTDEV_ECHO_LAST_PORT, TEST_DATA));
        assert_eq!(
            TEST_DATA.last().unwrap(),
            &verify_ghcb_gets_altered(|| inw(TESTDEV_ECHO_LAST_PORT))
        );
    }

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "Currently unhandled by #VC handler"]
    fn test_sev_snp_enablement_msr() {
        const MSR_SEV_STATUS: u32 = 0b10;
        const MSR_SEV_STATUS_SEV_SNP_ENABLED: u64 = 0b100;

        let sev_status = verify_ghcb_gets_altered(|| read_msr(MSR_SEV_STATUS));
        assert_ne!(sev_status & MSR_SEV_STATUS_SEV_SNP_ENABLED, 0);
    }

    const MSR_APIC_BASE: u32 = 0x1b;

    const APIC_DEFAULT_PHYS_BASE: u64 = 0xfee00000; // KVM's default
    const APIC_BASE_PHYS_ADDR_MASK: u64 = 0xffffff000; // bit 12-35

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "Currently unhandled by #VC handler"]
    fn test_rdmsr_apic() {
        let apic_base = verify_ghcb_gets_altered(|| read_msr(MSR_APIC_BASE));
        assert_eq!(apic_base & APIC_BASE_PHYS_ADDR_MASK, APIC_DEFAULT_PHYS_BASE);
    }

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "Currently unhandled by #VC handler"]
    fn test_rdmsr_debug_ctl() {
        const MSR_DEBUG_CTL: u32 = 0x1d9;
        let apic_base = verify_ghcb_gets_altered(|| read_msr(MSR_DEBUG_CTL));
        assert_eq!(apic_base, 0);
    }

    const MSR_TSC_AUX: u32 = 0xc0000103;

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "Currently unhandled by #VC handler"]
    fn test_wrmsr_tsc_aux() {
        let test_val = 0x1234;
        verify_ghcb_gets_altered(|| write_msr(MSR_TSC_AUX, test_val));
        let readback = verify_ghcb_gets_altered(|| read_msr(MSR_TSC_AUX));
        assert_eq!(test_val, readback);
    }

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "Currently unhandled by #VC handler"]
    fn test_vmmcall_error() {
        let res = verify_ghcb_gets_altered(|| unsafe { raw_vmmcall(1005, 0, 0, 0) });
        assert_eq!(res, -1000);
    }

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "Currently unhandled by #VC handler"]
    fn test_vmmcall_vapic_poll_irq() {
        const VMMCALL_HC_VAPIC_POLL_IRQ: u32 = 1;

        let res =
            verify_ghcb_gets_altered(|| unsafe { raw_vmmcall(VMMCALL_HC_VAPIC_POLL_IRQ, 0, 0, 0) });
        assert_eq!(res, 0);
    }

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "Currently unhandled by #VC handler"]
    fn test_read_write_dr7() {
        const DR7_DEFAULT: u64 = 0x400;
        const DR7_TEST: u64 = 0x401;

        let old_dr7 = verify_ghcb_gets_altered(get_dr7);
        assert_eq!(old_dr7, DR7_DEFAULT);

        verify_ghcb_gets_altered(|| unsafe { set_dr7(DR7_TEST) });
        let new_dr7 = verify_ghcb_gets_altered(get_dr7);
        assert_eq!(new_dr7, DR7_TEST);
    }

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "Currently unhandled by #VC handler"]
    fn test_rdtsc() {
        let mut prev: u64 = rdtsc();
        for _ in 0..50 {
            let cur = rdtsc();
            assert!(cur > prev);
            prev = cur;
        }
    }

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "Currently unhandled by #VC handler"]
    fn test_rdtscp() {
        let expected_pid = u32::try_from(verify_ghcb_gets_altered(|| read_msr(MSR_TSC_AUX)))
            .expect("pid should be 32 bits");
        let RdtscpOut {
            timestamp: mut prev,
            pid,
        } = rdtscp();
        assert_eq!(pid, expected_pid);
        for _ in 0..50 {
            let RdtscpOut {
                timestamp: cur,
                pid,
            } = rdtscp();
            assert_eq!(pid, expected_pid);
            assert!(cur > prev);
            prev = cur;
        }
    }

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "Currently unhandled by #VC handler"]
    fn test_wbinvd() {
        verify_ghcb_gets_altered(|| unsafe {
            asm!("wbinvd");
        });
    }

    const APIC_DEFAULT_VERSION_REGISTER_OFFSET: u64 = 0x30;
    const EXPECTED_APIC_VERSION_NUMBER: u32 = 0x50014;

    #[test]
    // #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[ignore = "apic mmio is not supported"]
    fn test_mmio_apic_version() {
        let mut version: u32 = 0;
        let address = u32::try_from(APIC_DEFAULT_PHYS_BASE + APIC_DEFAULT_VERSION_REGISTER_OFFSET)
            .expect("APIC address should fit in 32 bits");
        verify_ghcb_gets_altered(|| unsafe {
            asm!(
                "mov (%edx), %eax",
                out("eax") version,
                in("edx") address,
                options(att_syntax)
            )
        });
        assert_eq!(version, EXPECTED_APIC_VERSION_NUMBER);
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use super::error::TdVmcallError::Retry;
use super::error::{TdxError, TdxSuccess, tdvmcall_result, tdx_recoverable_error, tdx_result};
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::X86GeneralRegs;
use crate::cpu::cpuid::CpuidResult;
use crate::error::SvsmError;
use crate::mm::pagetable::PageFrame;
use crate::mm::{PerCPUPageMappingGuard, virt_to_frame};
use crate::types::{PAGE_SHIFT, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::MemoryRegion;

use bitfield_struct::bitfield;
use bitflags::bitflags;
use core::arch::asm;

const TDG_VP_TDVMCALL: u32 = 0;
const TDG_VP_VEINFO_GET: u32 = 3;
const TDG_MEM_PAGE_ACCEPT: u32 = 6;
const TDG_VM_RD: u32 = 7;

const TDVMCALL_CPUID: u32 = 10;
const TDVMCALL_HLT: u32 = 12;
const TDVMCALL_IO: u32 = 30;
const TDVMCALL_RDMSR: u32 = 31;
const TDVMCALL_WRMSR: u32 = 32;
const TDVMCALL_MAP_GPA: u32 = 0x10001;
const TDVMCALL_REPORT_FATAL_ERROR: u32 = 0x10003;

pub const MD_TDCS_NUM_L2_VMS: u64 = 0x9010_0001_0000_0005;

bitflags! {
    /// Register bitmap to indicate which registers are passed to host
    /// during a TDVMCALL.
    #[derive(Copy, Clone, Debug)]
    struct TdxRegs: u64 {
        const RDX = 1 << 2;
        const RBX = 1 << 3;
        const RSI = 1 << 6;
        const RDI = 1 << 7;
        const R8 = 1 << 8;
        const R9 = 1 << 9;
        const R10 = 1 << 10;
        const R11 = 1 << 11;
        const R12 = 1 << 12;
        const R13 = 1 << 13;
        const R14 = 1 << 14;
        const R15 = 1 << 15;
    }
}

/// Virtualization exception information
#[derive(Clone, Copy, Debug)]
pub struct TdVeInfo {
    pub exit_reason: u32,
    pub exit_qualification: u64,
    pub gla: u64,
    pub gpa: u64,
    pub exit_instruction_length: u32,
    pub exit_instruction_info: u32,
}

#[bitfield(u64)]
struct EptMappingInfo {
    #[bits(12)]
    pub flags: u64,
    #[bits(52)]
    pub page_frame_number: u64,
}

impl From<PageFrame> for EptMappingInfo {
    fn from(frame: PageFrame) -> Self {
        let (gpa, flags) = match frame {
            PageFrame::Size4K(gpa) => (u64::from(gpa), 0),
            PageFrame::Size2M(gpa) => (u64::from(gpa), 1),
            PageFrame::Size1G(gpa) => (u64::from(gpa), 2),
        };
        Self::new()
            .with_flags(flags)
            .with_page_frame_number(gpa >> PAGE_SHIFT)
    }
}

/// # Safety
/// This function has the potential to zero arbitrary memory, so the caller is
/// required to ensure that the supplied physical address range is appropriate
/// for acceptance.
unsafe fn tdg_mem_page_accept(frame: PageFrame) -> u64 {
    loop {
        // SAFETY: executing TDCALL requires the use of assembly.  The caller
        // takes responsibility for correctness of the parameters.
        let err = unsafe {
            let mut ret: u64;
            asm!("tdcall",
                 in("rax") TDG_MEM_PAGE_ACCEPT,
                 in("rcx") EptMappingInfo::from(frame).into_bits(),
                 lateout("rax") ret,
                 options(att_syntax));
            ret
        };
        if !tdx_recoverable_error(err) {
            return err;
        }
    }
}

/// # Safety
/// This function will zero arbitrary memory, so the caller is required to
/// ensure that the supplied physical address range is appropriate for
/// acceptance.  The caller is additionally required to ensure that the address
/// range is appropriate aligned to 4 KB boundaries.
pub unsafe fn td_accept_physical_memory(region: MemoryRegion<PhysAddr>) -> Result<(), SvsmError> {
    let mut addr = region.start();
    if !addr.is_aligned(PAGE_SIZE) {
        return Err(SvsmError::InvalidAddress);
    }

    let end = region.end();

    while addr < end {
        if addr.is_aligned(PAGE_SIZE_2M) && addr + PAGE_SIZE_2M <= end {
            // SAFETY: the caller takes responsibility for the correct usage of
            // the physical address.
            let ret = unsafe { tdx_result(tdg_mem_page_accept(PageFrame::Size2M(addr))) };
            match ret {
                Ok(s) => {
                    if s == TdxSuccess::PageAlreadyAccepted {
                        // The caller is expected not to accept a page twice
                        // unless doing so is known to be safe.  If the TDX
                        // module indicates that the page was already accepted,
                        // it must mean that the page was not removed after a
                        // previous attempt to accept.  In this case, the page
                        // must be zeroed now because the caller expects every
                        // accepted page to be zeroed.
                        // SAFETY: the caller takes responsibility for the
                        // correct usage of the physical address.
                        unsafe {
                            let mapping =
                                PerCPUPageMappingGuard::create(addr, addr + PAGE_SIZE_2M, 0)?;
                            mapping
                                .virt_addr()
                                .as_mut_ptr::<u8>()
                                .write_bytes(0, PAGE_SIZE_2M);
                        }
                    }
                    addr = addr + PAGE_SIZE_2M;
                    continue;
                }
                Err(TdxError::PageSizeMismatch) => {
                    // Fall through to the 4 KB path below.
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }

        // SAFETY: the caller takes responsibility for the correct usage of the
        // physical address.
        let ret = unsafe { tdx_result(tdg_mem_page_accept(PageFrame::Size4K(addr))) };
        match ret {
            Ok(s) => {
                if s == TdxSuccess::PageAlreadyAccepted {
                    // Zero the 4 KB page.
                    // SAFETY: the caller takes responsibility for the correct
                    // usage of the physical address.
                    unsafe {
                        let mapping = PerCPUPageMappingGuard::create(addr, addr + PAGE_SIZE, 0)?;
                        mapping
                            .virt_addr()
                            .as_mut_ptr::<u8>()
                            .write_bytes(0, PAGE_SIZE);
                    }
                }
                addr = addr + PAGE_SIZE;
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

/// # Safety
/// This function will zero arbitrary memory, so the caller is required to
/// ensure that the supplied virtual address range is appropriate for
/// acceptance.  The caller is additionally required to ensure that the address
/// range is appropriate aligned to 4 KB boundaries.
unsafe fn td_accept_virtual_4k(vaddr: VirtAddr, paddr: PhysAddr) -> Result<(), SvsmError> {
    // SAFETY: the caller takes responsibility for the correct usage of the
    // physical address.
    let ret = unsafe { tdx_result(tdg_mem_page_accept(PageFrame::Size4K(paddr))) };
    match ret {
        Ok(s) => {
            if s == TdxSuccess::PageAlreadyAccepted {
                // Zero the 4 KB page.
                // SAFETY: the caller takes responsibility for the correct
                // usage of the virtual address.
                unsafe {
                    vaddr.as_mut_ptr::<u8>().write_bytes(0, PAGE_SIZE);
                }
            }
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// # Safety
/// This function will zero arbitrary memory, so the caller is required to
/// ensure that the supplied virtual address range is appropriate for
/// acceptance.  The caller is additionally required to ensure that the address
/// range is appropriate aligned to 4 KB boundaries.
unsafe fn td_accept_virtual_2m(vaddr: VirtAddr, paddr: PhysAddr) -> Result<(), SvsmError> {
    // SAFETY: the caller takes responsibility for the correct usage of the
    // physical address.
    let ret = unsafe { tdx_result(tdg_mem_page_accept(PageFrame::Size2M(paddr))) };
    match ret {
        Ok(s) => {
            if s == TdxSuccess::PageAlreadyAccepted {
                // Zero the 2M page.
                // SAFETY: the caller takes responsibility for the correct
                // usage of the virtual address.
                unsafe {
                    vaddr.as_mut_ptr::<u8>().write_bytes(0, PAGE_SIZE_2M);
                }
            }
            Ok(())
        }
        Err(TdxError::PageSizeMismatch) => {
            // Process this 2 MB page as a series of 4 KB pages.
            for offset in 0usize..512usize {
                // SAFETY: the caller takes responsibility for the correct
                // usage of the physical address.
                unsafe {
                    td_accept_virtual_4k(
                        vaddr + (offset << PAGE_SHIFT),
                        paddr + (offset << PAGE_SHIFT),
                    )?;
                }
            }
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// # Safety
/// This function will zero arbitrary memory, so the caller is required to
/// ensure that the supplied virtual address range is appropriate for
/// acceptance.  The caller is additionally required to ensure that the address
/// range is appropriate aligned to 4 KB boundaries.
pub unsafe fn td_accept_virtual_memory(region: MemoryRegion<VirtAddr>) -> Result<(), SvsmError> {
    let mut vaddr = region.start();
    if !vaddr.is_aligned(PAGE_SIZE) {
        return Err(SvsmError::InvalidAddress);
    }

    let vaddr_end = region.end();
    while vaddr < vaddr_end {
        let frame = virt_to_frame(vaddr);
        let size = if vaddr.is_aligned(PAGE_SIZE_2M)
            && vaddr + PAGE_SIZE_2M <= vaddr_end
            && frame.size() >= PAGE_SIZE_2M
        {
            // SAFETY: the caller takes responsibility for the correct usage of
            // the virtual address.
            unsafe {
                td_accept_virtual_2m(vaddr, frame.address())?;
            }
            PAGE_SIZE_2M
        } else {
            // SAFETY: the caller takes responsibility for the correct usage of
            // the virtual address.
            unsafe {
                td_accept_virtual_4k(vaddr, frame.address())?;
            }
            PAGE_SIZE
        };

        vaddr = vaddr + size;
    }
    Ok(())
}

pub fn tdcall_get_ve_info() -> Option<TdVeInfo> {
    let mut out_rcx: u64;
    let mut out_rdx: u64;
    let mut out_r8: u64;
    let mut out_r9: u64;
    let mut out_r10: u64;
    // SAFETY: executing TDCALL requires the use of assembly.
    let err = unsafe {
        let mut ret: u64;
        asm!("tdcall",
             in("rax") TDG_VP_VEINFO_GET,
             lateout("rax") ret,
             out("rcx") out_rcx,
             out("rdx") out_rdx,
             out("r8") out_r8,
             out("r9") out_r9,
             out("r10") out_r10,
             options(att_syntax));
        ret
    };
    match tdx_result(err) {
        Ok(_) => Some(TdVeInfo {
            exit_reason: out_rcx as u32,
            exit_qualification: out_rdx,
            gla: out_r8,
            gpa: out_r9,
            exit_instruction_length: out_r10 as u32,
            exit_instruction_info: ((out_r10 >> 32) as u32),
        }),
        Err(TdxError::NoVeInfo) => None,
        Err(e) => panic!("Unknown TD error: {e:?}"),
    }
}

pub fn tdcall_vm_read(field: u64) -> u64 {
    let (val, err) = loop {
        let mut val: u64;
        // SAFETY: executing TDCALL requires the use of assembly.
        let err = unsafe {
            let mut ret: u64;
            asm!("tdcall",
                 in("rax") TDG_VM_RD,
                 in("rcx") 0,
                 in("rdx") field,
                 lateout("rax") ret,
                 lateout("rdx") _,
                 out("r8") val,
                 options(att_syntax));
            ret
        };
        if !tdx_recoverable_error(err) {
            break (val, err);
        }
    };
    // Ignore errors here since the caller cannot handle them.
    debug_assert!(tdx_result(err).is_ok());
    // val = 0 in case of no success.
    val
}

pub fn tdvmcall_map_gpa(mut gpa: u64, size: u64) -> Result<(), TdxError> {
    let pass_regs = TdxRegs::R10 | TdxRegs::R11 | TdxRegs::R12 | TdxRegs::R13;
    let end = gpa + size;
    loop {
        let mut ret: u64;
        let mut vmcall_ret: u64;
        let mut retry_gpa: u64;
        // SAFETY: executing TDCALL requires the use of assembly.
        unsafe {
            asm!("tdcall",
                 in("rax") TDG_VP_TDVMCALL,
                 in("rcx") pass_regs.bits(),
                 in("r10") 0,
                 in("r11") TDVMCALL_MAP_GPA,
                 in("r12") gpa,
                 in("r13") end - gpa,
                 lateout("rax") ret,
                 lateout("r10") vmcall_ret,
                 lateout("r11") retry_gpa,
                 options(att_syntax));
        }

        debug_assert!(tdx_result(ret).is_ok());
        let err = tdvmcall_result(vmcall_ret);

        // If a retry was requested, then reissue the call as requested by the
        // host.  No validation is performed on this value because it is
        // being passed to an untrusted host.
        if err != Err(TdxError::Vmcall(Retry)) {
            return err;
        }

        gpa = retry_gpa;
    }
}

pub fn tdvmcall_cpuid(cpuid_fn: u32, cpuid_subfn: u32) -> CpuidResult {
    let pass_regs =
        TdxRegs::R10 | TdxRegs::R11 | TdxRegs::R12 | TdxRegs::R13 | TdxRegs::R14 | TdxRegs::R15;
    let mut ret: u64;
    let mut vmcall_ret: u64;
    let mut result_eax: u32;
    let mut result_ebx: u32;
    let mut result_ecx: u32;
    let mut result_edx: u32;
    // SAFETY: executing TDCALL requires the use of assembly.
    unsafe {
        asm!("tdcall",
             in("rax") TDG_VP_TDVMCALL,
             in("rcx") pass_regs.bits(),
             in("r10") 0,
             in("r11") TDVMCALL_CPUID,
             in("r12") cpuid_fn,
             in("r13") cpuid_subfn,
             lateout("rax") ret,
             lateout("r10") vmcall_ret,
             lateout("r11") _,
             lateout("r12") result_eax,
             lateout("r13") result_ebx,
             lateout("r14") result_ecx,
             lateout("r15") result_edx,
             options(att_syntax));
    }
    // r10 is expected to be TDG.VP.VMCALL_SUCCESS per the GHCI spec
    // Make sure the result matches the expectation
    debug_assert!(tdvmcall_result(vmcall_ret).is_ok());
    debug_assert!(tdx_result(ret).is_ok());

    CpuidResult {
        eax: result_eax,
        ebx: result_ebx,
        ecx: result_ecx,
        edx: result_edx,
    }
}

pub fn tdvmcall_rdmsr(msr: u32) -> u64 {
    let pass_regs = TdxRegs::R10 | TdxRegs::R11 | TdxRegs::R12;
    let mut ret: u64;
    let mut vmcall_ret: u64;
    let mut result: u64;

    // SAFETY: executing TDCALL requires the use of assembly.
    unsafe {
        asm!("tdcall",
             in("rax") TDG_VP_TDVMCALL,
             in("rcx") pass_regs.bits(),
             in("r10") 0,
             in("r11") TDVMCALL_RDMSR,
             in("r12") msr as u64,
             lateout("rax") ret,
             lateout("r10") vmcall_ret,
             lateout("r11") result,
             options(att_syntax));
    }
    // r10 is expected to be TDG.VP.VMCALL_SUCCESS per the GHCI spec
    // Make sure the result matches the expectation
    debug_assert!(tdvmcall_result(vmcall_ret).is_ok());
    debug_assert!(tdx_result(ret).is_ok());

    result
}

pub fn tdvmcall_wrmsr(msr: u32, value: u64) {
    let pass_regs = TdxRegs::R10 | TdxRegs::R11 | TdxRegs::R12 | TdxRegs::R13;
    let mut ret: u64;
    let mut vmcall_ret: u64;

    // SAFETY: executing TDCALL requires the use of assembly.
    unsafe {
        asm!("tdcall",
             in("rax") TDG_VP_TDVMCALL,
             in("rcx") pass_regs.bits(),
             in("r10") 0,
             in("r11") TDVMCALL_WRMSR,
             in("r12") msr as u64,
             in("r13") value,
             lateout("rax") ret,
             lateout("r10") vmcall_ret,
             options(att_syntax));
    }
    // r10 is expected to be TDG.VP.VMCALL_SUCCESS per the GHCI spec
    // Make sure the result matches the expectation
    debug_assert!(tdvmcall_result(vmcall_ret).is_ok());
    debug_assert!(tdx_result(ret).is_ok());
}

#[derive(Clone, Copy, Debug)]
pub enum TdpHaltInterruptState {
    Enabled,
    Disabled,
}

pub fn tdvmcall_halt(interrupt_state: TdpHaltInterruptState) {
    let pass_regs = TdxRegs::R10 | TdxRegs::R11 | TdxRegs::R12;
    let interrupts_blocked = match interrupt_state {
        TdpHaltInterruptState::Enabled => 0,
        TdpHaltInterruptState::Disabled => 1,
    };
    let mut ret: u64;
    let mut vmcall_ret: u64;
    // SAFETY: executing TDCALL requires the use of assembly.
    unsafe {
        asm!("pushfq",
             "test %r12d, %r12d",
             "jnz 1f",
             "sti",
             "1:",
             "tdcall",
             "popfq",
             in("rax") TDG_VP_TDVMCALL,
             in("rcx") pass_regs.bits(),
             in("r10") 0,
             in("r11") TDVMCALL_HLT,
             in("r12") interrupts_blocked,
             lateout("rax") ret,
             lateout("r10") vmcall_ret,
             lateout("r11") _,
             lateout("r12") _,
             options(att_syntax));
    }
    // r10 is expected to be TDG.VP.VMCALL_SUCCESS per the GHCI spec
    // Make sure the result matches the expectation
    debug_assert!(tdvmcall_result(vmcall_ret).is_ok());
    debug_assert!(tdx_result(ret).is_ok());
}

/// R12 bitfield for `TDVMCALL_REPORT_FATAL_ERROR`.
#[bitfield(u64)]
struct FatalErrorR12 {
    error_code: u32,
    #[bits(31)]
    ext_error_code: u32,
    gpa_valid: bool,
}

pub fn tdvmcall_report_fatal_error() -> ! {
    let pass_regs = TdxRegs::R10 | TdxRegs::R11 | TdxRegs::R12;
    // Default error code (0)
    let r12 = FatalErrorR12::new();

    // This TDCALL is not supposed to return, but guard against
    // a non-cooperating host with an infinite loop, ensuring
    // execution never leaves this function.
    loop {
        // SAFETY: executing TDCALL requires the use of assembly.
        unsafe {
            asm!("tdcall",
                 in("rax") TDG_VP_TDVMCALL,
                 in("rcx") pass_regs.bits(),
                 in("r10") 0,
                 in("r11") TDVMCALL_REPORT_FATAL_ERROR,
                 in("r12") r12.into_bits(),
            );
        }
    }
}

fn tdvmcall_io(port: u16, data: u32, size: usize, write: bool) -> u32 {
    let pass_regs =
        TdxRegs::R10 | TdxRegs::R11 | TdxRegs::R12 | TdxRegs::R13 | TdxRegs::R14 | TdxRegs::R15;
    let mut ret: u64;
    let mut vmcall_ret: u64;
    let mut output: u32;
    // SAFETY: executing TDCALL requires the use of assembly.
    unsafe {
        asm!("tdcall",
             in("rax") TDG_VP_TDVMCALL,
             in("rcx") pass_regs.bits(),
             in("r10") 0,
             in("r11") TDVMCALL_IO,
             in("r12") size,
             in("r13") write as u32,
             in("r14") port as u32,
             in("r15") data,
             lateout("rax") ret,
             lateout("r10") vmcall_ret,
             lateout("r11") output,
             lateout("r12") _,
             lateout("r13") _,
             lateout("r14") _,
             lateout("r15") _,
             options(att_syntax));
    }

    // Ignore errors here.  The caller cannot handle them, and since the
    // I/O operation was performed by an untrusted source, the error
    // information is not meaningfully different than a maliciously unreliable
    // operation.
    debug_assert!(tdvmcall_result(vmcall_ret).is_ok());
    debug_assert!(tdx_result(ret).is_ok());

    output
}

pub fn tdvmcall_io_write<T>(port: u16, data: T)
where
    u32: From<T>,
{
    let _ = tdvmcall_io(port, u32::from(data), size_of::<T>(), true);
}

pub fn tdvmcall_io_read<T>(port: u16) -> u32 {
    tdvmcall_io(port, 0, size_of::<T>(), false)
}

pub fn tdvmcall_hyperv_hypercall(regs: &mut X86GeneralRegs) {
    let pass_regs = TdxRegs::RDX | TdxRegs::R8 | TdxRegs::R10 | TdxRegs::R11;
    let mut ret: u64;
    let mut vmcall_ret: u64;
    let mut hypercall_ret: u64;
    // A Hyper-V hypercall uses VMCALL but does not use the standard GHCI
    // convention.  The distinction is encoded in R10, which always passes
    // zero for GHCI calls, and which passes the Hyper-V hypercall code (which
    // is never zero) in the case of hypercalls.
    debug_assert_ne!({ regs.rcx }, 0);
    // SAFETY: executing TDCALL requires the use of assembly.
    unsafe {
        asm!("tdcall",
             in("rax") TDG_VP_TDVMCALL,
             in("rcx") pass_regs.bits(),
             in("r10") regs.rcx,
             in("rdx") regs.rdx,
             in("r8") regs.r8,
             lateout("rax") ret,
             lateout("r10") vmcall_ret,
             lateout("r11") hypercall_ret,
             options(att_syntax));
    }

    // Ignore errors here.  The caller cannot handle them, and the final
    // status is not trustworthy anyway.
    debug_assert!(tdx_result(ret).is_ok());
    debug_assert!(tdvmcall_result(vmcall_ret).is_ok());

    regs.rax = hypercall_ret as usize;
}

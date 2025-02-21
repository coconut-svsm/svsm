// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use super::error::{tdvmcall_result, tdx_recoverable_error, tdx_result, TdxError, TdxSuccess};
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::cpuid::CpuidResult;
use crate::error::SvsmError;
use crate::mm::pagetable::PageFrame;
use crate::mm::{virt_to_frame, PerCPUPageMappingGuard};
use crate::types::{PAGE_SHIFT, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::MemoryRegion;

use bitfield_struct::bitfield;
use core::arch::asm;

const TDG_VP_TDVMCALL: u32 = 0;
const TDG_MEM_PAGE_ACCEPT: u32 = 6;

const TDVMCALL_CPUID: u32 = 10;
const TDVMCALL_HLT: u32 = 12;
const TDVMCALL_IO: u32 = 30;

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

pub fn tdvmcall_cpuid(cpuid_fn: u32, cpuid_subfn: u32) -> CpuidResult {
    let pass_regs = (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 15);
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
             in("rcx") pass_regs,
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

pub fn tdvmcall_halt() {
    let pass_regs = (1 << 10) | (1 << 11) | (1 << 12);
    let mut ret: u64;
    let mut vmcall_ret: u64;
    // SAFETY: executing TDCALL requires the use of assembly.
    unsafe {
        asm!("tdcall",
             in("rax") TDG_VP_TDVMCALL,
             in("rcx") pass_regs,
             in("r10") 0,
             in("r11") TDVMCALL_HLT,
             in("r12") 0,
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

fn tdvmcall_io(port: u16, data: u32, size: usize, write: bool) -> u32 {
    let pass_regs = (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 15);
    let mut ret: u64;
    let mut vmcall_ret: u64;
    let mut output: u32;
    // SAFETY: executing TDCALL requires the use of assembly.
    unsafe {
        asm!("tdcall",
             in("rax") TDG_VP_TDVMCALL,
             in("rcx") pass_regs,
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

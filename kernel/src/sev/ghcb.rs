// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::msr::{write_msr, SEV_GHCB};
use crate::cpu::percpu::this_cpu;
use crate::cpu::{flush_tlb_global_sync, IrqGuard, X86GeneralRegs};
use crate::error::SvsmError;
use crate::mm::validate::{
    valid_bitmap_clear_valid_4k, valid_bitmap_set_valid_4k, valid_bitmap_valid_addr,
};
use crate::mm::virt_to_phys;
use crate::platform::PageStateChangeOp;
use crate::sev::hv_doorbell::HVDoorbell;
use crate::sev::utils::raw_vmgexit;
use crate::types::{Bytes, PageSize, GUEST_VMPL, PAGE_SIZE_2M};
use crate::utils::MemoryRegion;

use crate::mm::PageBox;
use core::arch::global_asm;
use core::mem::{self, offset_of};
use core::ops::Deref;
use core::ptr;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::msr_protocol::{invalidate_page_msr, register_ghcb_gpa_msr, validate_page_msr};
use super::{pvalidate, PvalidateOp};

use zerocopy::{FromZeros, Immutable, IntoBytes};

#[repr(C, packed)]
#[derive(Debug, Default, Clone, Copy, IntoBytes, Immutable)]
pub struct PageStateChangeHeader {
    cur_entry: u16,
    end_entry: u16,
    reserved: u32,
}

const PSC_GFN_MASK: u64 = ((1u64 << 52) - 1) & !0xfffu64;

const PSC_OP_SHIFT: u8 = 52;
const PSC_OP_PRIVATE: u64 = 1 << PSC_OP_SHIFT;
const PSC_OP_SHARED: u64 = 2 << PSC_OP_SHIFT;
const PSC_OP_PSMASH: u64 = 3 << PSC_OP_SHIFT;
const PSC_OP_UNSMASH: u64 = 4 << PSC_OP_SHIFT;

const PSC_FLAG_HUGE_SHIFT: u8 = 56;
const PSC_FLAG_HUGE: u64 = 1 << PSC_FLAG_HUGE_SHIFT;

const GHCB_BUFFER_SIZE: usize = 0x7f0;

macro_rules! ghcb_getter {
    ($name:ident, $field:ident,$t:ty) => {
        #[allow(unused)]
        fn $name(&self) -> Result<$t, GhcbError> {
            self.is_valid(offset_of!(Self, $field))
                .then(|| self.$field.load(Ordering::Relaxed))
                .ok_or(GhcbError::VmgexitInvalid)
        }
    };
}

macro_rules! ghcb_setter {
    ($name:ident, $field:ident, $t:ty) => {
        #[allow(unused)]
        fn $name(&self, val: $t) {
            self.$field.store(val, Ordering::Relaxed);
            self.set_valid(offset_of!(Self, $field));
        }
    };
}

#[derive(Clone, Copy, Debug)]
pub enum GhcbError {
    // Attempted to write at an invalid offset in the GHCB
    InvalidOffset,
    // A response from the hypervisor after VMGEXIT is invalid
    VmgexitInvalid,
    // A response from the hypervisor included an error code
    VmgexitError(u64, u64),
}

impl From<GhcbError> for SvsmError {
    fn from(e: GhcbError) -> Self {
        Self::Ghcb(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
#[expect(non_camel_case_types, clippy::upper_case_acronyms)]
enum GHCBExitCode {
    RDTSC = 0x6e,
    CPUID = 0x72,
    IOIO = 0x7b,
    MSR = 0x7c,
    VMMCALL = 0x81,
    RDTSCP = 0x87,
    MMIO_READ = 0x8000_0001,
    MMIO_WRITE = 0x8000_0002,
    SNP_PSC = 0x8000_0010,
    GUEST_REQUEST = 0x8000_0011,
    GUEST_EXT_REQUEST = 0x8000_0012,
    AP_CREATE = 0x80000013,
    HV_DOORBELL = 0x8000_0014,
    HV_IPI = 0x8000_0015,
    CONFIGURE_INT_INJ = 0x8000_001B,
    DISABLE_ALT_INJ = 0x8000_001C,
    SPECIFIC_EOI = 0x8000_001D,
}

#[derive(Clone, Copy, Debug)]
pub enum GHCBIOSize {
    Size8,
    Size16,
    Size32,
}

impl TryFrom<Bytes> for GHCBIOSize {
    type Error = SvsmError;

    fn try_from(size: Bytes) -> Result<GHCBIOSize, Self::Error> {
        match size {
            Bytes::One => Ok(GHCBIOSize::Size8),
            Bytes::Two => Ok(GHCBIOSize::Size16),
            Bytes::Four => Ok(GHCBIOSize::Size32),
            _ => Err(SvsmError::InvalidBytes),
        }
    }
}

#[derive(Debug)]
pub struct GhcbPage(PageBox<GHCB>);

impl GhcbPage {
    pub fn new() -> Result<Self, SvsmError> {
        let page = PageBox::<GHCB>::try_new_zeroed()?;
        let vaddr = page.vaddr();
        let paddr = virt_to_phys(vaddr);

        // SAFETY: we trust virt_to_phys() to return GHCB's physical address
        // since it panics if vaddr is invalid.
        unsafe {
            // Make page invalid
            pvalidate(vaddr, PageSize::Regular, PvalidateOp::Invalid)?;

            // Let the Hypervisor take the page back
            invalidate_page_msr(paddr)?;
        }

        // Needs guarding for Stage2 GHCB
        if valid_bitmap_valid_addr(paddr) {
            valid_bitmap_clear_valid_4k(paddr);
        }

        // Map page unencrypted
        this_cpu().get_pgtable().set_shared_4k(vaddr)?;
        flush_tlb_global_sync();

        // SAFETY: all zeros is a valid representation for the GHCB.
        Ok(Self(page))
    }
}

impl Drop for GhcbPage {
    fn drop(&mut self) {
        let vaddr = self.0.vaddr();
        let paddr = virt_to_phys(vaddr);

        // Re-encrypt page
        this_cpu()
            .get_pgtable()
            .set_encrypted_4k(vaddr)
            .expect("Could not re-encrypt page");

        // Unregister GHCB PA
        // SAFETY: mapping the GHCB at physical address 0 is safe.
        unsafe {
            register_ghcb_gpa_msr(PhysAddr::null()).expect("Could not unregister GHCB");
        }

        // SAFETY: we trust virt_to_phys() to return GHCB's physical address
        // since it panics if vaddr is invalid.
        unsafe {
            // Ask the hypervisor to change the page back to the private page
            // state.
            validate_page_msr(paddr).expect("Could not change page state");

            // Make page guest-valid
            pvalidate(vaddr, PageSize::Regular, PvalidateOp::Valid)
                .expect("Could not pvalidate page");
        }

        // Needs guarding for Stage2 GHCB
        if valid_bitmap_valid_addr(paddr) {
            valid_bitmap_set_valid_4k(paddr);
        }
    }
}

impl Deref for GhcbPage {
    type Target = GHCB;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

#[repr(C)]
#[derive(Debug, FromZeros)]
pub struct GHCB {
    reserved_1: [AtomicU8; 0xcb],
    cpl: AtomicU8,
    reserved_2: [AtomicU8; 0x74],
    xss: AtomicU64,
    reserved_3: [AtomicU8; 0x18],
    dr7: AtomicU64,
    reserved_4: [AtomicU8; 0x90],
    rax: AtomicU64,
    reserved_5: [AtomicU8; 0x100],
    reserved_6: AtomicU64,
    rcx: AtomicU64,
    rdx: AtomicU64,
    rbx: AtomicU64,
    reserved_7: AtomicU64,
    rbp: AtomicU64,
    rsi: AtomicU64,
    rdi: AtomicU64,
    r8: AtomicU64,
    r9: AtomicU64,
    r10: AtomicU64,
    r11: AtomicU64,
    r12: AtomicU64,
    r13: AtomicU64,
    r14: AtomicU64,
    r15: AtomicU64,
    reserved_8: [AtomicU8; 0x10],
    sw_exit_code: AtomicU64,
    sw_exit_info_1: AtomicU64,
    sw_exit_info_2: AtomicU64,
    sw_scratch: AtomicU64,
    reserved_9: [AtomicU8; 0x38],
    xcr0: AtomicU64,
    valid_bitmap: [AtomicU64; 2],
    x87_state_gpa: AtomicU64,
    reserved_10: [AtomicU8; 0x3f8],
    buffer: [AtomicU8; GHCB_BUFFER_SIZE],
    reserved_11: [AtomicU8; 0xa],
    version: AtomicU16,
    usage: AtomicU32,
}

impl GHCB {
    ghcb_getter!(get_cpl_valid, cpl, u8);
    ghcb_setter!(set_cpl_valid, cpl, u8);

    ghcb_getter!(get_xss_valid, xss, u64);
    ghcb_setter!(set_xss_valid, xss, u64);

    ghcb_getter!(get_dr7_valid, dr7, u64);
    ghcb_setter!(set_dr7_valid, dr7, u64);

    ghcb_getter!(get_rax_valid, rax, u64);
    ghcb_setter!(set_rax_valid, rax, u64);

    ghcb_getter!(get_rcx_valid, rcx, u64);
    ghcb_setter!(set_rcx_valid, rcx, u64);

    ghcb_getter!(get_rdx_valid, rdx, u64);
    ghcb_setter!(set_rdx_valid, rdx, u64);

    ghcb_getter!(get_rbx_valid, rbx, u64);
    ghcb_setter!(set_rbx_valid, rbx, u64);

    ghcb_getter!(get_r8_valid, r8, u64);
    ghcb_setter!(set_r8_valid, r8, u64);

    ghcb_getter!(get_exit_code_valid, sw_exit_code, u64);
    ghcb_setter!(set_exit_code_valid, sw_exit_code, u64);

    ghcb_getter!(get_exit_info_1_valid, sw_exit_info_1, u64);
    ghcb_setter!(set_exit_info_1_valid, sw_exit_info_1, u64);

    ghcb_getter!(get_exit_info_2_valid, sw_exit_info_2, u64);
    ghcb_setter!(set_exit_info_2_valid, sw_exit_info_2, u64);

    ghcb_getter!(get_sw_scratch_valid, sw_scratch, u64);
    ghcb_setter!(set_sw_scratch_valid, sw_scratch, u64);

    ghcb_getter!(get_sw_xcr0_valid, xcr0, u64);
    ghcb_setter!(set_sw_xcr0_valid, xcr0, u64);

    ghcb_getter!(get_sw_x87_state_gpa_valid, x87_state_gpa, u64);
    ghcb_setter!(set_sw_x87_state_gpa_valid, x87_state_gpa, u64);

    ghcb_getter!(get_version_valid, version, u16);
    ghcb_setter!(set_version_valid, version, u16);

    ghcb_getter!(get_usage_valid, usage, u32);
    ghcb_setter!(set_usage_valid, usage, u32);

    pub fn vmmcall(&self, regs: &mut X86GeneralRegs) -> Result<(), SvsmError> {
        self.clear();
        self.set_rcx_valid(regs.rcx as u64);
        self.set_rdx_valid(regs.rdx as u64);
        self.set_r8_valid(regs.r8 as u64);
        self.vmgexit(GHCBExitCode::VMMCALL, 0, 0)?;
        regs.rax = self.get_rax_valid()? as usize;
        Ok(())
    }

    pub fn cpuid(&self, eax: u32, ecx: u32) -> Result<CpuidResult, SvsmError> {
        self.clear();
        self.set_rax_valid(eax as u64);
        self.set_rcx_valid(ecx as u64);
        self.vmgexit(GHCBExitCode::CPUID, 0, 0)?;
        Ok(CpuidResult {
            eax: self.get_rax_valid()? as u32,
            ebx: self.get_rbx_valid()? as u32,
            ecx: self.get_rcx_valid()? as u32,
            edx: self.get_rdx_valid()? as u32,
        })
    }

    pub fn cpuid_regs(&self, regs: &mut X86GeneralRegs) -> Result<(), SvsmError> {
        let result = self.cpuid(regs.rax as u32, regs.rcx as u32)?;
        regs.rax = result.eax as usize;
        regs.rbx = result.ebx as usize;
        regs.rcx = result.ecx as usize;
        regs.rdx = result.edx as usize;
        Ok(())
    }

    pub fn rdtscp_regs(&self, regs: &mut X86GeneralRegs) -> Result<(), SvsmError> {
        self.clear();
        self.vmgexit(GHCBExitCode::RDTSCP, 0, 0)?;
        let rax = self.get_rax_valid()?;
        let rdx = self.get_rdx_valid()?;
        let rcx = self.get_rcx_valid()?;
        regs.rax = rax as usize;
        regs.rdx = rdx as usize;
        regs.rcx = rcx as usize;
        Ok(())
    }

    pub fn rdtsc_regs(&self, regs: &mut X86GeneralRegs) -> Result<(), SvsmError> {
        self.clear();
        self.vmgexit(GHCBExitCode::RDTSC, 0, 0)?;
        let rax = self.get_rax_valid()?;
        let rdx = self.get_rdx_valid()?;
        regs.rax = rax as usize;
        regs.rdx = rdx as usize;
        Ok(())
    }

    pub fn wrmsr(&self, msr_index: u32, value: u64) -> Result<(), SvsmError> {
        self.wrmsr_raw(msr_index as u64, value & 0xFFFF_FFFF, value >> 32)
    }

    pub fn wrmsr_regs(&self, regs: &X86GeneralRegs) -> Result<(), SvsmError> {
        self.wrmsr_raw(regs.rcx as u64, regs.rax as u64, regs.rdx as u64)
    }

    pub fn wrmsr_raw(&self, rcx: u64, rax: u64, rdx: u64) -> Result<(), SvsmError> {
        self.clear();

        self.set_rcx_valid(rcx);
        self.set_rax_valid(rax);
        self.set_rdx_valid(rdx);

        self.vmgexit(GHCBExitCode::MSR, 1, 0)?;
        Ok(())
    }

    /// Perform an MSR read via a GHCB call
    ///
    /// # Arguments
    ///
    /// - `msr_index` - MSR to read
    ///
    /// # Returns
    ///
    /// On a successful call, returns `Result` with a tuple `(u32, u32)`. The
    /// first value is the `RAX` and the second the `RDX` register. On failure
    /// a `Result` with `SvsmError` is returned.
    pub fn rdmsr_raw(&self, msr_index: u32) -> Result<(u32, u32), SvsmError> {
        self.clear();
        self.set_rcx_valid(msr_index as u64);
        self.vmgexit(GHCBExitCode::MSR, 0, 0)?;
        let eax: u32 = (self.get_rax_valid()? & 0xFFFFFFFF) as u32;
        let edx: u32 = (self.get_rdx_valid()? & 0xFFFFFFFF) as u32;
        Ok((eax, edx))
    }

    /// Perform an MSR read via a GHCB call an return a `u64` value.
    ///
    /// # Arguments
    ///
    /// - `msr_index` - MSR to read
    ///
    /// # Returns
    ///
    /// On a successful call, returns `Result` with a `u64` value. On failure
    /// a `Result` with `SvsmError` is returned.
    pub fn rdmsr(&self, msr_index: u32) -> Result<u64, SvsmError> {
        let (rax, rdx) = self.rdmsr_raw(msr_index)?;
        Ok((rax as u64) | ((rdx as u64) << 32))
    }

    pub fn rdmsr_regs(&self, regs: &mut X86GeneralRegs) -> Result<(), SvsmError> {
        let (rax, rdx) = self.rdmsr_raw(u32::try_from(regs.rcx).unwrap())?;
        regs.rdx = rdx as usize;
        regs.rax = rax as usize;
        Ok(())
    }

    pub fn register(&self) -> Result<(), SvsmError> {
        let vaddr = VirtAddr::from(self as *const GHCB);
        let paddr = virt_to_phys(vaddr);

        // Register GHCB GPA
        // SAFETY: we trust virt_to_phys() to return self's physical address
        // since it panics if vaddr is invalid.
        unsafe { Ok(register_ghcb_gpa_msr(paddr)?) }
    }

    pub fn clear(&self) {
        // Clear valid bitmap
        self.valid_bitmap[0].store(0, Ordering::Relaxed);
        self.valid_bitmap[1].store(0, Ordering::Relaxed);

        // Mark valid_bitmap valid
        let off = offset_of!(Self, valid_bitmap);
        self.set_valid(off);
        self.set_valid(off + mem::size_of::<u64>());
    }

    fn set_valid(&self, offset: usize) {
        let bit: usize = (offset >> 3) & 0x3f;
        let index: usize = (offset >> 9) & 0x1;
        let mask: u64 = 1 << bit;

        self.valid_bitmap[index].fetch_or(mask, Ordering::Relaxed);
    }

    fn is_valid(&self, offset: usize) -> bool {
        let bit: usize = (offset >> 3) & 0x3f;
        let index: usize = (offset >> 9) & 0x1;
        let mask: u64 = 1 << bit;

        (self.valid_bitmap[index].load(Ordering::Relaxed) & mask) == mask
    }

    fn vmgexit(
        &self,
        exit_code: GHCBExitCode,
        exit_info_1: u64,
        exit_info_2: u64,
    ) -> Result<(), GhcbError> {
        // GHCB is version 2
        self.set_version_valid(2);
        // GHCB Follows standard format
        self.set_usage_valid(0);
        self.set_exit_code_valid(exit_code as u64);
        self.set_exit_info_1_valid(exit_info_1);
        self.set_exit_info_2_valid(exit_info_2);

        let ghcb_address = VirtAddr::from(self as *const GHCB);
        let ghcb_pa = u64::from(virt_to_phys(ghcb_address));
        // Disable interrupts between writing the MSR and making the GHCB call
        // to prevent reentrant use of the GHCB MSR.
        let guard = IrqGuard::new();
        // SAFETY: GHCB is already allocated and setup so this is safe.
        unsafe {
            write_msr(SEV_GHCB, ghcb_pa);
        }
        raw_vmgexit();
        drop(guard);

        let sw_exit_info_1 = self.get_exit_info_1_valid()?;
        if sw_exit_info_1 != 0 {
            return Err(GhcbError::VmgexitError(
                sw_exit_info_1,
                self.sw_exit_info_2.load(Ordering::Relaxed),
            ));
        }

        Ok(())
    }

    pub fn ioio_in(&self, port: u16, size: GHCBIOSize) -> Result<u64, SvsmError> {
        self.clear();

        let mut info: u64 = 1; // IN instruction

        info |= (port as u64) << 16;

        match size {
            GHCBIOSize::Size8 => info |= 1 << 4,
            GHCBIOSize::Size16 => info |= 1 << 5,
            GHCBIOSize::Size32 => info |= 1 << 6,
        }

        self.vmgexit(GHCBExitCode::IOIO, info, 0)?;
        let rax = self.get_rax_valid()?;
        Ok(rax)
    }

    pub fn ioio_out(&self, port: u16, size: GHCBIOSize, value: u64) -> Result<(), SvsmError> {
        self.clear();

        let mut info: u64 = 0; // OUT instruction

        info |= (port as u64) << 16;

        match size {
            GHCBIOSize::Size8 => info |= 1 << 4,
            GHCBIOSize::Size16 => info |= 1 << 5,
            GHCBIOSize::Size32 => info |= 1 << 6,
        }

        self.set_rax_valid(value);
        self.vmgexit(GHCBExitCode::IOIO, info, 0)?;
        Ok(())
    }

    fn write_buffer<T>(&self, data: &T, offset: usize) -> Result<(), GhcbError>
    where
        T: IntoBytes + Immutable,
    {
        let src = data.as_bytes();
        self.write_buffer_slice(src, offset)
    }

    fn write_buffer_slice(&self, data: &[u8], offset: usize) -> Result<(), GhcbError> {
        let dst = &self
            .buffer
            .get(offset..)
            .ok_or(GhcbError::InvalidOffset)?
            .get(..data.len())
            .ok_or(GhcbError::InvalidOffset)?;
        for (dst, src) in dst.iter().zip(data.iter().copied()) {
            dst.store(src, Ordering::Relaxed);
        }
        Ok(())
    }

    fn read_buffer_slice(&self, data: &mut [u8], offset: usize) -> Result<(), GhcbError> {
        let src = &self
            .buffer
            .get(offset..)
            .ok_or(GhcbError::InvalidOffset)?
            .get(..data.len())
            .ok_or(GhcbError::InvalidOffset)?;
        for (d, s) in data.iter_mut().zip(src.iter()) {
            *d = s.load(Ordering::Relaxed);
        }
        Ok(())
    }

    fn pepare_buffer(&self) {
        let buffer_va = VirtAddr::from(self.buffer.as_ptr());
        let buffer_pa = u64::from(virt_to_phys(buffer_va));
        self.set_sw_scratch_valid(buffer_pa);
    }

    /// Perfrom a write to a memory-mapped IO area
    ///
    /// # Safety
    ///
    /// Caller must ensure that `pa` points to a properly aligned memory location and the
    /// memory accessed is part of a valid MMIO range.
    pub unsafe fn mmio_write(&self, pa: PhysAddr, value: &[u8]) -> Result<(), SvsmError> {
        self.clear();
        self.write_buffer_slice(value, 0)?;
        self.pepare_buffer();
        self.vmgexit(GHCBExitCode::MMIO_WRITE, u64::from(pa), value.len() as u64)?;
        Ok(())
    }

    /// Perfrom a read from a memory-mapped IO area
    ///
    /// # Safety
    ///
    /// Caller must ensure that `pa` points to a properly aligned memory location and the
    /// memory accessed is part of a valid MMIO range.
    pub unsafe fn mmio_read(&self, pa: PhysAddr, value: &mut [u8]) -> Result<(), SvsmError> {
        self.clear();
        self.pepare_buffer();
        self.vmgexit(GHCBExitCode::MMIO_READ, u64::from(pa), value.len() as u64)?;
        self.read_buffer_slice(value, 0)?;
        Ok(())
    }

    pub fn psc_entry(
        &self,
        paddr: PhysAddr,
        op_mask: u64,
        current_page: u64,
        size: PageSize,
    ) -> u64 {
        assert!(size == PageSize::Regular || paddr.is_aligned(PAGE_SIZE_2M));

        let mut entry: u64 =
            ((paddr.bits() as u64) & PSC_GFN_MASK) | op_mask | (current_page & 0xfffu64);
        if size == PageSize::Huge {
            entry |= PSC_FLAG_HUGE;
        }

        entry
    }

    pub fn page_state_change(
        &self,
        region: MemoryRegion<PhysAddr>,
        size: PageSize,
        op: PageStateChangeOp,
    ) -> Result<(), SvsmError> {
        // Maximum entries (8 bytes each_ minus 8 bytes for header
        let max_entries: u16 = ((GHCB_BUFFER_SIZE - 8) / 8).try_into().unwrap();
        let mut entries: u16 = 0;
        let mut paddr = region.start();
        let end = region.end();
        let op_mask: u64 = match op {
            PageStateChangeOp::Private => PSC_OP_PRIVATE,
            PageStateChangeOp::Shared => PSC_OP_SHARED,
            PageStateChangeOp::Psmash => PSC_OP_PSMASH,
            PageStateChangeOp::Unsmash => PSC_OP_UNSMASH,
        };

        self.clear();

        while paddr < end {
            let size = if size == PageSize::Huge
                && paddr.is_aligned(PAGE_SIZE_2M)
                && paddr + PAGE_SIZE_2M <= end
            {
                PageSize::Huge
            } else {
                PageSize::Regular
            };
            let pgsize = usize::from(size);
            let entry = self.psc_entry(paddr, op_mask, 0, size);
            let offset = usize::from(entries) * 8 + 8;
            self.write_buffer(&entry, offset)?;
            entries += 1;
            paddr = paddr + pgsize;

            if entries == max_entries || paddr >= end {
                let header = PageStateChangeHeader {
                    cur_entry: 0,
                    end_entry: entries - 1,
                    reserved: 0,
                };
                self.write_buffer(&header, 0)?;

                self.pepare_buffer();

                if let Err(mut e) = self.vmgexit(GHCBExitCode::SNP_PSC, 0, 0) {
                    if let Err(err) = self.get_exit_info_2_valid() {
                        e = err;
                    }

                    if let GhcbError::VmgexitError(_, info2) = e {
                        let info_high: u32 = (info2 >> 32) as u32;
                        let info_low: u32 = (info2 & 0xffff_ffffu64) as u32;
                        log::error!(
                            "GHCB SnpPageStateChange failed err_high: {:#x} err_low: {:#x}",
                            info_high,
                            info_low
                        );
                    }
                    return Err(e.into());
                }

                entries = 0;
            }
        }

        Ok(())
    }

    pub fn ap_create(
        &self,
        vmsa_gpa: PhysAddr,
        apic_id: u64,
        vmpl: u64,
        sev_features: u64,
    ) -> Result<(), SvsmError> {
        self.clear();
        let exit_info_1: u64 = 1 | (vmpl & 0xf) << 16 | apic_id << 32;
        let exit_info_2: u64 = vmsa_gpa.into();
        self.set_rax_valid(sev_features);
        self.vmgexit(GHCBExitCode::AP_CREATE, exit_info_1, exit_info_2)?;
        Ok(())
    }

    pub fn register_guest_vmsa(
        &self,
        vmsa_gpa: PhysAddr,
        apic_id: u64,
        vmpl: u64,
        sev_features: u64,
    ) -> Result<(), SvsmError> {
        self.clear();
        let exit_info_1: u64 = (vmpl & 0xf) << 16 | apic_id << 32;
        let exit_info_2: u64 = vmsa_gpa.into();
        self.set_rax_valid(sev_features);
        self.vmgexit(GHCBExitCode::AP_CREATE, exit_info_1, exit_info_2)?;
        Ok(())
    }

    pub fn register_hv_doorbell(&self, paddr: PhysAddr) -> Result<(), SvsmError> {
        self.clear();
        self.vmgexit(GHCBExitCode::HV_DOORBELL, 1, u64::from(paddr))?;
        Ok(())
    }

    pub fn guest_request(&self, req_page: VirtAddr, resp_page: VirtAddr) -> Result<(), SvsmError> {
        self.clear();

        let info1: u64 = u64::from(virt_to_phys(req_page));
        let info2: u64 = u64::from(virt_to_phys(resp_page));

        self.vmgexit(GHCBExitCode::GUEST_REQUEST, info1, info2)?;

        let sw_exit_info_2 = self.get_exit_info_2_valid()?;
        if sw_exit_info_2 != 0 {
            return Err(GhcbError::VmgexitError(
                self.sw_exit_info_1.load(Ordering::Relaxed),
                sw_exit_info_2,
            )
            .into());
        }

        Ok(())
    }

    pub fn guest_ext_request(
        &self,
        req_page: VirtAddr,
        resp_page: VirtAddr,
        data_pages: VirtAddr,
        data_size: u64,
    ) -> Result<(), SvsmError> {
        self.clear();

        let info1: u64 = u64::from(virt_to_phys(req_page));
        let info2: u64 = u64::from(virt_to_phys(resp_page));
        let rax: u64 = u64::from(virt_to_phys(data_pages));

        self.set_rax_valid(rax);
        self.set_rbx_valid(data_size);

        self.vmgexit(GHCBExitCode::GUEST_EXT_REQUEST, info1, info2)?;

        let sw_exit_info_2 = self.get_exit_info_2_valid()?;

        // On error, RBX and exit_info_2 are returned for proper error handling.
        // For an extended request, if the buffer provided is too small, the hypervisor
        // will return in RBX the number of contiguous pages required
        if sw_exit_info_2 != 0 {
            return Err(
                GhcbError::VmgexitError(self.rbx.load(Ordering::Relaxed), sw_exit_info_2).into(),
            );
        }

        Ok(())
    }

    pub fn hv_ipi(&self, icr: u64) -> Result<(), SvsmError> {
        self.clear();
        self.vmgexit(GHCBExitCode::HV_IPI, icr, 0)?;
        Ok(())
    }

    pub fn configure_interrupt_injection(&self, vector: usize) -> Result<(), SvsmError> {
        self.clear();
        self.vmgexit(GHCBExitCode::CONFIGURE_INT_INJ, vector as u64, 0)?;
        Ok(())
    }

    pub fn specific_eoi(&self, vector: u8, vmpl: u8) -> Result<(), SvsmError> {
        self.clear();
        let exit_info = ((vmpl as u64) << 16) | (vector as u64);
        self.vmgexit(GHCBExitCode::SPECIFIC_EOI, exit_info, 0)?;
        Ok(())
    }

    pub fn disable_alternate_injection(
        &self,
        tpr: u8,
        in_intr_shadow: bool,
        interrupts_enabled: bool,
    ) -> Result<(), SvsmError> {
        let mut exit_info = (GUEST_VMPL as u64) << 16;
        exit_info |= (tpr as u64) << 8;
        if in_intr_shadow {
            exit_info |= 2;
        }
        if interrupts_enabled {
            exit_info |= 1;
        }
        self.clear();
        self.vmgexit(GHCBExitCode::DISABLE_ALT_INJ, exit_info, 0)?;
        Ok(())
    }

    #[inline]
    #[cfg(test)]
    pub fn fill(&self, val: u8) {
        // SAFETY: All bytes in `Self` are part of an atomic integer type.
        // This allows us to cast `Self` to a slice of `AtomicU8`s.
        let bytes = unsafe {
            core::slice::from_raw_parts(self as *const _ as *const AtomicU8, size_of::<Self>())
        };
        for byte in bytes {
            byte.store(val, Ordering::Relaxed);
        }
    }
}

extern "C" {
    pub fn switch_to_vmpl_unsafe(hv_doorbell: *const HVDoorbell, vmpl: u32) -> bool;
}

pub fn switch_to_vmpl(vmpl: u32) {
    // The switch to a lower VMPL must be done with an assembly sequence in
    // order to ensure that any #HV that occurs during the sequence will
    // correctly block the VMPL switch so that events can be processed.
    let hv_doorbell = this_cpu().hv_doorbell();
    let ptr = match hv_doorbell {
        Some(doorbell) => ptr::from_ref(doorbell),
        None => ptr::null(),
    };
    // SAFETY: FFI call. Parameters and return values are checked.
    unsafe {
        if !switch_to_vmpl_unsafe(ptr, vmpl) {
            panic!("Failed to switch to VMPL {}", vmpl);
        }
    }
}

global_asm!(
    r#"
        .globl switch_to_vmpl_unsafe
    switch_to_vmpl_unsafe:

        /* Upon entry,
         * rdi = pointer to the HV doorbell page
         * esi = target VMPL
         */
        /* Check if NoFurtherSignal is set (bit 15 of the first word of the
         * #HV doorbell page).  If so, abort the transition. */
        test %rdi, %rdi
        jz switch_vmpl_proceed
        testw $0x8000, (%rdi)

        /* From this point until the vmgexit, if a #HV arrives, the #HV handler
         * must prevent the VMPL transition. */
        .globl switch_vmpl_window_start
    switch_vmpl_window_start:
        jnz switch_vmpl_cancel

    switch_vmpl_proceed:
        /* Use the MSR-based VMPL switch request to avoid any need to use the
         * GHCB page.  Run VMPL request is 0x16 and response is 0x17. */
        movl $0x16, %eax
        movl %esi, %edx
        movl ${SEV_GHCB}, %ecx
        wrmsr
        rep; vmmcall

        .globl switch_vmpl_window_end
    switch_vmpl_window_end:
        /* Verify that the request was honored.  ECX still contains the MSR
         * number. */
        rdmsr
        andl $0xFFF, %eax
        cmpl $0x17, %eax
        jz switch_vmpl_cancel
        xorl %eax, %eax
        ret

        /* An aborted VMPL switch is treated as a successful switch. */
        .globl switch_vmpl_cancel
    switch_vmpl_cancel:
        movl $1, %eax
        ret
        "#,
    SEV_GHCB = const SEV_GHCB,
    options(att_syntax)
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghcb_layout() {
        assert_eq!(offset_of!(GHCB, cpl), 0x0cb);
        assert_eq!(offset_of!(GHCB, xss), 0x140);
        assert_eq!(offset_of!(GHCB, dr7), 0x160);
        assert_eq!(offset_of!(GHCB, rax), 0x1f8);
        assert_eq!(offset_of!(GHCB, rcx), 0x308);
        assert_eq!(offset_of!(GHCB, rdx), 0x310);
        assert_eq!(offset_of!(GHCB, rbx), 0x318);
        assert_eq!(offset_of!(GHCB, sw_exit_code), 0x390);
        assert_eq!(offset_of!(GHCB, sw_exit_info_1), 0x398);
        assert_eq!(offset_of!(GHCB, sw_exit_info_2), 0x3a0);
        assert_eq!(offset_of!(GHCB, sw_scratch), 0x3a8);
        assert_eq!(offset_of!(GHCB, xcr0), 0x3e8);
        assert_eq!(offset_of!(GHCB, valid_bitmap), 0x3f0);
        assert_eq!(offset_of!(GHCB, x87_state_gpa), 0x400);
        assert_eq!(offset_of!(GHCB, buffer), 0x800);
        assert_eq!(offset_of!(GHCB, version), 0xffa);
        assert_eq!(offset_of!(GHCB, usage), 0xffc);
        assert_eq!(mem::size_of::<GHCB>(), 0x1000);
    }
}

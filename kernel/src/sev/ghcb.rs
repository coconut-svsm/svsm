// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::msr::{write_msr, SEV_GHCB};
use crate::cpu::percpu::this_cpu;
use crate::cpu::{flush_tlb_global_sync, X86GeneralRegs};
use crate::error::SvsmError;
use crate::mm::pagetable::get_init_pgtable_locked;
use crate::mm::validate::{
    valid_bitmap_clear_valid_4k, valid_bitmap_set_valid_4k, valid_bitmap_valid_addr,
};
use crate::mm::virt_to_phys;
use crate::platform::PageStateChangeOp;
use crate::sev::hv_doorbell::HVDoorbell;
use crate::sev::sev_snp_enabled;
use crate::sev::utils::raw_vmgexit;
use crate::types::{Bytes, PageSize, PAGE_SIZE_2M};
use crate::utils::MemoryRegion;

use core::arch::global_asm;
use core::cell::Cell;
use core::mem::{self, offset_of};
use core::ptr;

use super::msr_protocol::{invalidate_page_msr, register_ghcb_gpa_msr, validate_page_msr};
use super::{pvalidate, PvalidateOp};

#[repr(C, packed)]
#[derive(Debug, Default, Clone, Copy)]
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
                .then(|| self.$field.get())
                .ok_or(GhcbError::VmgexitInvalid)
        }
    };
}

macro_rules! ghcb_setter {
    ($name:ident, $field:ident, $t:ty) => {
        #[allow(unused)]
        fn $name(&self, val: $t) {
            self.$field.set(val);
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
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
enum GHCBExitCode {
    RDTSC = 0x6e,
    IOIO = 0x7b,
    MSR = 0x7c,
    RDTSCP = 0x87,
    SNP_PSC = 0x8000_0010,
    GUEST_REQUEST = 0x8000_0011,
    GUEST_EXT_REQUEST = 0x8000_0012,
    AP_CREATE = 0x80000013,
    HV_DOORBELL = 0x8000_0014,
    HV_IPI = 0x8000_0015,
    CONFIGURE_INT_INJ = 0x8000_0019,
    SPECIFIC_EOI = 0x8000_001B,
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

#[repr(C)]
#[derive(Debug, Clone)]
pub struct GHCB {
    reserved_1: Cell<[u8; 0xcb]>,
    cpl: Cell<u8>,
    reserved_2: Cell<[u8; 0x74]>,
    xss: Cell<u64>,
    reserved_3: Cell<[u8; 0x18]>,
    dr7: Cell<u64>,
    reserved_4: Cell<[u8; 0x90]>,
    rax: Cell<u64>,
    reserved_5: Cell<[u8; 0x100]>,
    reserved_6: Cell<u64>,
    rcx: Cell<u64>,
    rdx: Cell<u64>,
    rbx: Cell<u64>,
    reserved_7: Cell<[u8; 0x70]>,
    sw_exit_code: Cell<u64>,
    sw_exit_info_1: Cell<u64>,
    sw_exit_info_2: Cell<u64>,
    sw_scratch: Cell<u64>,
    reserved_8: Cell<[u8; 0x38]>,
    xcr0: Cell<u64>,
    valid_bitmap: Cell<[u64; 2]>,
    x87_state_gpa: Cell<u64>,
    reserved_9: Cell<[u8; 0x3f8]>,
    buffer: Cell<[u8; GHCB_BUFFER_SIZE]>,
    reserved_10: Cell<[u8; 0xa]>,
    version: Cell<u16>,
    usage: Cell<u32>,
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

    pub fn init(vaddr: VirtAddr) -> Result<(), SvsmError> {
        let paddr = virt_to_phys(vaddr);

        if sev_snp_enabled() {
            // Make page invalid
            pvalidate(vaddr, PageSize::Regular, PvalidateOp::Invalid)?;

            // Let the Hypervisor take the page back
            invalidate_page_msr(paddr)?;

            // Needs guarding for Stage2 GHCB
            if valid_bitmap_valid_addr(paddr) {
                valid_bitmap_clear_valid_4k(paddr);
            }
        }

        // Map page unencrypted
        get_init_pgtable_locked().set_shared_4k(vaddr)?;

        flush_tlb_global_sync();

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

    pub fn rdmsr_regs(&self, regs: &mut X86GeneralRegs) -> Result<(), SvsmError> {
        self.clear();

        self.set_rcx_valid(regs.rcx as u64);

        self.vmgexit(GHCBExitCode::MSR, 0, 0)?;
        let rdx = self.get_rdx_valid()?;
        let rax = self.get_rax_valid()?;
        regs.rdx = rdx as usize;
        regs.rax = rax as usize;
        Ok(())
    }

    pub fn register(&self) -> Result<(), SvsmError> {
        let vaddr = VirtAddr::from(self as *const GHCB);
        let paddr = virt_to_phys(vaddr);

        // Register GHCB GPA
        Ok(register_ghcb_gpa_msr(paddr)?)
    }

    pub fn shutdown(&self) -> Result<(), SvsmError> {
        let vaddr = VirtAddr::from(ptr::from_ref(self));
        let paddr = virt_to_phys(vaddr);

        // Re-encrypt page
        get_init_pgtable_locked().set_encrypted_4k(vaddr)?;

        // Unregister GHCB PA
        register_ghcb_gpa_msr(PhysAddr::null())?;

        // Make page guest-invalid
        validate_page_msr(paddr)?;

        // Make page guest-valid
        pvalidate(vaddr, PageSize::Regular, PvalidateOp::Valid)?;

        // Needs guarding for Stage2 GHCB
        if valid_bitmap_valid_addr(paddr) {
            valid_bitmap_set_valid_4k(paddr);
        }

        Ok(())
    }

    pub fn clear(&self) {
        // Clear valid bitmap
        self.valid_bitmap.set([0, 0]);

        // Mark valid_bitmap valid
        let off = offset_of!(Self, valid_bitmap);
        self.set_valid(off);
        self.set_valid(off + mem::size_of::<u64>());
    }

    fn set_valid(&self, offset: usize) {
        let bit: usize = (offset >> 3) & 0x3f;
        let index: usize = (offset >> 9) & 0x1;
        let mask: u64 = 1 << bit;

        let mut bitmap = self.valid_bitmap.get();
        bitmap[index] |= mask;
        self.valid_bitmap.set(bitmap);
    }

    fn is_valid(&self, offset: usize) -> bool {
        let bit: usize = (offset >> 3) & 0x3f;
        let index: usize = (offset >> 9) & 0x1;
        let mask: u64 = 1 << bit;

        (self.valid_bitmap.get()[index] & mask) == mask
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
        write_msr(SEV_GHCB, ghcb_pa);
        raw_vmgexit();

        let sw_exit_info_1 = self.get_exit_info_1_valid()?;
        if sw_exit_info_1 != 0 {
            return Err(GhcbError::VmgexitError(
                sw_exit_info_1,
                self.sw_exit_info_2.get(),
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
        T: Copy,
    {
        offset
            .checked_add(mem::size_of::<T>())
            .filter(|end| *end <= GHCB_BUFFER_SIZE)
            .ok_or(GhcbError::InvalidOffset)?;

        // SAFETY: we have verified that the offset is within bounds and does
        // not overflow
        let dst = unsafe { self.buffer.as_ptr().cast::<u8>().add(offset) };
        if dst.align_offset(mem::align_of::<T>()) != 0 {
            return Err(GhcbError::InvalidOffset);
        }

        // SAFETY: we have verified the pointer is aligned and within bounds.
        unsafe { dst.cast::<T>().copy_from_nonoverlapping(data, 1) }
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

                let buffer_va = VirtAddr::from(self.buffer.as_ptr());
                let buffer_pa = u64::from(virt_to_phys(buffer_va));
                self.set_sw_scratch_valid(buffer_pa);

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
            return Err(GhcbError::VmgexitError(self.sw_exit_info_1.get(), sw_exit_info_2).into());
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
            return Err(GhcbError::VmgexitError(self.rbx.get(), sw_exit_info_2).into());
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

    #[inline]
    #[cfg(test)]
    pub fn fill(&self, byte: u8) {
        let mut other = mem::MaybeUninit::<Self>::uninit();
        let other = unsafe {
            other.as_mut_ptr().write_bytes(byte, 1);
            other.assume_init()
        };
        self.copy_from(&other);
    }

    #[inline]
    #[cfg(test)]
    fn copy_from(&self, other: &Self) {
        self.reserved_1.set(other.reserved_1.get());
        self.cpl.set(other.cpl.get());
        self.reserved_2.set(other.reserved_2.get());
        self.xss.set(other.xss.get());
        self.reserved_3.set(other.reserved_3.get());
        self.dr7.set(other.dr7.get());
        self.reserved_4.set(other.reserved_4.get());
        self.rax.set(other.rax.get());
        self.reserved_5.set(other.reserved_5.get());
        self.reserved_6.set(other.reserved_6.get());
        self.rcx.set(other.rcx.get());
        self.rdx.set(other.rdx.get());
        self.rbx.set(other.rbx.get());
        self.reserved_7.set(other.reserved_7.get());
        self.sw_exit_code.set(other.sw_exit_code.get());
        self.sw_exit_info_1.set(other.sw_exit_info_1.get());
        self.sw_exit_info_2.set(other.sw_exit_info_2.get());
        self.sw_scratch.set(other.sw_scratch.get());
        self.reserved_8.set(other.reserved_8.get());
        self.xcr0.set(other.xcr0.get());
        self.valid_bitmap.set(other.valid_bitmap.get());
        self.x87_state_gpa.set(other.x87_state_gpa.get());
        self.reserved_9.set(other.reserved_9.get());
        self.buffer.set(other.buffer.get());
        self.reserved_10.set(other.reserved_10.get());
        self.version.set(other.version.get());
        self.usage.set(other.usage.get());
    }
}

extern "C" {
    pub fn switch_to_vmpl_unsafe(hv_doorbell: *const HVDoorbell, vmpl: u32) -> bool;
}

pub fn switch_to_vmpl(vmpl: u32) {
    // The switch to a lower VMPL must be done with an assembly sequence in
    // order to ensure that any #HV that occurs during the sequence will
    // correctly block the VMPL switch so that events can be processed.
    let hv_doorbell = this_cpu().hv_doorbell_unsafe();
    unsafe {
        // Process any pending #HV events before leaving the SVSM.  No event
        // can cancel the request to enter the guest VMPL, so proceed with
        // guest entry once events have been handled.
        if !hv_doorbell.is_null() {
            (*hv_doorbell).process_pending_events();
        }
        if !switch_to_vmpl_unsafe(hv_doorbell, vmpl) {
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
        movl $0xC0010130, %ecx
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
        /* Process any pending events if NoFurtherSignal has been set. */
        test %rdi, %rdi
        jz no_pending_events
        testw $0x8000, (%rdi)
        jz no_pending_events
        call process_hv_events
    no_pending_events:
        movl $1, %eax
        ret
        "#,
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

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::flush_tlb_global_sync;
use crate::cpu::percpu::{this_cpu, this_cpu_shared, PERCPU_AREAS, PERCPU_VMSAS};
use crate::cpu::vmsa::{vmsa_mut_ref_from_vaddr, vmsa_ref_from_vaddr};
use crate::error::SvsmError;
use crate::locking::RWLock;
use crate::mm::virtualrange::{VIRT_ALIGN_2M, VIRT_ALIGN_4K};
use crate::mm::PerCPUPageMappingGuard;
use crate::mm::{valid_phys_address, writable_phys_addr, GuestPtr};
use crate::protocols::apic::{APIC_PROTOCOL_VERSION_MAX, APIC_PROTOCOL_VERSION_MIN};
use crate::protocols::attest::{ATTEST_PROTOCOL_VERSION_MAX, ATTEST_PROTOCOL_VERSION_MIN};
use crate::protocols::errors::SvsmReqError;
use crate::protocols::{
    RequestParams, SVSM_APIC_PROTOCOL, SVSM_ATTEST_PROTOCOL, SVSM_CORE_PROTOCOL,
};
use crate::requests::SvsmCaa;
use crate::sev::utils::{
    pvalidate, rmp_clear_guest_vmsa, rmp_grant_guest_access, rmp_revoke_guest_access,
    rmp_set_guest_vmsa, PvalidateOp, RMPFlags, SevSnpError,
};
use crate::sev::vmsa::VMSAControl;
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::zero_mem_region;
use cpuarch::vmsa::VMSA;

const SVSM_REQ_CORE_REMAP_CA: u32 = 0;
const SVSM_REQ_CORE_PVALIDATE: u32 = 1;
const SVSM_REQ_CORE_CREATE_VCPU: u32 = 2;
const SVSM_REQ_CORE_DELETE_VCPU: u32 = 3;
const SVSM_REQ_CORE_DEPOSIT_MEM: u32 = 4;
const SVSM_REQ_CORE_WITHDRAW_MEM: u32 = 5;
const SVSM_REQ_CORE_QUERY_PROTOCOL: u32 = 6;
const SVSM_REQ_CORE_CONFIGURE_VTOM: u32 = 7;

pub const CORE_PROTOCOL_VERSION_MIN: u32 = 1;
pub const CORE_PROTOCOL_VERSION_MAX: u32 = 1;

// This lock prevents races around PVALIDATE and CREATE_VCPU
//
// Without the lock there is a possible attack where the error path of
// core_create_vcpu() could give the guest OS access to a SVSM page.
//
// The PValidate path will take the lock for read, the create_vcpu path takes
// the lock for write.
static PVALIDATE_LOCK: RWLock<()> = RWLock::new(());

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct PValidateRequest {
    entries: u16,
    next: u16,
    resv: u32,
}

/// # Safety
/// The caller must only call this function on a page that was committed for
/// use as a guest VMSA.
unsafe fn core_create_vcpu_error_restore(paddr: Option<PhysAddr>, vaddr: Option<VirtAddr>) {
    if let Some(v) = vaddr {
        // SAFETY: the caller guarantees the safety of this address.
        if let Err(err) = unsafe { rmp_clear_guest_vmsa(v) } {
            log::error!("Failed to restore page permissions: {:#?}", err);
        }
    }
    // In case mappings have been changed
    flush_tlb_global_sync();

    if let Some(p) = paddr {
        // SAFETY: This can only fail if another CPU unregisters our
        // unused VMSA. This is not possible, since unregistration of
        // an unused VMSA only happens in the error path of core_create_vcpu(),
        // with a physical address that only this CPU managed to register.
        PERCPU_VMSAS.unregister(p, false).unwrap();
    }
}

// VMSA validity checks according to SVSM spec
fn check_vmsa(new: &VMSA, sev_features: u64, svme_mask: u64) -> bool {
    new.vmpl == RMPFlags::GUEST_VMPL.bits() as u8
        && new.efer & svme_mask == svme_mask
        && new.sev_features == sev_features
}

/// per-cpu request mapping area size (1GB)
fn core_create_vcpu(params: &RequestParams) -> Result<(), SvsmReqError> {
    let paddr = PhysAddr::from(params.rcx);
    let pcaa = PhysAddr::from(params.rdx);
    let apic_id: u32 = (params.r8 & 0xffff_ffff) as u32;

    // Check VMSA address
    if !valid_phys_address(paddr) || !paddr.is_page_aligned() {
        return Err(SvsmReqError::invalid_address());
    }

    // Check CAA address
    if !valid_phys_address(pcaa) || !pcaa.is_page_aligned() {
        return Err(SvsmReqError::invalid_address());
    }

    // Check whether VMSA page and CAA region overlap
    //
    // Since both areas are 4kb aligned and 4kb in size, and correct alignment
    // was already checked, it is enough here to check whether VMSA and CAA
    // page have the same starting address.
    if paddr == pcaa {
        return Err(SvsmReqError::invalid_address());
    }

    let target_cpu = PERCPU_AREAS
        .get_by_apic_id(apic_id)
        .ok_or_else(SvsmReqError::invalid_parameter)?;

    // Got valid gPAs and APIC ID, register VMSA immediately to avoid races
    PERCPU_VMSAS.register(paddr, target_cpu.cpu_index(), true)?;

    // Time to map the VMSA. No need to clean up the registered VMSA on the
    // error path since this is a fatal error anyway.
    let mapping_guard = PerCPUPageMappingGuard::create_4k(paddr)?;
    let vaddr = mapping_guard.virt_addr();

    // Prevent any parallel PVALIDATE requests from being processed
    let lock = PVALIDATE_LOCK.lock_write();

    // Make sure the guest can't make modifications to the VMSA page
    rmp_revoke_guest_access(vaddr, PageSize::Regular).inspect_err(|_| {
        // SAFETY: this address has already been validated as a guest-owned
        // address.
        unsafe {
            core_create_vcpu_error_restore(Some(paddr), None);
        }
    })?;

    // TLB flush needed to propagate new permissions
    flush_tlb_global_sync();

    let new_vmsa = vmsa_ref_from_vaddr(vaddr);
    let svme_mask: u64 = 1u64 << 12;

    // VMSA validity checks according to SVSM spec
    if !check_vmsa(new_vmsa, params.sev_features, svme_mask) {
        // SAFETY: this address has already been validated as a guest-owned
        // address.
        unsafe {
            core_create_vcpu_error_restore(Some(paddr), Some(vaddr));
        }
        return Err(SvsmReqError::invalid_parameter());
    }

    // Set the VMSA bit
    // SAFETY: this page was already validated to be a guest-owned page.
    unsafe {
        rmp_set_guest_vmsa(vaddr).inspect_err(|_| {
            core_create_vcpu_error_restore(Some(paddr), Some(vaddr));
        })?;
    }

    drop(lock);

    assert!(PERCPU_VMSAS.set_used(paddr) == Some(target_cpu.cpu_index()));
    target_cpu.update_guest_vmsa_caa(paddr, pcaa);

    Ok(())
}

fn core_delete_vcpu(params: &RequestParams) -> Result<(), SvsmReqError> {
    let paddr = PhysAddr::from(params.rcx);

    PERCPU_VMSAS
        .unregister(paddr, true)
        .map_err(|_| SvsmReqError::invalid_parameter())?;

    // Map the VMSA
    let mapping_guard = PerCPUPageMappingGuard::create_4k(paddr)?;
    let vaddr = mapping_guard.virt_addr();

    // Clear EFER.SVME on deleted VMSA. If the VMSA is executing
    // disable() will loop until that is not the case
    let del_vmsa = vmsa_mut_ref_from_vaddr(vaddr);
    del_vmsa.disable();

    // Do not return early here, as we need to do a TLB flush
    // SAFETY: this page is known to already be in use as a guest VMSA.
    let res = unsafe { rmp_clear_guest_vmsa(vaddr).map_err(|_| SvsmReqError::invalid_address()) };

    // Unmap the page
    drop(mapping_guard);

    // Tell everyone the news and flush temporary mapping
    flush_tlb_global_sync();

    res
}

fn core_deposit_mem(_params: &RequestParams) -> Result<(), SvsmReqError> {
    log::info!("Request SVSM_REQ_CORE_DEPOSIT_MEM not yet supported");
    Err(SvsmReqError::unsupported_call())
}

fn core_withdraw_mem(_params: &RequestParams) -> Result<(), SvsmReqError> {
    log::info!("Request SVSM_REQ_CORE_WITHDRAW_MEM not yet supported");
    Err(SvsmReqError::unsupported_call())
}

fn protocol_supported(version: u32, version_min: u32, version_max: u32) -> u64 {
    if version >= version_min && version <= version_max {
        let ret_low: u64 = version_min.into();
        let ret_high: u64 = version_max.into();

        ret_low | (ret_high << 32)
    } else {
        0
    }
}

fn core_query_protocol(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let rcx: u64 = params.rcx;
    let protocol: u32 = (rcx >> 32).try_into().unwrap();
    let version: u32 = (rcx & 0xffff_ffffu64).try_into().unwrap();

    let ret_val = match protocol {
        SVSM_CORE_PROTOCOL => protocol_supported(
            version,
            CORE_PROTOCOL_VERSION_MIN,
            CORE_PROTOCOL_VERSION_MAX,
        ),
        SVSM_APIC_PROTOCOL => {
            // The APIC protocol is only supported if the calling CPU supports
            // alternate injection.
            if this_cpu().use_apic_emulation() {
                protocol_supported(
                    version,
                    APIC_PROTOCOL_VERSION_MIN,
                    APIC_PROTOCOL_VERSION_MAX,
                )
            } else {
                0
            }
        }
        SVSM_ATTEST_PROTOCOL => protocol_supported(
            version,
            ATTEST_PROTOCOL_VERSION_MIN,
            ATTEST_PROTOCOL_VERSION_MAX,
        ),
        _ => 0,
    };

    params.rcx = ret_val;

    Ok(())
}

fn core_configure_vtom(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let query: bool = (params.rcx & 1) == 1;

    // Report that vTOM configuration is unsupported
    if query {
        params.rcx = 0;
        Ok(())
    } else {
        Err(SvsmReqError::invalid_request())
    }
}

fn core_pvalidate_one(entry: u64, flush: &mut bool) -> Result<(), SvsmReqError> {
    let (page_size_bytes, valign, huge) = match entry & 3 {
        0 => (PAGE_SIZE, VIRT_ALIGN_4K, PageSize::Regular),
        1 => (PAGE_SIZE_2M, VIRT_ALIGN_2M, PageSize::Huge),
        _ => return Err(SvsmReqError::invalid_parameter()),
    };

    let valid = match (entry & 4) == 4 {
        true => PvalidateOp::Valid,
        false => PvalidateOp::Invalid,
    };
    let ign_cf = (entry & 8) == 8;

    let paddr = PhysAddr::from(entry).page_align();

    if !paddr.is_aligned(page_size_bytes) {
        return Err(SvsmReqError::invalid_parameter());
    }

    if !valid_phys_address(paddr) {
        log::debug!("Invalid phys address: {:#x}", paddr);
        return Err(SvsmReqError::invalid_address());
    }

    let guard = PerCPUPageMappingGuard::create(paddr, paddr + page_size_bytes, valign)?;
    let vaddr = guard.virt_addr();

    // Take lock to prevent races with CREATE_VCPU calls
    let lock = PVALIDATE_LOCK.lock_read();

    if valid == PvalidateOp::Invalid {
        *flush |= true;
        rmp_revoke_guest_access(vaddr, huge)?;
    }

    // SAFETY: the physical address was guaranteed to be a guest address and
    // cannot affect memory safety.
    unsafe {
        pvalidate(vaddr, huge, valid).or_else(|err| match err {
            SvsmError::SevSnp(SevSnpError::FAIL_UNCHANGED(_)) if ign_cf => Ok(()),
            _ => Err(err),
        })?;
    }

    drop(lock);

    if valid == PvalidateOp::Valid {
        // Zero out a page when it is validated and before giving other VMPLs
        // access to it. This is necessary to prevent a possible HV attack:
        //
        // Attack scenario:
        //   1) SVSM stores secrets in VMPL0 memory at GPA A
        //   2) HV invalidates GPA A and maps the SPA to GPA B, which is in the
        //      OS range of GPAs
        //   3) Guest OS asks SVSM to validate GPA B
        //   4) SVSM validates page and gives OS access
        //   5) OS can now read SVSM secrets from GPA B
        //
        // The SVSM will not notice the attack until it tries to access GPA A
        // again. Prevent it by clearing every page before giving access to
        // other VMPLs.
        //
        // Be careful to not clear GPAs which the HV might have mapped
        // read-only, as the write operation might cause infinite #NPF loops.
        //
        // Special thanks to Tom Lendacky for reporting the issue and tracking
        // down the #NPF loops.
        //
        if writable_phys_addr(paddr) {
            // FIXME: This check leaves a window open for the attack described
            // above. Remove the check once OVMF and Linux have been fixed and
            // no longer try to pvalidate MMIO memory.

            // SAFETY: paddr is validated at the beginning of the function, and
            // we trust PerCPUPageMappingGuard::create() to return a valid
            // vaddr pointing to a mapped region of at least page_size_bytes
            // size.
            unsafe {
                zero_mem_region(vaddr, vaddr + page_size_bytes);
            }
        } else {
            log::warn!("Not clearing possible read-only page at PA {:#x}", paddr);
        }
        // SAFETY: the address was validated earlier as a guest page and thus
        // memory safety is not affected.
        unsafe {
            rmp_grant_guest_access(vaddr, huge)?;
        }
    }

    Ok(())
}

fn core_pvalidate(params: &RequestParams) -> Result<(), SvsmReqError> {
    let gpa = PhysAddr::from(params.rcx);

    if !gpa.is_aligned(8) || !valid_phys_address(gpa) {
        return Err(SvsmReqError::invalid_parameter());
    }

    let paddr = gpa.page_align();
    let offset = gpa.page_offset();

    let guard = PerCPUPageMappingGuard::create_4k(paddr)?;
    let start = guard.virt_addr();

    let guest_page = GuestPtr::<PValidateRequest>::new(start + offset);
    // SAFETY: start is a new mapped page address, thus valid.
    // offset can't exceed a page size, so guest_page belongs to mapped memory.
    let mut request = unsafe { guest_page.read()? };

    let entries = request.entries;
    let next = request.next;

    // Each entry is 8 bytes in size, 8 bytes for the request header
    let max_entries: u16 = ((PAGE_SIZE - offset - 8) / 8).try_into().unwrap();

    if entries == 0 || entries > max_entries || entries <= next {
        return Err(SvsmReqError::invalid_parameter());
    }

    let mut loop_result = Ok(());
    let mut flush = false;

    let guest_entries = guest_page.offset(1).cast::<u64>();
    for i in next..entries {
        let index = i as isize;
        // SAFETY: guest_entries comes from guest_page which is a new mapped
        // page. index is between [next, entries) and both values have been
        // validated.
        let entry = match unsafe { guest_entries.offset(index).read() } {
            Ok(v) => v,
            Err(e) => {
                loop_result = Err(e.into());
                break;
            }
        };

        loop_result = core_pvalidate_one(entry, &mut flush);
        match loop_result {
            Ok(()) => request.next += 1,
            Err(SvsmReqError::RequestError(..)) => break,
            Err(SvsmReqError::FatalError(..)) => return loop_result,
        }
    }

    // SAFETY: guest_page is obtained from a guest-provided physical address
    // (untrusted), so it needs to be valid (ie. belongs to the guest and only
    // the guest). The physical address is validated by valid_phys_address()
    // called at the beginning of SVSM_CORE_PVALIDATE handler (this one).
    if let Err(e) = unsafe { guest_page.write_ref(&request) } {
        loop_result = Err(e.into());
    }

    if flush {
        flush_tlb_global_sync();
    }

    loop_result
}

fn core_remap_ca(params: &RequestParams) -> Result<(), SvsmReqError> {
    let gpa = PhysAddr::from(params.rcx);

    if !gpa.is_aligned(8) || !valid_phys_address(gpa) || gpa.crosses_page(8) {
        return Err(SvsmReqError::invalid_parameter());
    }

    let offset = gpa.page_offset();
    let paddr = gpa.page_align();

    // Temporarily map new CAA to clear it
    let mapping_guard = PerCPUPageMappingGuard::create_4k(paddr)?;
    let vaddr = mapping_guard.virt_addr() + offset;

    let pending = GuestPtr::<SvsmCaa>::new(vaddr);
    // SAFETY: pending points to a new allocated page
    unsafe { pending.write(SvsmCaa::zeroed())? };

    // Clear any pending interrupt state before remapping the calling area to
    // ensure that any pending lazy EOI has been processed.
    this_cpu().clear_pending_interrupts();

    this_cpu_shared().update_guest_caa(gpa);

    Ok(())
}

pub fn core_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        SVSM_REQ_CORE_REMAP_CA => core_remap_ca(params),
        SVSM_REQ_CORE_PVALIDATE => core_pvalidate(params),
        SVSM_REQ_CORE_CREATE_VCPU => core_create_vcpu(params),
        SVSM_REQ_CORE_DELETE_VCPU => core_delete_vcpu(params),
        SVSM_REQ_CORE_DEPOSIT_MEM => core_deposit_mem(params),
        SVSM_REQ_CORE_WITHDRAW_MEM => core_withdraw_mem(params),
        SVSM_REQ_CORE_QUERY_PROTOCOL => core_query_protocol(params),
        SVSM_REQ_CORE_CONFIGURE_VTOM => core_configure_vtom(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}

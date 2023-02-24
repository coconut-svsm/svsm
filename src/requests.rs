// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::{VirtAddr, PhysAddr, PAGE_SIZE, PAGE_SIZE_2M};
use crate::cpu::percpu::{this_cpu_mut, this_cpu, percpu, unregister_guest_vmsa};
use crate::cpu::{flush_tlb_global_sync};
use crate::sev::vmsa::{VMSA, GuestVMExit};
use crate::sev::utils::{pvalidate, rmp_revoke_guest_access, rmp_grant_guest_access,
    rmp_set_guest_vmsa, rmp_clear_guest_vmsa, RMPFlags, SevSnpError};
use crate::mm::PerCPUPageMappingGuard;
use crate::utils::{page_align, page_offset, is_aligned, crosses_page, halt};
use crate::mm::{valid_phys_address, GuestPtr};

#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types, dead_code)]
enum SvsmResultCode {
    SUCCESS,
    INCOMPLETE,
    UNSUPPORTED_PROTOCOL,
    UNSUPPORTED_CALL,
    INVALID_ADDRESS,
    INVALID_FORMAT,
    INVALID_PARAMETER,
    INVALID_REQUEST,
    BUSY,
    PROTOCOL_BASE(u64),
}

impl From<SvsmResultCode> for u64 {
    fn from(res: SvsmResultCode) -> u64 {
        match res {
            SvsmResultCode::SUCCESS => 0x0000_0000,
            SvsmResultCode::INCOMPLETE => 0x8000_0000,
            SvsmResultCode::UNSUPPORTED_PROTOCOL => 0x8000_0001,
            SvsmResultCode::UNSUPPORTED_CALL => 0x8000_0002,
            SvsmResultCode::INVALID_ADDRESS => 0x8000_0003,
            SvsmResultCode::INVALID_FORMAT => 0x8000_0004,
            SvsmResultCode::INVALID_PARAMETER => 0x8000_0005,
            SvsmResultCode::INVALID_REQUEST => 0x8000_0006,
            SvsmResultCode::BUSY => 0x8000_0007,
            SvsmResultCode::PROTOCOL_BASE(code) => 0x8000_1000 + code,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SvsmError {
    RequestError(SvsmResultCode),
    FatalError(())
}

macro_rules! impl_req_err {
    ($name:ident, $v:ident) => {
        fn $name() -> Self {
            Self::RequestError(SvsmResultCode::$v)
        }
    }
}

#[allow(dead_code)]
impl SvsmError {
    impl_req_err!(incomplete, INCOMPLETE);
    impl_req_err!(unsupported_protocol, UNSUPPORTED_PROTOCOL);
    impl_req_err!(unsupported_call, UNSUPPORTED_CALL);
    impl_req_err!(invalid_address, INVALID_ADDRESS);
    impl_req_err!(invalid_format, INVALID_FORMAT);
    impl_req_err!(invalid_parameter, INVALID_PARAMETER);
    impl_req_err!(invalid_request, INVALID_REQUEST);
    impl_req_err!(busy, BUSY);
    fn protocol(code: u64) -> Self {
        Self::RequestError(SvsmResultCode::PROTOCOL_BASE(code))
    }
}

// SEV-SNP errors obtained from PVALIDATE or RMPADJUST are returned
// to the guest as protocol-specific errors.
impl From<SevSnpError> for SvsmError {
    fn from(err: SevSnpError) -> SvsmError {
        SvsmError::protocol(err.ret())
    }
}

const SVSM_REQ_CORE_REMAP_CA : u32 = 0;
const SVSM_REQ_CORE_PVALIDATE : u32 = 1;
const SVSM_REQ_CORE_CREATE_VCPU : u32 = 2;
const SVSM_REQ_CORE_DELETE_VCPU : u32 = 3;
const SVSM_REQ_CORE_DEPOSIT_MEM : u32 = 4;
const SVSM_REQ_CORE_WITHDRAW_MEM : u32 = 5;
const SVSM_REQ_CORE_QUERY_PROTOCOL : u32 = 6;
const SVSM_REQ_CORE_CONFIGURE_VTOM : u32 = 7;

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct PValidateRequest {
    entries : u16,
    next : u16,
    resv : u32,
}

fn core_create_vcpu_error_restore(vaddr: VirtAddr) -> Result<(), SvsmError> {
    if let Err(err) = rmp_clear_guest_vmsa(vaddr) {
        log::error!("Failed to restore page permissions ({}, code: {})", err, err.ret());
    }
    // In case mappings have been changed
    flush_tlb_global_sync();

    Ok(())
}

// VMSA validity checks according to SVSM spec
fn check_vmsa(new: &VMSA, old: &VMSA, svme_mask: u64) -> bool {
    new.vmpl == RMPFlags::VMPL1.bits() as u8 &&
        new.efer & svme_mask == svme_mask &&
        new.sev_features == old.sev_features
}

/// per-cpu request mapping area size (1GB)
fn core_create_vcpu(vmsa: &VMSA) -> Result<(), SvsmError> {
    let paddr = vmsa.rcx as PhysAddr;
    let pcaa = vmsa.rdx as PhysAddr;
    let apic_id: u32 = (vmsa.r8 & 0xffff_ffff) as u32;

    // Check VMSA address
    if !valid_phys_address(paddr) || !is_aligned(paddr, PAGE_SIZE) {
        return Err(SvsmError::invalid_address());
    }

    // Check CAA address
    if !valid_phys_address(pcaa) || !is_aligned(pcaa, 8) {
        return Err(SvsmError::invalid_address());
    }

    let target_cpu = percpu(apic_id)
        .ok_or_else(SvsmError::invalid_parameter)?;

    // Time to map the VMSA
    let mapping_guard = PerCPUPageMappingGuard::create(paddr, 1, false)
        .map_err(SvsmError::FatalError)?;
    let vaddr = mapping_guard.virt_addr();

    // Make sure the guest can't make modifications to the VMSA page
    rmp_set_guest_vmsa(vaddr)?;

    // TLB flush needed to propagate new permissions
    flush_tlb_global_sync();

    let new_vmsa = VMSA::from_virt_addr(vaddr);
    let svme_mask: u64 = 1u64 << 12;

    // VMSA validity checks according to SVSM spec
    if !check_vmsa(new_vmsa, vmsa, svme_mask) {
        core_create_vcpu_error_restore(vaddr)?;
        return Err(SvsmError::invalid_parameter());
    }

    // Unmap any previously used VMSA on the target VCPU and map the new one
    if target_cpu.try_unmap_guest_vmsa()
        .and_then(|_| target_cpu.map_guest_vmsa(paddr, true))
        .is_err()
    {
        core_create_vcpu_error_restore(vaddr)?;
        return Err(SvsmError::busy());
    }

    if target_cpu.map_caa_phys(pcaa).is_err() {
        if target_cpu.unmap_guest_vmsa().is_err() {
            log::error!("Failed to unmap guest VMSA");
        }
        core_create_vcpu_error_restore(vaddr)?;
        return Err(SvsmError::busy());
    }

    Ok(())
}

fn core_delete_vcpu(vmsa: &VMSA)-> Result<(), SvsmError> {
    let paddr = vmsa.rcx as PhysAddr;

    let vmsa_entry = unregister_guest_vmsa(paddr)
        .map_err(|e| match e {
            e if e > 0 => SvsmError::protocol(e),
            _ => SvsmError::invalid_parameter(),
        })?;

    // Map the VMSA
    let mapping_guard = PerCPUPageMappingGuard::create(vmsa_entry.paddr, 0, false)
        .map_err(SvsmError::FatalError)?;

    // Remove VMSA permissions from page
    rmp_clear_guest_vmsa(mapping_guard.virt_addr())?;

    // Unmap the page
    drop(mapping_guard);

    // Tell everyone the news and flush temporary mapping
    flush_tlb_global_sync();

    Ok(())
}

fn core_deposit_mem(_vmsa: &VMSA)-> Result<(), SvsmError> {
    log::info!("Request SVSM_REQ_CORE_DEPOSIT_MEM not yet supported");
    Err(SvsmError::unsupported_call())
}

fn core_withdraw_mem(_vmsa: &VMSA)-> Result<(), SvsmError> {
    log::info!("Request SVSM_REQ_CORE_WITHDRAW_MEM not yet supported");
    Err(SvsmError::unsupported_call())
}

fn core_query_protocol(_vmsa: &VMSA)-> Result<(), SvsmError> {
    log::info!("Request SVSM_REQ_CORE_QUERY_PROTOCOL not yet supported");
    Err(SvsmError::unsupported_call())
}

fn core_configure_vtom(_vmsa: &VMSA)-> Result<(), SvsmError> {
    log::info!("Request SVSM_REQ_CORE_CONFIGURE_VTOM not yet supported");
    Err(SvsmError::unsupported_call())
}

fn core_pvalidate_one(entry: u64, flush: &mut bool) -> Result<(), SvsmError> {
    let page_size: u64 = entry & 3;

    if page_size > 1 {
        return Err(SvsmError::invalid_parameter());
    }

    let huge = page_size == 1;
    let valid = (entry & 4) == 4;
    let ign_cf = (entry & 8) == 8;

    let alignment = { if huge { PAGE_SIZE_2M } else { PAGE_SIZE } };
    let paddr: PhysAddr = (entry as usize) & !(PAGE_SIZE - 1);

    if !is_aligned(paddr, alignment) {
        return Err(SvsmError::invalid_parameter());
    }

    if !valid_phys_address(paddr) {
        log::debug!("Invalid phys address: {:#x}", paddr);
        return Err(SvsmError::invalid_address());
    }

    let guard = PerCPUPageMappingGuard::create(paddr, 1, huge)
        .map_err(SvsmError::FatalError)?;
    let vaddr = guard.virt_addr();

    if !valid {
        *flush |= true;
        rmp_revoke_guest_access(vaddr, huge)?;
    }

    pvalidate(vaddr, huge, valid)
        .or_else(|err| match err {
            SevSnpError::FAIL_UNCHANGED(_) if ign_cf => Ok(()),
            _ => Err(err),
        })?;

    if valid {
        rmp_grant_guest_access(vaddr, huge)?;
    }

    Ok(())
}

fn core_pvalidate(vmsa: &VMSA) -> Result<(), SvsmError> {
    let gpa : PhysAddr = vmsa.rcx.try_into().unwrap();

    if !is_aligned(gpa, 8) || !valid_phys_address(gpa) {
        return Err(SvsmError::invalid_parameter());
    }

    let paddr = page_align(gpa);
    let offset = page_offset(gpa);

    let guard = PerCPUPageMappingGuard::create(paddr, 0, false)
        .map_err(SvsmError::FatalError)?;
    let start = guard.virt_addr();

    let guest_page = GuestPtr::<PValidateRequest>::new(start + offset);
    let mut request = guest_page.read()
        .map_err(|_| SvsmError::invalid_address())?;

    let entries = request.entries;
    let next = request.next;

    // Each entry is 8 bytes in size, 8 bytes for the request header
    let max_entries : u16 = ((PAGE_SIZE - offset - 8) / 8).try_into().unwrap();

    if entries == 0 || entries > max_entries || entries <= next {
        return Err(SvsmError::invalid_parameter());
    }

    let mut loop_result = Ok(());
    let mut flush = false;

    let guest_entries = guest_page.offset(1).cast::<u64>();
    for i in next..entries {
        let index = i as usize;
        let entry = match guest_entries.offset(index).read() {
            Ok(v) => v,
            Err(_) => {
                loop_result = Err(SvsmError::invalid_address());
                break;
            },
        };

        loop_result = core_pvalidate_one(entry, &mut flush);
        match loop_result {
            Ok(()) => request.next += 1,
            Err(SvsmError::RequestError(..)) => break,
            Err(SvsmError::FatalError(..)) => return loop_result,
        }
    }

    if guest_page.write_ref(&request).is_err() {
        loop_result = Err(SvsmError::invalid_address());
    }

    if flush {
        flush_tlb_global_sync();
    }

    loop_result
}

fn core_remap_ca(vmsa: &VMSA) -> Result<(), SvsmError> {
    let gpa : PhysAddr = vmsa.rcx.try_into().unwrap();

    if !is_aligned(gpa, 8) || !valid_phys_address(gpa) || crosses_page(gpa, 8) {
        return Err(SvsmError::invalid_parameter());
    }

    // Unmap old CAA
    this_cpu_mut()
        .unmap_caa()
        .map_err(SvsmError::FatalError)?;

    // Map new CAA
    let vaddr = this_cpu_mut()
        .map_caa_phys(gpa)
        .map_err(SvsmError::FatalError)?;

    let pending = GuestPtr::<u64>::new(vaddr);
    pending.write(0)
        .map_err(|_| SvsmError::invalid_address())?;

    Ok(())
}

fn core_protocol_request(request: u32, vmsa: &VMSA) -> Result<(), SvsmError> {
    match request {
        SVSM_REQ_CORE_REMAP_CA => core_remap_ca(vmsa),
        SVSM_REQ_CORE_PVALIDATE => core_pvalidate(vmsa),
        SVSM_REQ_CORE_CREATE_VCPU => core_create_vcpu(vmsa),
        SVSM_REQ_CORE_DELETE_VCPU => core_delete_vcpu(vmsa),
        SVSM_REQ_CORE_DEPOSIT_MEM => core_deposit_mem(vmsa),
        SVSM_REQ_CORE_WITHDRAW_MEM => core_withdraw_mem(vmsa),
        SVSM_REQ_CORE_QUERY_PROTOCOL => core_query_protocol(vmsa),
        SVSM_REQ_CORE_CONFIGURE_VTOM => core_configure_vtom(vmsa),
        _ => Err(SvsmError::unsupported_call()),
    }
}

fn request_loop_once(vmsa: &VMSA, protocol: u32, request: u32) -> Result<bool, SvsmError> {
    if !matches!(vmsa.guest_exit_code, GuestVMExit::VMGEXIT) {
        return Ok(false);
    }

    let caa_addr = this_cpu().get_caa_addr()
        .ok_or_else(|| {
            log::error!("No CAA mapped - bailing out");
            SvsmError::FatalError(())
        })?;

    let guest_pending = GuestPtr::<u64>::new(caa_addr);
    let pending = guest_pending.read()
        .map_err(|_| SvsmError::invalid_address())?;
    guest_pending.write(0)
        .map_err(|_| SvsmError::invalid_address())?;

    if pending != 1 {
        return Ok(false);
    }

    match protocol {
        0 => core_protocol_request(request, vmsa).map(|_| true),
        _ => Err(SvsmError::unsupported_protocol()),
    }
}

pub fn request_loop() {
    loop {
        let locked = this_cpu_mut().get_guest_vmsa();
        let vmsa_ref = match locked.clone() {
            Some(vmsa) => vmsa,
            None => {
                // When there is no VMSA - go into halt and retry when someone wakes us up
                log::debug!("No VMSA! Halting");
                drop(locked);
                halt();
                continue;
            }
        };
        let vmsa = vmsa_ref.vmsa();

        // Clear EFER.SVME in guest VMSA
        vmsa.disable();

        let rax = vmsa.rax;
        let protocol = (rax >> 32) as u32;
        let request = (rax & 0xffff_ffff) as u32;

        vmsa.rax = match request_loop_once(&vmsa, protocol, request) {
            Ok(success) => match success {
                true => SvsmResultCode::SUCCESS.into(),
                false => vmsa.rax,
            },
            Err(SvsmError::RequestError(code)) => {
                log::debug!("Soft error handling protocol {} request {}: {:?}", protocol, request, code);
                code.into()
            },
            Err(SvsmError::FatalError(..)) => {
                log::error!("Fatal error handling core protocol request {}", request);
                break;
            }
        };

        // Make VMSA runable again by setting EFER.SVME
        vmsa.enable();

        flush_tlb_global_sync();
        this_cpu_mut().ghcb().run_vmpl(1).expect("Failed to run VMPL 1");
    }
}

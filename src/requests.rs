// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::{VirtAddr, PhysAddr, PAGE_SIZE, PAGE_SIZE_2M};
use crate::cpu::percpu::{this_cpu_mut, this_cpu, percpu};
use crate::cpu::{flush_tlb_global_sync};
use crate::sev::vmsa::VMSA;
use crate::sev::utils::{pvalidate, rmp_adjust, RMPFlags};
use crate::mm::PerCPUPageMappingGuard;
use crate::utils::{page_align, page_offset, is_aligned, crosses_page, halt};
use crate::mm::{valid_phys_address, GuestPtr};

const SVSM_REQ_CORE_REMAP_CA : u32 = 0;
const SVSM_REQ_CORE_PVALIDATE : u32 = 1;
const SVSM_REQ_CORE_CREATE_VCPU : u32 = 2;
const SVSM_REQ_CORE_DELETE_VCPU : u32 = 3;
const SVSM_REQ_CORE_DEPOSIT_MEM : u32 = 4;
const SVSM_REQ_CORE_WITHDRAW_MEM : u32 = 5;
const SVSM_REQ_CORE_QUERY_PROTOCOL : u32 = 6;
const SVSM_REQ_CORE_CONFIGURE_VTOM : u32 = 7;

const SVSM_SUCCESS : u64 = 0x0000_0000;
const _SVSM_ERR_INCOMPLETE : u64 = 0x8000_0000;
const SVSM_ERR_UNSUPPORTED_PROTOCOL : u64 = 0x8000_0001;
const SVSM_ERR_UNSUPPORTED_CALL : u64 = 0x8000_0002;
const SVSM_ERR_INVALID_ADDRESS : u64= 0x8000_0003;
const _SVSM_ERR_INVALID_FORMAT : u64 = 0x8000_0004;
const SVSM_ERR_INVALID_PARAMETER : u64 = 0x8000_0005;
const _SVSM_ERR_INVALID_REQUEST : u64 = 0x8000_0006;
const SVSM_ERR_BUSY: u64 = 0x8000_0007;

const SVSM_ERR_PROTOCOL_BASE : u64 = 0x8000_1000;

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct PValidateRequest {
    entries : u16,
    next : u16,
    resv : u32,
}

fn make_vmsa(vaddr: VirtAddr) -> Result<(), u64> {
    rmpadjust_update_vmsa(vaddr, RMPFlags::VMPL1 | RMPFlags::VMSA, false)?;

    Ok(())
}

fn core_create_vcpu_error_restore(vaddr: VirtAddr) -> Result<(), ()> {
    if let Err(error_code) = grant_access(vaddr, false) {
        log::error!("Failed to restore page permissions (code: {})", error_code);
    }
    // In case mappings have been changed
    flush_tlb_global_sync();

    return Ok(())
}

/// per-cpu request mapping area size (1GB)
fn core_create_vcpu(vmsa: &mut VMSA) -> Result<(),()> {
    let paddr = vmsa.rcx as PhysAddr;
    let pcaa = vmsa.rdx as PhysAddr;
    let apic_id: u32 = (vmsa.r8 & 0xffff_ffff) as u32;

    vmsa.rax = SVSM_ERR_INVALID_ADDRESS;

    // Check VMSA address
    if !valid_phys_address(paddr) || !is_aligned(paddr, PAGE_SIZE) {
        return Ok(());
    }

    // Check CAA address
    if !valid_phys_address(pcaa) || !is_aligned(pcaa, 8) {
        return Ok(());
    }

    vmsa.rax = SVSM_ERR_INVALID_PARAMETER;
    let has_cpu = percpu(apic_id);
    if let None = has_cpu {
        return Ok(());
    }

    let target_cpu = has_cpu.unwrap();

    // This returns Option<LockGuard<Option<VmsaRef>>>
    // - Outer Option tells whether lock was taken or not
    // - LockGuard is the owner of the lock if it was taken
    // - Inner Option tells whether there is a guest vmsa configured
    let check_guest_vmsa = target_cpu.try_update_guest_vmsa();

    vmsa.rax = SVSM_ERR_BUSY;

    // Check if lock was aquired
    if let Err(_) = check_guest_vmsa {
        return Ok(());
    }

    let old_vmsa_ref = check_guest_vmsa.unwrap();

    // Is there already a guest VMSA on that VCPU?
    if let Some(vmsa_ref) = old_vmsa_ref {
        // Revoke RMP permissions for old VMSA page
        let mapping_guard = PerCPUPageMappingGuard::create(vmsa_ref.paddr, 0, false)?;
        let vaddr = mapping_guard.virt_addr();
        if let Err(error_code) = revoke_access(vaddr, false) {
            vmsa.rax = error_code;
            return Ok(());
        }

        // Restore normal guest permissions
        if vmsa_ref.guest_owned {
            if let Err(error_code) = grant_access(vaddr, false) {
                vmsa.rax = error_code;
                return Ok(());
            }
        }
    }

    // Time to map the VMSA
    let mapping_guard = PerCPUPageMappingGuard::create(paddr, 1, false)?;
    let vaddr = mapping_guard.virt_addr();

    // Make sure the guest can't make modifications anymore to the VMSA page
    if let Err(error_code) = revoke_access(vaddr, false) {
        vmsa.rax = error_code;
        return Ok(());
    }

    // TLB flush needed to propagate new permissions
    flush_tlb_global_sync();

    let new_vmsa = VMSA::from_virt_addr(vaddr);
    let svme_mask: u64 = 1u64 << 12;

    vmsa.rax = SVSM_ERR_INVALID_PARAMETER;

    // VMSA validity checks according to SVSM spec
    if (new_vmsa.vmpl != RMPFlags::VMPL1 as u8) ||
       ((new_vmsa.efer & svme_mask) != svme_mask) ||
       (new_vmsa.sev_features != vmsa.sev_features) {
        return core_create_vcpu_error_restore(vaddr);
    }

    if let Err(_) = make_vmsa(vaddr) {
        return core_create_vcpu_error_restore(vaddr);
    }

    if let Err(_) = target_cpu.map_guest_vmsa(paddr, true) {
        return core_create_vcpu_error_restore(vaddr);
    }

    if let Err(_) = target_cpu.map_caa_phys(pcaa) {
        if let Err(_) = target_cpu.unmap_guest_vmsa() {
            log::error!("Failed to unmap guest VMSA");
        }
        return core_create_vcpu_error_restore(vaddr);
    }

    vmsa.rax = SVSM_SUCCESS;

    Ok(())
}

fn core_delete_vcpu(vmsa: &mut VMSA)-> Result<(),()> {
    log::info!("Request SVSM_REQ_CORE_DELETE_VCPU not yet supported");
    vmsa.rax = SVSM_ERR_UNSUPPORTED_CALL;
    Ok(())
}

fn core_deposit_mem(vmsa: &mut VMSA)-> Result<(),()> {
    log::info!("Request SVSM_REQ_CORE_DEPOSIT_MEM not yet supported");
    vmsa.rax = SVSM_ERR_UNSUPPORTED_CALL;
    Ok(())
}

fn core_withdraw_mem(vmsa: &mut VMSA)-> Result<(),()> {
    log::info!("Request SVSM_REQ_CORE_WITHDRAW_MEM not yet supported");
    vmsa.rax = SVSM_ERR_UNSUPPORTED_CALL;
    Ok(())
}

fn core_query_protocol(vmsa: &mut VMSA)-> Result<(),()> {
    log::info!("Request SVSM_REQ_CORE_QUERY_PROTOCOL not yet supported");
    vmsa.rax = SVSM_ERR_UNSUPPORTED_CALL;
    Ok(())
}

fn core_configure_vtom(vmsa: &mut VMSA)-> Result<(),()> {
    log::info!("Request SVSM_REQ_CORE_CONFIGURE_VTOM not yet supported");
    vmsa.rax = SVSM_ERR_UNSUPPORTED_CALL;
    Ok(())
}

fn rmpadjust_update_vmsa(vaddr: VirtAddr, flags: u64, huge: bool) -> Result<(),u64> {
    if let Err(code) = rmp_adjust(vaddr, flags, huge) {
        let ret_code = if code < 0x10 { code } else { 0x11 };
        Err(SVSM_ERR_PROTOCOL_BASE + ret_code)
    } else {
        Ok(())
    }
}

fn revoke_access(vaddr: VirtAddr, huge: bool) -> Result<(),u64>
{
    rmpadjust_update_vmsa(vaddr, RMPFlags::VMPL1 | RMPFlags::NONE, huge)?;
    rmpadjust_update_vmsa(vaddr, RMPFlags::VMPL2 | RMPFlags::NONE, huge)?;
    rmpadjust_update_vmsa(vaddr, RMPFlags::VMPL3 | RMPFlags::NONE, huge)?;

    Ok(())
}

fn grant_access(vaddr: VirtAddr, huge: bool) -> Result<(),u64>
{
    rmpadjust_update_vmsa(vaddr, RMPFlags::VMPL1 | RMPFlags::RWX, huge)?;

    Ok(())
}

fn core_pvalidate_one(entry: u64) -> Result<(u64, bool),()> {
    let result: u64;
    let mut flush: bool = false;
    let page_size: u64 = entry & 3;

    if page_size > 1 {
        return Ok((SVSM_ERR_INVALID_PARAMETER, flush));
    }

    let huge: bool = page_size == 1;
    let valid: bool = (entry & 4) == 4;
    let ign_cf: bool = (entry & 8) == 8;

    let alignment = { if huge { PAGE_SIZE_2M } else { PAGE_SIZE } };
    let paddr: PhysAddr = (entry as usize) & !(PAGE_SIZE - 1);

    if !is_aligned(paddr, alignment) {
        return Ok((SVSM_ERR_INVALID_PARAMETER, flush));
    }

    if !valid_phys_address(paddr) {
        log::info!("Invalid phys address: {:#x}", paddr);
        return Ok((SVSM_ERR_INVALID_ADDRESS, flush));
    }

    let guard = PerCPUPageMappingGuard::create(paddr, 1, huge)?;
    let vaddr = guard.virt_addr();

    if !valid {
        if let Err(error_code) = revoke_access(vaddr, huge) {
            return Ok((error_code, true))
        }
        flush = true;
    }

    result = match pvalidate(vaddr, huge, valid) {
        Ok(_) => SVSM_SUCCESS,
        Err(e) => {
                    if e.error_code != 0 {
                        SVSM_ERR_PROTOCOL_BASE + e.error_code
                    } else if ign_cf == false && e.changed == false { 
                        SVSM_ERR_PROTOCOL_BASE + 0x10
                    } else  {
                        SVSM_SUCCESS
                    }
                },
    };

    if result != SVSM_SUCCESS {
        return Ok((result, flush));
    }

    if valid {
        if let Err(error_code) = grant_access(vaddr, huge) {
            return Ok((error_code, flush))
        }
    }

    Ok((SVSM_SUCCESS, flush))
}

fn core_pvalidate(vmsa: &mut VMSA) -> Result<(),()> {
    let gpa : PhysAddr = vmsa.rcx.try_into().unwrap();

    vmsa.rax = SVSM_ERR_INVALID_PARAMETER;

    if !is_aligned(gpa, 8) || !valid_phys_address(gpa) {
        return Err(())
    }

    let paddr = page_align(gpa);
    let offset = page_offset(gpa);

    let guard = PerCPUPageMappingGuard::create(paddr, 0, false)?;
    let start = guard.virt_addr();

    let guest_page = GuestPtr::<PValidateRequest>::new(start + offset);
    let mut request = match guest_page.read() {
        Ok(d) => d,
        Err(_) => { vmsa.rax = SVSM_ERR_INVALID_ADDRESS; return Ok(()); },
    };

    let entries = request.entries;
    let next = request.next;

    // Each entry is 8 bytes in size, 8 bytes for the request header
    let max_entries : u16 = ((PAGE_SIZE - offset - 8) / 8).try_into().unwrap();

    if entries == 0 || entries > max_entries || entries <= next {
        return Ok(())
    }

    vmsa.rax = SVSM_SUCCESS;

    let mut flush : bool = false;

    let guest_entries = guest_page.offset(1).cast::<u64>();
    for i in next..entries {
        let index = i as usize;
        let entry = match guest_entries.offset(index).read() {
            Ok(v) => v,
            Err(_) => { vmsa.rax = SVSM_ERR_INVALID_ADDRESS; break; },
        };

        let (result, flush_entry) = core_pvalidate_one(entry)?;
        flush |= flush_entry;
        if result == SVSM_SUCCESS {
            request.next += 1;
        } else {
            vmsa.rax = result;
            break;
        }
    }

    if let Err(_) = guest_page.write_ref(&request) {
        vmsa.rax = SVSM_ERR_INVALID_ADDRESS;
    }

    if flush {
        flush_tlb_global_sync();
    }

    Ok(())
}

fn core_remap_ca(vmsa: &mut VMSA) -> Result<(), ()> {
    let gpa : PhysAddr = vmsa.rcx.try_into().unwrap();

    vmsa.rax = SVSM_ERR_INVALID_PARAMETER;

    if !is_aligned(gpa, 8) || !valid_phys_address(gpa) || crosses_page(gpa, 8) {
        // Report error to guest
        return Ok(());
    }

    // Unmap old CAA
    this_cpu_mut().unmap_caa()?;

    // Map new CAA
    this_cpu_mut().map_caa_phys(gpa)?;

    let vaddr = this_cpu().get_caa_addr().unwrap();

    let pending = GuestPtr::<u64>::new(vaddr);
    if let Err(_) = pending.write(0) {
        vmsa.rax = SVSM_ERR_INVALID_ADDRESS;
    } else {
        vmsa.rax = SVSM_SUCCESS;
    }

    Ok(())
}

fn core_protocol_request(request: u32, vmsa: &mut VMSA) -> Result<(),()> {
    let result = match request {
        SVSM_REQ_CORE_REMAP_CA => core_remap_ca(vmsa),
        SVSM_REQ_CORE_PVALIDATE => core_pvalidate(vmsa),
        SVSM_REQ_CORE_CREATE_VCPU => core_create_vcpu(vmsa),
        SVSM_REQ_CORE_DELETE_VCPU => core_delete_vcpu(vmsa),
        SVSM_REQ_CORE_DEPOSIT_MEM => core_deposit_mem(vmsa),
        SVSM_REQ_CORE_WITHDRAW_MEM => core_withdraw_mem(vmsa),
        SVSM_REQ_CORE_QUERY_PROTOCOL => core_query_protocol(vmsa),
        SVSM_REQ_CORE_CONFIGURE_VTOM => core_configure_vtom(vmsa),
        _ => {
            log::info!("Core protocol request {} not supported", request);
            vmsa.rax = SVSM_ERR_UNSUPPORTED_CALL;
            Ok(())
        },
    };

    if let Err(_) = result {
        log::error!("Error handling core protocol request {}", request);
    }

    result
}

pub fn request_loop() {

    loop {
        let locked = this_cpu_mut().get_guest_vmsa();
        let opt_vmsa_ref = locked.clone();
        if let None = opt_vmsa_ref {
            // When there is no VMSA - go into halt and retry when someone wakes us up
            drop(locked);
            halt();
            continue;
        }

        let result = this_cpu().get_caa_addr();
        let vmsa_ref = opt_vmsa_ref.unwrap();
        let vmsa = vmsa_ref.vmsa();

        // Clear EFER.SVME in guest VMSA
        vmsa.disable();

        let rax = vmsa.rax;
        let protocol : u32 = (rax >> 32) as u32;
        let request : u32 = (rax & 0xffff_ffff) as u32;

        if let None = result {
            log::error!("No CAA mapped - bailing out");
            break;
        }

        let caa_addr = result.unwrap();

        let guest_pending = GuestPtr::<u64>::new(caa_addr);
        let pending = match guest_pending.read() {
            Ok(v) => v,
            Err(_) => { vmsa.rax = SVSM_ERR_INVALID_ADDRESS; 0 },
        };

        if let Err(_) = guest_pending.write(0) {
            vmsa.rax = SVSM_ERR_INVALID_ADDRESS;
        } else if pending == 1 {
            if protocol == 0 {
                if let Err(_) = core_protocol_request(request, vmsa) {
                    log::error!("Fatal Error handling core protocol request");
                    break;
                }
            } else {
                log::info!("Only protocol 0 supported, got {}", protocol);
                vmsa.rax = SVSM_ERR_UNSUPPORTED_PROTOCOL;
            }
        }

        // Make VMSA runable again by setting EFER.SVME
        vmsa.enable();

        flush_tlb_global_sync();
        this_cpu_mut().ghcb().run_vmpl(1).expect("Failed to run VMPL 1");
    }
}

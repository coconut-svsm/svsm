// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::{VirtAddr, PhysAddr, PAGE_SIZE, PAGE_SIZE_2M};
use crate::cpu::percpu::{this_cpu_mut, this_cpu};
use crate::sev::vmsa::VMSA;
use crate::sev::utils::{pvalidate, rmp_adjust_report, RMPFlags};
use crate::mm::pagetable::{PageTable, PTMappingGuard, invlpg, get_init_pgtable_locked, flush_tlb_global};
use crate::utils::{page_align, page_offset, is_aligned, crosses_page};
use crate::mm::valid_phys_address;

const  SVSM_REQ_CORE_REMAP_CA : u32 = 0;
const  SVSM_REQ_CORE_PVALIDATE : u32 = 1;
const _SVSM_REQ_CORE_CREATE_VCPU : u32 = 2;
const _SVSM_REQ_CORE_DELETE_VCPU : u32 = 3;
const _SVSM_REQ_CORE_DEPOSIT_MEM : u32 = 4;
const _SVSM_REQ_CORE_WITHDRAW_MEM : u32 = 5;
const _SVSM_REQ_CORE_QUERY_PROTOCOL : u32 = 6;
const _SVSM_REQ_CORE_CONFIGURE_VTOM : u32 = 7;

const SVSM_SUCCESS : u64 = 0x0000_0000;
const _SVSM_ERR_INCOMPLETE : u64 = 0x8000_0000;
const _SVSM_ERR_UNSUPPORTED_PROTOCOL : u64 = 0x8000_0001;
const _SVSM_ERR_UNSUPPORTED_CALL : u64 = 0x8000_0002;
const _SVSM_ERR_INVALID_ADDRESS : u64= 0x8000_0003;
const _SVSM_ERR_INVALID_FORMAT : u64 = 0x8000_0004;
const SVSM_ERR_INVALID_PARAMETER : u64 = 0x8000_0005;
const _SVSM_ERR_INVALID_REQUEST : u64 = 0x8000_0006;

const SVSM_ERR_PROTOCOL_BASE : u64 = 0x8000_1000;

#[repr(C, packed)]
struct PValidateRequest {
    entries : u16,
    next : u16,
    resv : u32,
    list : [u64; 511],
}

/// Base address for per-cpu request mappings
const REQUEST_BASE_ADDR : VirtAddr = 0xffff_ff00_0000_0000;
/// per-cpu request mapping area size (1GB)
const REQUEST_REGION_SIZE : usize = 0x40000000;

fn region_base_addr() -> VirtAddr {
    let apic_id : usize = this_cpu().get_apic_id().try_into().unwrap();

    REQUEST_BASE_ADDR + (apic_id * REQUEST_REGION_SIZE)
}

fn reset_access(vaddr: VirtAddr, huge: bool) -> Result<(),()>
{
    rmp_adjust_report(vaddr, RMPFlags::VMPL1_NONE, huge)?;
    rmp_adjust_report(vaddr, RMPFlags::VMPL2_NONE, huge)?;
    rmp_adjust_report(vaddr, RMPFlags::VMPL3_NONE, huge)?;

    Ok(())
}

fn core_pvalidate_one(vmsa: &mut VMSA, entry: u64) -> Result<bool,()> {
    let mut flush : bool = false;

    let huge: bool = (entry & 3) == 1;
    let valid: bool = (entry & 4) == 4;
    let ign_cf: bool = (entry & 8) == 8;

    let alignment = { if huge { PAGE_SIZE_2M } else { PAGE_SIZE } };
    let vaddr : VirtAddr = region_base_addr() + alignment;
    let paddr: PhysAddr = (entry as usize) & !(PAGE_SIZE - 1);

    if !is_aligned(paddr, alignment) || !valid_phys_address(paddr) {
        vmsa.rax = SVSM_ERR_INVALID_PARAMETER;
        return Err(())
    }

    let flags = PageTable::data_flags();

    if huge {
        get_init_pgtable_locked().map_2m(vaddr, paddr, &flags)?;
    } else {
        get_init_pgtable_locked().map_4k(vaddr, paddr, &flags)?;
    }

    if !valid {
        flush = true;
        reset_access(vaddr, huge)?;
    }

    let result = pvalidate(vaddr, huge, valid);

    let ret_code : u64 = match result {
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

    vmsa.rax = ret_code;

    if ret_code != SVSM_SUCCESS {
        log::error!("Failed to process entry: {:#x} return code: {:#x}", entry, ret_code);
        return Err(());
    }

    if valid {
        rmp_adjust_report(vaddr, RMPFlags::VMPL1_RWX, huge)?;
    }

    if huge {
        get_init_pgtable_locked().unmap_2m(vaddr)?;
    } else {
        get_init_pgtable_locked().unmap_4k(vaddr)?;
    }

    invlpg(vaddr);

    Ok(flush)
}

fn core_pvalidate(vmsa: &mut VMSA) -> Result<(),()> {
    let gpa : PhysAddr = vmsa.rcx.try_into().unwrap();
    let region = region_base_addr();

    vmsa.rax = SVSM_ERR_INVALID_PARAMETER;

    if !is_aligned(gpa, 8) || !valid_phys_address(gpa) {
        return Err(())
    }

    let paddr = page_align(gpa);
    let offset = page_offset(gpa);

    let start = region;
    let end = start + PAGE_SIZE;

	let guard = PTMappingGuard::create(start, end, paddr);
    guard.check_mapping()?;

    unsafe {
        let req = (start + offset) as *mut PValidateRequest;

        let entries = (*req).entries;
        let next = (*req).next;

        // Each entry is 8 bytes in size, 8 bytes for the request header
        let max_entries : u16 = ((PAGE_SIZE - offset - 8) / 8).try_into().unwrap();

        if entries == 0 || entries > max_entries || entries <= next {
            return Ok(())
        }

        vmsa.rax = SVSM_SUCCESS;

        let mut flush : bool = false;

        for i in next..entries {
            let index = i as usize;
            let entry = (*req).list[index];

            let result = core_pvalidate_one(vmsa, entry);
            if let Err(_) = result {
                break;
            }
            (*req).next += 1;
            flush |= result.unwrap();
        }

        if flush {
            flush_tlb_global();
        }
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

    unsafe {
        let pending : *mut u64 = vaddr as *mut u64;
        // Clear the whole 8 bytes for of the CA
        (*pending) = 0;
    }

    vmsa.rax = SVSM_SUCCESS;

    Ok(())
}

fn core_protocol_request(request: u32, vmsa: &mut VMSA) -> Result<(),()> {
    let result = match request {
        SVSM_REQ_CORE_REMAP_CA => core_remap_ca(vmsa),
        SVSM_REQ_CORE_PVALIDATE => core_pvalidate(vmsa),
        _ => { log::error!("Core protocol request {} not supported", request); Err(()) },
    };

    if let Err(_) = result {
        log::error!("Error handling core protocol request {}", request);
    }

    result
}

pub fn request_loop() {

    loop {
        flush_tlb_global();

        let result = this_cpu().get_caa_addr();
        let vmsa = this_cpu_mut().vmsa(1);

        // Clear EFER.SVME in guest VMSA
        vmsa.disable();

        if let None = result {
            log::error!("No CAA mapped - bailing out");
            break;
        }

        let caa_addr = result.unwrap();

        let pending: u8 = unsafe {
            let pending_ptr = caa_addr as *mut u8;
            let ret: u8 = *pending_ptr;

            (*pending_ptr) = 0;
            ret
        };

        if pending == 1 {
            let rax = vmsa.rax;
            let protocol : u32 = (rax >> 32) as u32;
            let request : u32 = (rax & 0xffff_ffff) as u32;

            if protocol != 0 {
                log::error!("Only protocol 0 supported, got {}", protocol);
                break;
            }

            if let Err(_) = core_protocol_request(request, vmsa) {
                log::error!("Error handling core protocol request");
                break;
            }

            // Make VMSA runable again
            vmsa.enable();
        }

        this_cpu_mut().ghcb().run_vmpl(1).expect("Failed to run VMPL 1");
    }
}

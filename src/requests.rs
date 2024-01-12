// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::cpu::flush_tlb_global_sync;
use crate::cpu::percpu::{this_cpu, this_cpu_mut};
use crate::error::SvsmError;
use crate::mm::GuestPtr;
use crate::protocols::core::core_protocol_request;
use crate::protocols::errors::{SvsmReqError, SvsmResultCode};
use crate::protocols::RequestParams;
use crate::types::GUEST_VMPL;
use crate::utils::halt;
use cpuarch::vmsa::GuestVMExit;

/// Returns true if there is a valid VMSA mapping
pub fn update_mappings() -> Result<(), SvsmError> {
    let mut locked = this_cpu().guest_vmsa_ref();
    let mut ret = Ok(());

    if !locked.needs_update() {
        return Ok(());
    }

    this_cpu_mut().unmap_guest_vmsa();
    this_cpu_mut().unmap_caa();

    match locked.vmsa_phys() {
        Some(paddr) => this_cpu_mut().map_guest_vmsa(paddr)?,
        None => ret = Err(SvsmError::MissingVMSA),
    }

    if let Some(paddr) = locked.caa_phys() {
        this_cpu_mut().map_guest_caa(paddr)?
    }

    locked.set_updated();

    ret
}

fn request_loop_once(
    params: &mut RequestParams,
    protocol: u32,
    request: u32,
) -> Result<bool, SvsmReqError> {
    if !matches!(params.guest_exit_code, GuestVMExit::VMGEXIT) {
        return Ok(false);
    }

    let caa_addr = this_cpu().caa_addr().ok_or_else(|| {
        log::error!("No CAA mapped - bailing out");
        SvsmReqError::FatalError(SvsmError::MissingCAA)
    })?;

    let guest_pending = GuestPtr::<u64>::new(caa_addr);
    let pending = guest_pending.read()?;
    guest_pending.write(0)?;

    if pending != 1 {
        return Ok(false);
    }

    match protocol {
        0 => core_protocol_request(request, params).map(|_| true),
        _ => Err(SvsmReqError::unsupported_protocol()),
    }
}

pub fn request_loop() {
    loop {
        // Determine whether the guest is runnable.  If not, halt and wait for
        // the guest to execute.  When halting, assume that the hypervisor
        // will schedule the guest VMPL on its own.
        let mut vmsa_ref = if update_mappings().is_ok() {
            let mut vmsa_ref = this_cpu().guest_vmsa_ref();
            let vmsa = vmsa_ref.vmsa();

            // Make VMSA runnable again by setting EFER.SVME
            vmsa.enable();

            flush_tlb_global_sync();

            this_cpu_mut()
                .ghcb()
                .run_vmpl(GUEST_VMPL as u64)
                .expect("Failed to run guest VMPL");

            vmsa_ref
        } else {
            loop {
                log::debug!("No VMSA or CAA! Halting");
                halt();

                if update_mappings().is_ok() {
                    break;
                }
            }

            this_cpu().guest_vmsa_ref()
        };

        let vmsa = vmsa_ref.vmsa();

        // Clear EFER.SVME in guest VMSA
        vmsa.disable();

        let rax = vmsa.rax;
        let protocol = (rax >> 32) as u32;
        let request = (rax & 0xffff_ffff) as u32;
        let mut params = RequestParams::from_vmsa(vmsa);

        vmsa.rax = match request_loop_once(&mut params, protocol, request) {
            Ok(success) => match success {
                true => SvsmResultCode::SUCCESS.into(),
                false => vmsa.rax,
            },
            Err(SvsmReqError::RequestError(code)) => {
                log::debug!(
                    "Soft error handling protocol {} request {}: {:?}",
                    protocol,
                    request,
                    code
                );
                code.into()
            }
            Err(SvsmReqError::FatalError(err)) => {
                log::error!(
                    "Fatal error handling core protocol request {}: {:?}",
                    request,
                    err
                );
                break;
            }
        };

        // Write back results
        params.write_back(vmsa);
    }
}

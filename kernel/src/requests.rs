// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::cpu::flush_tlb_global_sync;
use crate::cpu::percpu::{process_requests, this_cpu, wait_for_requests};
use crate::error::SvsmError;
use crate::mm::GuestPtr;
use crate::protocols::core::core_protocol_request;
use crate::protocols::errors::{SvsmReqError, SvsmResultCode};
use crate::sev::ghcb::switch_to_vmpl;

#[cfg(all(feature = "mstpm", not(test)))]
use crate::protocols::{vtpm::vtpm_protocol_request, SVSM_VTPM_PROTOCOL};
use crate::protocols::{RequestParams, SVSM_CORE_PROTOCOL};
use crate::sev::vmsa::VMSAControl;
use crate::types::GUEST_VMPL;
use crate::utils::halt;
use cpuarch::vmsa::GuestVMExit;

/// The SVSM Calling Area (CAA)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SvsmCaa {
    call_pending: u8,
    mem_available: u8,
    _rsvd: [u8; 6],
}

impl SvsmCaa {
    /// Returns a copy of the this CAA with the `call_pending` field cleared.
    #[inline]
    const fn serviced(self) -> Self {
        Self {
            call_pending: 0,
            ..self
        }
    }

    /// A CAA with all of its fields set to zero.
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            call_pending: 0,
            mem_available: 0,
            _rsvd: [0; 6],
        }
    }
}

const _: () = assert!(core::mem::size_of::<SvsmCaa>() == 8);

/// Returns true if there is a valid VMSA mapping
pub fn update_mappings() -> Result<(), SvsmError> {
    let cpu = this_cpu();
    let mut locked = cpu.guest_vmsa_ref();
    let mut ret = Ok(());

    if !locked.needs_update() {
        return Ok(());
    }

    cpu.unmap_guest_vmsa();
    cpu.unmap_caa();

    match locked.vmsa_phys() {
        Some(paddr) => cpu.map_guest_vmsa(paddr)?,
        None => ret = Err(SvsmError::MissingVMSA),
    }

    if let Some(paddr) = locked.caa_phys() {
        cpu.map_guest_caa(paddr)?
    }

    locked.set_updated();

    ret
}

struct RequestInfo {
    protocol: u32,
    request: u32,
    params: RequestParams,
}

fn request_loop_once(
    params: &mut RequestParams,
    protocol: u32,
    request: u32,
) -> Result<bool, SvsmReqError> {
    if !matches!(params.guest_exit_code, GuestVMExit::VMGEXIT) {
        return Ok(false);
    }

    match protocol {
        SVSM_CORE_PROTOCOL => core_protocol_request(request, params).map(|_| true),
        #[cfg(all(feature = "mstpm", not(test)))]
        SVSM_VTPM_PROTOCOL => vtpm_protocol_request(request, params).map(|_| true),
        _ => Err(SvsmReqError::unsupported_protocol()),
    }
}

fn check_requests() -> Result<bool, SvsmReqError> {
    let cpu = this_cpu();
    let vmsa_ref = cpu.guest_vmsa_ref();
    if let Some(caa_addr) = vmsa_ref.caa_addr() {
        let calling_area = GuestPtr::<SvsmCaa>::new(caa_addr);
        let caa = calling_area.read()?;
        calling_area.write(caa.serviced())?;
        Ok(caa.call_pending != 0)
    } else {
        Ok(false)
    }
}

pub fn request_loop() {
    loop {
        // Determine whether the guest is runnable.  If not, halt and wait for
        // the guest to execute.  When halting, assume that the hypervisor
        // will schedule the guest VMPL on its own.
        if update_mappings().is_ok() {
            // Make VMSA runnable again by setting EFER.SVME.  This requires a
            // separate scope so the CPU reference does not outlive the use of
            // the VMSA reference.
            {
                let cpu = this_cpu();
                let mut vmsa_ref = cpu.guest_vmsa_ref();
                let vmsa = vmsa_ref.vmsa();
                vmsa.enable();
            }

            flush_tlb_global_sync();

            switch_to_vmpl(GUEST_VMPL as u32);
        } else {
            loop {
                log::debug!("No VMSA or CAA! Halting");
                halt();

                if update_mappings().is_ok() {
                    break;
                }
            }
        }

        // Obtain a reference to the VMSA just long enough to extract the
        // request parameters.
        let (protocol, request) = {
            let cpu = this_cpu();
            let mut vmsa_ref = cpu.guest_vmsa_ref();
            let vmsa = vmsa_ref.vmsa();

            // Clear EFER.SVME in guest VMSA
            vmsa.disable();

            let rax = vmsa.rax;

            ((rax >> 32) as u32, (rax & 0xffff_ffff) as u32)
        };

        match check_requests() {
            Ok(pending) => {
                if pending {
                    process_requests();
                }
            }
            Err(SvsmReqError::RequestError(code)) => {
                log::debug!(
                    "Soft error handling protocol {} request {}: {:?}",
                    protocol,
                    request,
                    code
                );
            }
            Err(SvsmReqError::FatalError(err)) => {
                log::error!(
                    "Fatal error handling core protocol request {}: {:?}",
                    request,
                    err
                );
                break;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn request_processing_main() {
    let apic_id = this_cpu().get_apic_id();

    log::info!("Launching request-processing task on CPU {}", apic_id);

    loop {
        wait_for_requests();

        // Obtain a reference to the VMSA just long enough to extract the
        // request parameters.
        let mut rax: u64;
        let mut request_info = {
            let cpu = this_cpu();
            let mut vmsa_ref = cpu.guest_vmsa_ref();
            let vmsa = vmsa_ref.vmsa();

            // Clear EFER.SVME in guest VMSA
            vmsa.disable();

            rax = vmsa.rax;
            RequestInfo {
                protocol: (rax >> 32) as u32,
                request: (rax & 0xffff_ffff) as u32,
                params: RequestParams::from_vmsa(vmsa),
            }
        };

        rax = match request_loop_once(
            &mut request_info.params,
            request_info.protocol,
            request_info.request,
        ) {
            Ok(success) => match success {
                true => SvsmResultCode::SUCCESS.into(),
                false => rax,
            },
            Err(SvsmReqError::RequestError(code)) => {
                log::debug!(
                    "Soft error handling protocol {} request {}: {:?}",
                    request_info.protocol,
                    request_info.request,
                    code
                );
                code.into()
            }
            Err(SvsmReqError::FatalError(err)) => {
                log::error!(
                    "Fatal error handling core protocol request {}: {:?}",
                    request_info.request,
                    err
                );
                break;
            }
        };

        // Write back results
        {
            let cpu = this_cpu();
            let mut vmsa_ref = cpu.guest_vmsa_ref();
            let vmsa = vmsa_ref.vmsa();
            vmsa.rax = rax;
            request_info.params.write_back(vmsa);
        }
    }

    panic!("Request processing task died unexpectedly");
}

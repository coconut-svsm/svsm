// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::cpu::ipi::wait_for_ipi_block;
use crate::cpu::percpu::{this_cpu, PERCPU_AREAS};
use crate::mm::GuestPtr;
use crate::protocols::apic::apic_protocol_request;
use crate::protocols::core::core_protocol_request;
use crate::protocols::errors::{SvsmReqError, SvsmResultCode};
use crate::task::{go_idle, set_affinity, start_kernel_task};
use crate::vmm::{enter_guest, GuestExitMessage};

use crate::protocols::attest::attest_protocol_request;
#[cfg(all(feature = "vtpm", not(test)))]
use crate::protocols::{vtpm::vtpm_protocol_request, SVSM_VTPM_PROTOCOL};
use crate::protocols::{
    RequestParams, SVSM_APIC_PROTOCOL, SVSM_ATTEST_PROTOCOL, SVSM_CORE_PROTOCOL,
};
use cpuarch::vmsa::GuestVMExit;

use alloc::format;

/// The SVSM Calling Area (CAA)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SvsmCaa {
    call_pending: u8,
    mem_available: u8,
    pub no_eoi_required: u8,
    _rsvd: [u8; 5],
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

    /// Returns a copy of the this CAA with the `no_eoi_required` flag updated
    #[inline]
    pub const fn update_no_eoi_required(self, no_eoi_required: u8) -> Self {
        Self {
            no_eoi_required,
            ..self
        }
    }

    /// A CAA with all of its fields set to zero.
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            call_pending: 0,
            mem_available: 0,
            no_eoi_required: 0,
            _rsvd: [0; 5],
        }
    }
}

const _: () = assert!(core::mem::size_of::<SvsmCaa>() == 8);

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
        SVSM_ATTEST_PROTOCOL => attest_protocol_request(request, params).map(|_| true),
        #[cfg(all(feature = "vtpm", not(test)))]
        SVSM_VTPM_PROTOCOL => vtpm_protocol_request(request, params).map(|_| true),
        SVSM_APIC_PROTOCOL => apic_protocol_request(request, params).map(|_| true),
        _ => Err(SvsmReqError::unsupported_protocol()),
    }
}

fn check_requests() -> Result<bool, SvsmReqError> {
    let cpu = this_cpu();
    let vmsa_ref = cpu.guest_vmsa_ref();
    if let Some(caa_addr) = vmsa_ref.caa_addr() {
        let calling_area = GuestPtr::<SvsmCaa>::new(caa_addr);
        // SAFETY: guest vmsa and ca are always validated before beeing updated
        // (core_remap_ca(), core_create_vcpu() or prepare_fw_launch()) so
        // they're safe to use.
        let caa = unsafe { calling_area.read()? };

        let caa_serviced = caa.serviced();

        // SAFETY: guest vmsa is always validated before beeing updated
        // (core_remap_ca() or core_create_vcpu()) so it's safe to use.
        unsafe {
            calling_area.write(caa_serviced)?;
        }

        Ok(caa.call_pending != 0)
    } else {
        Ok(false)
    }
}

pub extern "C" fn request_loop_main(cpu_index: usize) {
    log::info!("Launching request-processing task on CPU {}", cpu_index);

    if cpu_index != 0 {
        // Send this task to the correct CPU.
        set_affinity(cpu_index);
    } else {
        // When starting the request loop on the BSP, start an additional
        // request loop task for each other processor in the system.
        let cpu_count = PERCPU_AREAS.len();
        for task_index in 1..cpu_count {
            let loop_name = format!("request-loop on CPU {}", task_index);
            start_kernel_task(request_loop_main, task_index, loop_name)
                .expect("Failed to launch request loop task");
        }
    }

    debug_assert_eq!(cpu_index, this_cpu().get_cpu_index());

    // Suppress the use of IPIs before entering the guest, and ensure that all
    // other CPUs have done the same.
    wait_for_ipi_block();

    loop {
        // Attempt to enter the guest.
        match enter_guest() {
            GuestExitMessage::NoMappings => {
                log::debug!("No VMSA or CAA! Halting");
                go_idle();
            }
            GuestExitMessage::Svsm((protocol, request, mut params)) => match check_requests() {
                Ok(pending) => {
                    if pending {
                        process_request(protocol, request, &mut params);
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
            },
        }
    }
}

fn process_request(protocol: u32, request: u32, params: &mut RequestParams) {
    let rax: Option<u64> = match request_loop_once(params, protocol, request) {
        Ok(success) => match success {
            true => Some(SvsmResultCode::SUCCESS.into()),
            false => None,
        },
        Err(SvsmReqError::RequestError(code)) => {
            log::debug!(
                "Soft error handling protocol {} request {}: {:?}",
                protocol,
                request,
                code
            );
            Some(code.into())
        }
        Err(SvsmReqError::FatalError(err)) => {
            panic!(
                "Fatal error handling core protocol request {}: {:?}",
                request, err
            );
        }
    };

    // Write back results
    {
        let cpu = this_cpu();
        let mut vmsa_ref = cpu.guest_vmsa_ref();
        let vmsa = vmsa_ref.vmsa();
        if let Some(val) = rax {
            vmsa.rax = val;
        }
        params.write_back(vmsa);
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::cpu::ipi::wait_for_ipi_block;
use crate::cpu::percpu::{this_cpu, PERCPU_AREAS};
use crate::protocols::apic::apic_protocol_request;
use crate::protocols::core::core_protocol_request;
use crate::protocols::errors::{SvsmReqError, SvsmResultCode};
use crate::task::{go_idle, set_affinity, start_kernel_task};
use crate::vmm::{enter_guest, GuestExitMessage, GuestRegister};

use crate::protocols::attest::attest_protocol_request;
#[cfg(all(feature = "vtpm", not(test)))]
use crate::protocols::{vtpm::vtpm_protocol_request, SVSM_VTPM_PROTOCOL};
use crate::protocols::{
    RequestParams, SVSM_APIC_PROTOCOL, SVSM_ATTEST_PROTOCOL, SVSM_CORE_PROTOCOL,
};

use alloc::format;
use alloc::vec::Vec;

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
    /// Indicates whether the `call_pending` flag is set.
    #[inline]
    pub fn call_pending(&self) -> bool {
        self.call_pending != 0
    }

    /// Returns a copy of the this CAA with the `call_pending` field cleared.
    #[inline]
    pub const fn serviced(self) -> Self {
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
) -> Result<(), SvsmReqError> {
    match protocol {
        SVSM_CORE_PROTOCOL => core_protocol_request(request, params),
        SVSM_ATTEST_PROTOCOL => attest_protocol_request(request, params),
        #[cfg(all(feature = "vtpm", not(test)))]
        SVSM_VTPM_PROTOCOL => vtpm_protocol_request(request, params),
        SVSM_APIC_PROTOCOL => apic_protocol_request(request, params),
        _ => Err(SvsmReqError::unsupported_protocol()),
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

    let mut guest_regs = Vec::<GuestRegister>::new();

    loop {
        // Attempt to enter the guest.  Once registers have been set, reset the
        // vector so they are not set again.
        let msg = enter_guest(guest_regs.as_slice());
        guest_regs = Vec::new();

        match msg {
            GuestExitMessage::NoMappings => {
                log::debug!("No VMSA or CAA! Halting");
                go_idle();
            }
            GuestExitMessage::Svsm((protocol, request, mut params)) => {
                guest_regs = process_request(protocol, request, &mut params);
            }
        }
    }
}

fn process_request(protocol: u32, request: u32, params: &mut RequestParams) -> Vec<GuestRegister> {
    let rax: Option<u64> = match request_loop_once(params, protocol, request) {
        Ok(()) => Some(SvsmResultCode::SUCCESS.into()),
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

    // Generate vector of registers to update.
    let mut guest_regs = Vec::<GuestRegister>::new();
    if let Some(val) = rax {
        guest_regs.push(GuestRegister::X64Rax(val));
    }

    params.capture(&mut guest_regs);

    guest_regs
}

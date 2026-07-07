// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::cpu::percpu::{PERCPU_AREAS, this_cpu};
use crate::protocols::apic::apic_protocol_request;
use crate::protocols::core::core_protocol_request;
use crate::protocols::errors::{SvsmReqError, SvsmResultCode};
use crate::task::{KernelThreadStartInfo, go_idle, set_affinity, start_kernel_thread};
use crate::vmm::{GuestExitMessage, enter_guest};

use crate::protocols::attest::attest_protocol_request;
use crate::protocols::{
    RequestOutput, RequestParams, SVSM_APIC_PROTOCOL, SVSM_ATTEST_PROTOCOL, SVSM_CORE_PROTOCOL,
};
#[cfg(all(feature = "uefivars", not(test)))]
use crate::protocols::{SVSM_UEFI_MM_PROTOCOL, uefivars::uefi_mm_protocol_request};
#[cfg(all(feature = "vtpm", not(test)))]
use crate::protocols::{SVSM_VTPM_PROTOCOL, vtpm::vtpm_protocol_request};

use zerocopy::{FromBytes, IntoBytes};

/// The SVSM Calling Area (CAA)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes)]
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
        #[cfg(all(feature = "uefivars", not(test)))]
        SVSM_UEFI_MM_PROTOCOL => uefi_mm_protocol_request(request, params),
        _ => Err(SvsmReqError::unsupported_protocol()),
    }
}

pub fn request_loop_start(_: usize) {
    // This should always be started on the BSP.
    debug_assert_eq!(this_cpu().get_cpu_index(), 0);

    // Start an additional request loop task for each other processor in the
    // system.
    let cpu_count = PERCPU_AREAS.len();
    for task_index in 1..cpu_count {
        start_kernel_thread(KernelThreadStartInfo::new(request_loop_main, task_index))
            .expect("Failed to launch request loop thread");
    }

    // Enter the main processing loop for the BSP.
    request_loop_main(0);
}

fn request_loop_main(cpu_index: usize) {
    // Send this task to the correct CPU.
    set_affinity(cpu_index);

    log::info!("Launching request-processing task on CPU {cpu_index}");

    let mut output = RequestOutput::new();

    loop {
        // Attempt to enter the guest.  Once registers have been set, reset the
        // vector so they are not set again.
        let msg = enter_guest(output);
        output.clear();

        match msg {
            GuestExitMessage::NoMappings => {
                log::debug!("No VMSA or CAA! Halting");
                go_idle();
            }
            GuestExitMessage::Svsm((protocol, request, mut input)) => {
                let rax = process_request(protocol, request, &mut input);
                output.set_rax(rax);
                input.capture(&mut output);
            }
        }
    }
}

fn process_request(protocol: u32, request: u32, params: &mut RequestParams) -> u64 {
    match request_loop_once(params, protocol, request) {
        Ok(()) => SvsmResultCode::SUCCESS.into(),
        Err(SvsmReqError::RequestError(code)) => {
            log::debug!("Soft error handling protocol {protocol} request {request}: {code:?}");
            code.into()
        }
        Err(SvsmReqError::FatalError(err)) => {
            panic!(
                "Fatal error handling core protocol request {}: {:?}",
                request, err
            );
        }
    }
}

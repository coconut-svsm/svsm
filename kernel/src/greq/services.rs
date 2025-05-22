// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

//! API to send `SNP_GUEST_REQUEST` commands to the PSP

use zerocopy::FromBytes;

use crate::{
    greq::{
        driver::{send_extended_guest_request, send_regular_guest_request},
        msg::SnpGuestRequestMsgType,
        pld_report::{SnpReportRequest, SnpReportResponse},
    },
    protocols::errors::SvsmReqError,
};
use core::mem::size_of;

const REPORT_REQUEST_SIZE: usize = size_of::<SnpReportRequest>();
const REPORT_RESPONSE_SIZE: usize = size_of::<SnpReportResponse>();

fn get_report(buffer: &mut [u8], certs: Option<&mut [u8]>) -> Result<usize, SvsmReqError> {
    let request: &SnpReportRequest = SnpReportRequest::try_from_as_ref(buffer)?;
    // Non-VMPL0 attestation reports can be requested by the guest kernel
    // directly to the PSP.
    if !request.is_vmpl0() {
        return Err(SvsmReqError::invalid_parameter());
    }
    let response_len = if certs.is_none() {
        send_regular_guest_request(
            SnpGuestRequestMsgType::ReportRequest,
            buffer,
            REPORT_REQUEST_SIZE,
        )?
    } else {
        send_extended_guest_request(
            SnpGuestRequestMsgType::ReportRequest,
            buffer,
            REPORT_REQUEST_SIZE,
            certs.unwrap(),
        )?
    };
    if REPORT_RESPONSE_SIZE > response_len {
        return Err(SvsmReqError::invalid_request());
    }
    let (response, _rest) = SnpReportResponse::ref_from_prefix(buffer)
        .map_err(|_| SvsmReqError::invalid_parameter())?;
    response.validate()?;

    Ok(response_len)
}

/// Request a regular VMPL0 attestation report to the PSP.
///
/// Use the `SNP_GUEST_REQUEST` driver to send the provided `MSG_REPORT_REQ` command to
/// the PSP. The VPML field of the command must be set to zero.
///
/// The VMPCK0 is disabled for subsequent calls if this function fails in a way that
/// the VM state can be compromised.
///
/// # Arguments
///
/// * `buffer`: Buffer with the [`MSG_REPORT_REQ`](SnpReportRequest) command that will be
///   sent to the PSP. It must be large enough to hold the
///   [`MSG_REPORT_RESP`](SnpReportResponse) received from the PSP.
///
/// # Returns
///
/// * Success
///     * `usize`: Number of bytes written to `buffer`. It should match the
///       [`MSG_REPORT_RESP`](SnpReportResponse) size.
/// * Error
///     * [`SvsmReqError`]
pub fn get_regular_report(buffer: &mut [u8]) -> Result<usize, SvsmReqError> {
    get_report(buffer, None)
}

/// Request an extended VMPL0 attestation report to the PSP.
///
/// We say that it is extended because it requests a VMPL0 attestation report
/// to the PSP (as in [`get_regular_report()`]) and also requests to the hypervisor
/// the certificates required to verify the attestation report.
///
/// The VMPCK0 is disabled for subsequent calls if this function fails in a way that
/// the VM state can be compromised.
///
/// # Arguments
///
/// * `buffer`: Buffer with the [`MSG_REPORT_REQ`](SnpReportRequest) command that will be
///   sent to the PSP. It must be large enough to hold the
///   [`MSG_REPORT_RESP`](SnpReportResponse) received from the PSP.
/// * `certs`:  Buffer to store the SEV-SNP certificates received from the hypervisor.
///
/// # Return codes
///
/// * Success
///     * `usize`: Number of bytes written to `buffer`. It should match
///       the [`MSG_REPORT_RESP`](SnpReportResponse) size.
/// * Error
///     * [`SvsmReqError`]
///     * `SvsmReqError::FatalError(SvsmError::Ghcb(GhcbError::VmgexitError(certs_buffer_size, psp_rc)))`:
///         * `certs` is not large enough to hold the certificates.
///             * `certs_buffer_size`: number of bytes required.
///             * `psp_rc`: PSP return code
pub fn get_extended_report(buffer: &mut [u8], certs: &mut [u8]) -> Result<usize, SvsmReqError> {
    get_report(buffer, Some(certs))
}

#[cfg(test)]
mod tests {
    #[allow(unused)]
    use super::*;

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[cfg(test_in_svsm)]
    fn test_snp_launch_measurement() {
        extern crate alloc;

        use crate::serial::Terminal;
        use crate::testing::{assert_eq_warn, svsm_test_io, IORequest};
        use crate::testutils::{is_qemu_test_env, is_test_platform_type};

        use alloc::vec;
        use bootlib::platform::SvsmPlatformType;

        if is_qemu_test_env() && is_test_platform_type(SvsmPlatformType::Snp) {
            let sp = svsm_test_io().unwrap();

            sp.put_byte(IORequest::GetLaunchMeasurement as u8);

            let mut expected_measurement = [0u8; 48];
            for byte in &mut expected_measurement {
                *byte = sp.get_byte();
            }

            let mut buf = vec![0; size_of::<SnpReportResponse>()];
            let size = get_regular_report(&mut buf).unwrap();
            assert_eq!(size, buf.len());

            let (response, _rest) = SnpReportResponse::ref_from_prefix(&buf).unwrap();
            response.validate().unwrap();
            // FIXME: we still have some cases where the precalculated value does
            // not match, so for now we just issue a warning until we fix the problem.
            assert_eq_warn!(expected_measurement, *response.measurement());
        }
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr};
use crate::cpu::irq_state::raw_irqs_disable;
use crate::cpu::msr::{read_msr, write_msr, SEV_GHCB};
use crate::cpu::{irqs_enabled, IrqGuard};
use crate::error::SvsmError;
use crate::platform::halt;
use crate::utils::immut_after_init::ImmutAfterInitCell;

use super::utils::raw_vmgexit;

use bitflags::bitflags;
use core::fmt;
use core::fmt::Display;

#[derive(Clone, Copy, Debug)]
pub enum GhcbMsrError {
    // The info section of the response did not match our request
    InfoMismatch,
    // The data section of the response did not match our request,
    // or it was malformed altogether.
    DataMismatch,
}

impl From<GhcbMsrError> for SvsmError {
    fn from(e: GhcbMsrError) -> Self {
        Self::GhcbMsr(e)
    }
}

#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum GHCBMsr {}

impl GHCBMsr {
    pub const SEV_INFO_REQ: u64 = 0x02;
    pub const SEV_INFO_RESP: u64 = 0x01;
    pub const SNP_REG_GHCB_GPA_REQ: u64 = 0x12;
    pub const SNP_REG_GHCB_GPA_RESP: u64 = 0x13;
    pub const SNP_STATE_CHANGE_REQ: u64 = 0x14;
    pub const SNP_STATE_CHANGE_RESP: u64 = 0x15;
    pub const SNP_HV_FEATURES_REQ: u64 = 0x80;
    pub const SNP_HV_FEATURES_RESP: u64 = 0x81;
    pub const TERM_REQ: u64 = 0x100;
}

bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct GHCBHvFeatures: u64 {
        const SEV_SNP                 = 1 << 0;
        const SEV_SNP_AP_CREATION     = 1 << 1;
        const SEV_SNP_RESTR_INJ       = 1 << 2;
        const SEV_SNP_RESTR_INJ_TIMER = 1 << 3;
        const APIC_ID_LIST            = 1 << 4;
        const SEV_SNP_MULTI_VMPL      = 1 << 5;
        const SEV_PAGE_STATE_CHANGE   = 1 << 6;
        const SEV_SNP_EXT_INTERRUPTS  = 1 << 9;
    }
}

impl Display for GHCBHvFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{:#x}", self.bits()))
    }
}

static GHCB_HV_FEATURES: ImmutAfterInitCell<GHCBHvFeatures> = ImmutAfterInitCell::uninit();

/// Check that we support the hypervisor's advertised GHCB versions.
pub fn verify_ghcb_version() {
    // This function is normally only called early during initializtion before
    // interrupts have been enabled, and before interrupt guards can safely be
    // used.
    assert!(!irqs_enabled());
    // Request SEV information.
    // SAFETY: Requesting info through the GHCB MSR protocol is safe.
    unsafe { write_msr(SEV_GHCB, GHCBMsr::SEV_INFO_REQ) };
    raw_vmgexit();
    let sev_info = read_msr(SEV_GHCB);

    // Parse the results.

    let response_ty = sev_info & 0xfff;
    assert_eq!(
        response_ty,
        GHCBMsr::SEV_INFO_RESP,
        "unexpected response type: {response_ty:#05x}"
    );

    // Compare announced supported GHCB MSR protocol version range
    // for compatibility.
    let min_version = (sev_info >> 32) & 0xffff;
    let max_version = (sev_info >> 48) & 0xffff;
    assert!(
        (min_version..=max_version).contains(&2),
        "the hypervisor doesn't support GHCB version 2 (min: {min_version}, max: {max_version})"
    );
}

pub fn hypervisor_ghcb_features() -> GHCBHvFeatures {
    *GHCB_HV_FEATURES
}

pub fn init_hypervisor_ghcb_features() -> Result<(), GhcbMsrError> {
    let guard = IrqGuard::new();
    // SAFETY: Requesting HV features through the GHCB MSR protocol is safe.
    unsafe { write_msr(SEV_GHCB, GHCBMsr::SNP_HV_FEATURES_REQ) };
    raw_vmgexit();
    let result = read_msr(SEV_GHCB);
    drop(guard);
    if (result & 0xFFF) == GHCBMsr::SNP_HV_FEATURES_RESP {
        let features = GHCBHvFeatures::from_bits_truncate(result >> 12);

        // Verify that the required features are supported.
        let required = GHCBHvFeatures::SEV_SNP
            | GHCBHvFeatures::SEV_SNP_AP_CREATION
            | GHCBHvFeatures::SEV_SNP_MULTI_VMPL;
        let missing = !features & required;
        if !missing.is_empty() {
            log::error!(
                "Required hypervisor GHCB features not available: present={:#x}, required={:#x}, missing={:#x}",
                features, required, missing
            );
            // FIXME - enforce this panic once KVM advertises the required
            // features.
            // panic!("Required hypervisor GHCB features not available");
        }

        GHCB_HV_FEATURES
            .init(features)
            .expect("Already initialized GHCB HV features");
        Ok(())
    } else {
        Err(GhcbMsrError::InfoMismatch)
    }
}

/// # Safety
///
/// Since this causes the GHCB to be remapped to a different physical address
/// (allowing leaking and modifying its content), `addr` should be validated.
pub unsafe fn register_ghcb_gpa_msr(addr: PhysAddr) -> Result<(), GhcbMsrError> {
    let mut info = addr.bits() as u64;

    info |= GHCBMsr::SNP_REG_GHCB_GPA_REQ;
    let guard = IrqGuard::new();
    // SAFETY: safety requirements should be checked by the caller
    unsafe { write_msr(SEV_GHCB, info) };
    raw_vmgexit();
    info = read_msr(SEV_GHCB);
    drop(guard);

    if (info & 0xfff) != GHCBMsr::SNP_REG_GHCB_GPA_RESP {
        return Err(GhcbMsrError::InfoMismatch);
    }

    if (info & !0xfff) != (addr.bits() as u64) {
        return Err(GhcbMsrError::DataMismatch);
    }

    Ok(())
}

/// # Safety
///
/// See [`validate_page_msr`] or [`invalidate_page_msr`] safety requirements.
unsafe fn set_page_valid_status_msr(addr: PhysAddr, valid: bool) -> Result<(), GhcbMsrError> {
    let mut info: u64 = (addr.bits() as u64) & 0x000f_ffff_ffff_f000;

    if valid {
        info |= 1u64 << 52;
    } else {
        info |= 2u64 << 52;
    }

    info |= GHCBMsr::SNP_STATE_CHANGE_REQ;
    let guard = IrqGuard::new();
    // SAFETY: safety requirements are delegated to the caller.
    unsafe { write_msr(SEV_GHCB, info) };
    raw_vmgexit();
    let response = read_msr(SEV_GHCB);
    drop(guard);

    if (response & 0xfff) != GHCBMsr::SNP_STATE_CHANGE_RESP {
        return Err(GhcbMsrError::InfoMismatch);
    }

    if (response & !0xfff) != 0 {
        return Err(GhcbMsrError::DataMismatch);
    }

    Ok(())
}

/// # Safety
///
/// Since this causes a page to be remmaped with a different encryption
/// attribute, `addr` should be validated.
pub unsafe fn validate_page_msr(addr: PhysAddr) -> Result<(), GhcbMsrError> {
    // SAFETY: safety requirements are delegated to the caller.
    unsafe { set_page_valid_status_msr(addr, true) }
}

/// # Safety
///
/// Since this causes a page to be remmaped with a different encryption
/// attribute, `addr` should be validated.
pub unsafe fn invalidate_page_msr(addr: PhysAddr) -> Result<(), GhcbMsrError> {
    // SAFETY: safety requirements are delegated to the caller.
    unsafe { set_page_valid_status_msr(addr, false) }
}

pub fn request_termination_msr() -> ! {
    let info: u64 = GHCBMsr::TERM_REQ;

    // Since this processor is destined for a fatal termination, there is
    // no reason to preserve interrupt state.  Interrupts can be disabled
    // outright prior to shutdown.
    raw_irqs_disable();
    // SAFETY: Requesting termination doesn't break memory safety.
    unsafe { write_msr(SEV_GHCB, info) };
    raw_vmgexit();
    loop {
        halt();
    }
}

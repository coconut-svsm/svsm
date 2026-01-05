// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod ghcb;
pub mod hv_doorbell;
pub mod msr_protocol;
pub mod secrets_page;
pub mod snp_apic;
pub mod status;
pub mod tlb;
pub mod vmsa;

pub mod utils;

pub use msr_protocol::init_hypervisor_ghcb_features;
pub use secrets_page::{SecretsPage, VMPCK_SIZE, secrets_page, secrets_page_mut};
pub use snp_apic::{GHCB_APIC_ACCESSOR, GHCBApicAccessor};
pub use status::sev_status_init;
pub use status::sev_status_verify;
pub use utils::{PvalidateOp, SevSnpError, pvalidate, pvalidate_range};
pub use utils::{RMPFlags, rmp_adjust};

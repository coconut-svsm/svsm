// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod ghcb;
pub mod hv_doorbell;
pub mod msr_protocol;
pub mod secrets_page;
pub mod status;
pub mod vmsa;

pub mod utils;

pub use msr_protocol::init_hypervisor_ghcb_features;
pub use secrets_page::{secrets_page, secrets_page_mut, SecretsPage, VMPCK_SIZE};
pub use status::sev_status_init;
pub use status::sev_status_verify;
pub use status::{sev_es_enabled, sev_snp_enabled};
pub use utils::{pvalidate, pvalidate_range, PvalidateOp, SevSnpError};
pub use utils::{rmp_adjust, RMPFlags};

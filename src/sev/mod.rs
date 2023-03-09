// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod ghcb;
pub mod msr_protocol;
pub mod secrets_page;
pub mod status;
pub mod vmsa;

pub mod utils;

pub use status::sev_status_init;
pub use status::sev_status_verify;
pub use status::{sev_es_enabled, sev_snp_enabled};
pub use utils::{pvalidate, pvalidate_range, SevSnpError};
pub use utils::{rmp_adjust, RMPFlags};

// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

//! OCP protocol implementation (SVSM draft spec).

pub mod requests;
pub mod source;

pub use requests::{
    OBSERVABILITY_CONFIGURATION_PROTOCOL_VERSION_MAX,
    OBSERVABILITY_CONFIGURATION_PROTOCOL_VERSION_MIN, add_ocp_object, ocp_protocol_request,
};

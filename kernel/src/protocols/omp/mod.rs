// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

//! Observability and Management Protocol (OMP) implementation.

pub mod requests;
pub mod source;

pub use requests::{
    OBSERVABILITY_MANAGEMENT_PROTOCOL_VERSION_MAX, OBSERVABILITY_MANAGEMENT_PROTOCOL_VERSION_MIN,
    omp_protocol_request,
};

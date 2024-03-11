// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

//! This crate provides definitions of structures used bo COCONUT-SVSM during
//! its boot process, which must also be shared with the utility that builds
//! the boot image file.

#![no_std]

pub mod igvm_params;
pub mod kernel_launch;
pub mod platform;

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::platform::SvsmPlatform;

#[derive(Clone, Copy, Debug)]
pub struct NativePlatform {}

impl NativePlatform {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for NativePlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl SvsmPlatform for NativePlatform {
    fn env_setup(&mut self) {}
    fn env_setup_late(&mut self) {}
}

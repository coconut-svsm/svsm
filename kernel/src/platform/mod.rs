// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::platform::native::NativePlatform;
use crate::platform::snp::SnpPlatform;

use bootlib::platform::SvsmPlatformType;

pub mod native;
pub mod snp;

/// This defines a platform abstraction to permit the SVSM to run on different
/// underlying architectures.
pub trait SvsmPlatform {
    /// Performs basic early initialization of the runtime environment.
    fn env_setup(&mut self);

    /// Performs initialization of the platform runtime environment after
    /// console logging has been initialized.
    fn env_setup_late(&mut self);
}

//FIXME - remove Copy trait
#[derive(Clone, Copy, Debug)]
pub enum SvsmPlatformCell {
    Snp(SnpPlatform),
    Native(NativePlatform),
}

impl SvsmPlatformCell {
    pub fn new(platform_type: SvsmPlatformType) -> Self {
        match platform_type {
            SvsmPlatformType::Native => SvsmPlatformCell::Native(NativePlatform::new()),
            SvsmPlatformType::Snp => SvsmPlatformCell::Snp(SnpPlatform::new()),
        }
    }

    pub fn as_mut_dyn_ref(&mut self) -> &mut dyn SvsmPlatform {
        match self {
            SvsmPlatformCell::Native(platform) => platform,
            SvsmPlatformCell::Snp(platform) => platform,
        }
    }
}

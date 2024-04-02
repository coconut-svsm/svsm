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

#[derive(Clone, Copy, Debug)]
pub struct PageEncryptionMasks {
    pub private_pte_mask: usize,
    pub shared_pte_mask: usize,
    pub addr_mask_width: u32,
    pub phys_addr_sizes: u32,
}

/// This defines a platform abstraction to permit the SVSM to run on different
/// underlying architectures.
pub trait SvsmPlatform {
    /// Performs basic early initialization of the runtime environment.
    fn env_setup(&mut self);

    /// Performs initialization of the platform runtime environment after
    /// console logging has been initialized.
    fn env_setup_late(&mut self);

    /// Determines the paging encryption masks for the current architecture.
    fn get_page_encryption_masks(&self, vtom: usize) -> PageEncryptionMasks;
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

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2025 Intel Corporation
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

#[derive(Copy, Clone, Debug)]
pub enum Cap {
    AvailableVmBitmap = 0,
    GlobalFeatureBitmap,
    NrCaps,
}

impl TryFrom<u32> for Cap {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == (Cap::AvailableVmBitmap as u32) {
            Ok(Cap::AvailableVmBitmap)
        } else if value == (Cap::GlobalFeatureBitmap as u32) {
            Ok(Cap::GlobalFeatureBitmap)
        } else if value == (Cap::NrCaps as u32) {
            Ok(Cap::NrCaps)
        } else {
            Err(())
        }
    }
}

impl From<Cap> for u32 {
    fn from(cap: Cap) -> Self {
        cap as Self
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Caps([u64; Cap::NrCaps as usize]);

impl Caps {
    pub fn new(vm_bitmap: u64, global_feat_bitmap: u64) -> Self {
        let mut caps = [0; Cap::NrCaps as usize];

        caps[Cap::AvailableVmBitmap as usize] = vm_bitmap;
        caps[Cap::GlobalFeatureBitmap as usize] = global_feat_bitmap;
        Self(caps)
    }

    pub fn get(&self, idx: Cap) -> u64 {
        match idx {
            Cap::NrCaps => Cap::NrCaps as u64,
            _ => *self.0.get(idx as usize).unwrap(),
        }
    }
}

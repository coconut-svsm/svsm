// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::error::SvsmError;

use super::io::IOPort;
use alloc::string::String;
use core::mem::size_of;

const FW_CFG_CTL: u16 = 0x510;
const FW_CFG_DATA: u16 = 0x511;

const _FW_CFG_ID: u16 = 0x01;
const FW_CFG_FILE_DIR: u16 = 0x19;

const MAX_FW_CFG_FILES: u32 = 0x1000;

#[non_exhaustive]
#[derive(Debug)]
pub struct FwCfg<'a> {
    driver: &'a dyn IOPort,
}

#[derive(Clone, Copy, Debug)]
pub enum FwCfgError {
    // Could not find the appropriate file selector.
    FileNotFound,
    // Unexpected file size.
    FileSize(u32),
    // Could not find an appropriate kernel region for the SVSM.
    KernelRegion,
    /// The firmware provided too many files to the guest
    TooManyFiles,
    /// Invalid Data format
    InvalidFormat,
}

impl From<FwCfgError> for SvsmError {
    fn from(err: FwCfgError) -> Self {
        Self::FwCfg(err)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FwCfgFile {
    size: u32,
    selector: u16,
}

impl FwCfgFile {
    pub fn size(&self) -> u32 {
        self.size
    }
    pub fn selector(&self) -> u16 {
        self.selector
    }
}

impl<'a> FwCfg<'a> {
    pub fn new(driver: &'a dyn IOPort) -> Self {
        FwCfg { driver }
    }

    pub fn select(&self, cfg: u16) {
        self.driver.outw(FW_CFG_CTL, cfg);
    }

    pub fn read_bytes(&self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            *byte = self.driver.inb(FW_CFG_DATA);
        }
    }

    fn read_be<T>(&self) -> T
    where
        T: core::ops::Shl<usize, Output = T> + core::ops::BitOr<T, Output = T> + From<u8>,
    {
        let mut val = T::from(0u8);
        let io = &self.driver;

        for _ in 0..size_of::<T>() {
            val = (val << 8) | T::from(io.inb(FW_CFG_DATA));
        }
        val
    }

    fn read_u8(&self) -> u8 {
        self.driver.inb(FW_CFG_DATA)
    }

    pub fn file_selector(&self, name: &str) -> Result<FwCfgFile, SvsmError> {
        self.select(FW_CFG_FILE_DIR);
        let n: u32 = self.read_be();

        if n > MAX_FW_CFG_FILES {
            return Err(SvsmError::FwCfg(FwCfgError::TooManyFiles));
        }

        for _ in 0..n {
            let size: u32 = self.read_be();
            let selector: u16 = self.read_be();
            let _unused: u16 = self.read_be();
            let mut st = String::with_capacity(56);
            let mut terminated = false;
            for _ in 0..56 {
                let c = self.read_u8();
                if terminated || c == b'\0' {
                    terminated = true;
                } else {
                    st.push(c.into());
                }
            }

            if st == name {
                return Ok(FwCfgFile { size, selector });
            }
        }

        Err(SvsmError::FwCfg(FwCfgError::FileNotFound))
    }
}

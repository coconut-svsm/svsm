// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::error::SvsmError;
use zerocopy::FromBytes;

use super::io::IOPort;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::size_of;

const FW_CFG_CTL: u16 = 0x510;
const FW_CFG_DATA: u16 = 0x511;

const _FW_CFG_ID: u16 = 0x01;
const FW_CFG_FILE_DIR: u16 = 0x19;

const MAX_FW_CFG_FILES: u32 = 0x1000;

mod hardware_info {
    use zerocopy::{FromBytes, Immutable, KnownLayout};

    pub const HW_INFO_FILE: &str = "etc/hardware-info";

    pub const TYPE_SVSM_VIRTIO_MMIO: u64 = 0x1000;

    #[derive(FromBytes, Debug, Immutable, KnownLayout)]
    #[repr(C)]
    pub struct Header {
        pub hw_type: u64,
        pub size: u64,
    }

    #[derive(FromBytes, Debug, Immutable, KnownLayout)]
    #[repr(C)]
    pub struct SimpleDevice {
        pub mmio_address: u64,
    }
}

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

#[derive(Debug)]
struct FwCfgFileIterator<'a> {
    fw_cfg: &'a FwCfg<'a>,
    file_size: usize,
}

impl<'a> FwCfgFileIterator<'a> {
    pub fn new(fw_cfg: &'a FwCfg<'a>, file_name: &str) -> Result<Self, SvsmError> {
        let file = fw_cfg.file_selector(file_name)?;
        fw_cfg.select(file.selector);
        Ok(Self {
            fw_cfg,
            file_size: file.size as usize,
        })
    }
}

impl Iterator for FwCfgFileIterator<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.file_size == 0 {
            return None;
        }
        self.file_size -= 1;
        Some(self.fw_cfg.read_u8())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.file_size, Some(self.file_size))
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

    /// Try reading an instance of T from the iterator.
    fn read_from_it<T: FromBytes>(i: &mut impl Iterator<Item = u8>) -> Result<T, FwCfgError> {
        let buffer: Vec<u8> = i.take(size_of::<T>()).collect();
        T::read_from_bytes(buffer.as_slice()).map_err(|_| FwCfgError::InvalidFormat)
    }

    pub fn get_virtio_mmio_addresses(&self) -> Result<Vec<u64>, SvsmError> {
        use hardware_info::*;

        let mut it = FwCfgFileIterator::new(self, HW_INFO_FILE)?;

        let mut addresses: Vec<u64> = Vec::<u64>::new();

        while let Ok(header) = Self::read_from_it::<Header>(&mut it) {
            if header.hw_type == TYPE_SVSM_VIRTIO_MMIO {
                addresses.push(Self::read_from_it::<SimpleDevice>(&mut it)?.mmio_address);
            } else {
                for _ in 0..header.size as usize {
                    it.next();
                }
            }
        }
        Ok(addresses)
    }
}

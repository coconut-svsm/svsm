// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::address::{Address, PhysAddr};
use crate::error::SvsmError;
use crate::mm::pagetable::max_phys_addr;
use crate::utils::MemoryRegion;

use super::io::IOPort;
use super::string::FixedString;
use alloc::vec::Vec;
use core::mem::size_of;

const FW_CFG_CTL: u16 = 0x510;
const FW_CFG_DATA: u16 = 0x511;

const _FW_CFG_ID: u16 = 0x01;
const FW_CFG_FILE_DIR: u16 = 0x19;

// Must be a power-of-2
const KERNEL_REGION_SIZE: u64 = 16 * 1024 * 1024;
const KERNEL_REGION_SIZE_MASK: u64 = !(KERNEL_REGION_SIZE - 1);

const MAX_FW_CFG_FILES: u32 = 0x1000;

//use crate::println;

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

    pub fn read_le<T>(&self) -> T
    where
        T: core::ops::Shl<usize, Output = T> + core::ops::BitOr<T, Output = T> + From<u8>,
    {
        let mut val = T::from(0u8);
        let io = &self.driver;

        for i in 0..size_of::<T>() {
            val = (T::from(io.inb(FW_CFG_DATA)) << (i * 8)) | val;
        }
        val
    }

    pub fn read_be<T>(&self) -> T
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

    pub fn read_char(&self) -> char {
        self.driver.inb(FW_CFG_DATA) as char
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
            let mut fs = FixedString::<56>::new();
            for _ in 0..56 {
                let c = self.read_char();
                fs.push(c);
            }

            if fs == name {
                return Ok(FwCfgFile { size, selector });
            }
        }

        Err(SvsmError::FwCfg(FwCfgError::FileNotFound))
    }

    fn find_svsm_region(&self) -> Result<MemoryRegion<PhysAddr>, SvsmError> {
        let file = self.file_selector("etc/sev/svsm")?;

        if file.size != 16 {
            return Err(SvsmError::FwCfg(FwCfgError::FileSize(file.size)));
        }

        self.select(file.selector);
        Ok(self.read_memory_region())
    }

    fn read_memory_region(&self) -> MemoryRegion<PhysAddr> {
        let start = PhysAddr::from(self.read_le::<u64>());
        let size = self.read_le::<u64>();
        let end = start.saturating_add(size as usize);

        assert!(start <= max_phys_addr(), "{start:#018x} is out of range");
        assert!(end <= max_phys_addr(), "{end:#018x} is out of range");

        MemoryRegion::from_addresses(start, end)
    }

    pub fn get_memory_regions(&self) -> Result<Vec<MemoryRegion<PhysAddr>>, SvsmError> {
        let mut regions = Vec::new();
        let file = self.file_selector("etc/e820")?;
        let entries = file.size / 20;

        self.select(file.selector);

        for _ in 0..entries {
            let region = self.read_memory_region();
            let t: u32 = self.read_le();

            if t == 1 {
                regions.push(region);
            }
        }

        Ok(regions)
    }

    fn find_kernel_region_e820(&self) -> Result<MemoryRegion<PhysAddr>, SvsmError> {
        let regions = self.get_memory_regions()?;
        let kernel_region = regions
            .iter()
            .max_by_key(|region| region.start())
            .ok_or(SvsmError::FwCfg(FwCfgError::KernelRegion))?;

        let start = PhysAddr::from(
            kernel_region
                .end()
                .bits()
                .saturating_sub(KERNEL_REGION_SIZE as usize)
                & KERNEL_REGION_SIZE_MASK as usize,
        );

        if start < kernel_region.start() {
            return Err(SvsmError::FwCfg(FwCfgError::KernelRegion));
        }

        Ok(MemoryRegion::new(start, kernel_region.len()))
    }

    pub fn find_kernel_region(&self) -> Result<MemoryRegion<PhysAddr>, SvsmError> {
        let kernel_region = self
            .find_svsm_region()
            .or_else(|_| self.find_kernel_region_e820())?;

        // Make sure that the kernel region doesn't overlap with the loader.
        if kernel_region.start() < PhysAddr::from(640 * 1024u64) {
            return Err(SvsmError::FwCfg(FwCfgError::KernelRegion));
        }

        Ok(kernel_region)
    }

    // This needs to be &mut self to prevent iterator invalidation, where the caller
    // could do fw_cfg.select() while iterating. Having a mutable reference prevents
    // other references.
    pub fn iter_flash_regions(&self) -> impl Iterator<Item = MemoryRegion<PhysAddr>> + '_ {
        let num = match self.file_selector("etc/flash") {
            Ok(file) => {
                self.select(file.selector);
                file.size as usize / 16
            }
            Err(_) => 0,
        };

        (0..num).map(|_| self.read_memory_region())
    }
}

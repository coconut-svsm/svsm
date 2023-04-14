// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::error::SvsmError;
use crate::mm::pagetable::max_phys_addr;

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

//use crate::println;

#[non_exhaustive]

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
}

impl From<FwCfgError> for SvsmError {
    fn from(err: FwCfgError) -> Self {
        Self::FwCfg(err)
    }
}

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

#[derive(Clone, Copy)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
}

impl MemoryRegion {
    /// Returns `true` if the region overlaps with another region with given
    /// start and end.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }
}

impl<'a> FwCfg<'a> {
    pub fn new(driver: &'a dyn IOPort) -> Self {
        FwCfg { driver }
    }

    pub fn select(&self, cfg: u16) {
        self.driver.outw(FW_CFG_CTL, cfg);
    }

    pub fn read_le<T>(&self) -> T
    where
        T: core::ops::Shl<usize, Output = T>
            + core::ops::BitOr<T, Output = T>
            + core::convert::From<u8>,
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
        T: core::ops::Shl<usize, Output = T>
            + core::ops::BitOr<T, Output = T>
            + core::convert::From<u8>,
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

        for _ in 0..n {
            let size: u32 = self.read_be();
            let select: u16 = self.read_be();
            let _unused: u16 = self.read_be();
            let mut fs = FixedString::<56>::new();
            for _ in 0..56 {
                let c = self.read_char();
                fs.push(c);
            }

            if fs == name {
                return Ok(FwCfgFile {
                    size: size,
                    selector: select,
                });
            }
        }

        Err(SvsmError::FwCfg(FwCfgError::FileNotFound))
    }

    fn find_svsm_region(&self) -> Result<MemoryRegion, SvsmError> {
        let file = self.file_selector("etc/sev/svsm")?;

        if file.size != 16 {
            return Err(SvsmError::FwCfg(FwCfgError::FileSize(file.size)));
        }

        self.select(file.selector);
        Ok(self.read_memory_region())
    }

    fn read_memory_region(&self) -> MemoryRegion {
        let start: u64 = self.read_le();
        let size: u64 = self.read_le();
        let end = start.saturating_add(size);

        assert!(start <= max_phys_addr(), "{start:#018x} is out of range");
        assert!(end <= max_phys_addr(), "{end:#018x} is out of range");

        MemoryRegion { start, end }
    }

    pub fn get_memory_regions(&self) -> Result<Vec<MemoryRegion>, SvsmError> {
        let mut regions: Vec<MemoryRegion> = Vec::new();
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

    fn find_kernel_region_e820(&self) -> Result<MemoryRegion, SvsmError> {
        let regions = self.get_memory_regions()?;
        let mut kernel_region = regions
            .iter()
            .max_by_key(|region| region.start)
            .copied()
            .ok_or(SvsmError::FwCfg(FwCfgError::KernelRegion))?;

        let start =
            (kernel_region.end.saturating_sub(KERNEL_REGION_SIZE)) & KERNEL_REGION_SIZE_MASK;

        if start < kernel_region.start {
            return Err(SvsmError::FwCfg(FwCfgError::KernelRegion));
        }

        kernel_region.start = start;

        Ok(kernel_region)
    }

    pub fn find_kernel_region(&self) -> Result<MemoryRegion, SvsmError> {
        let kernel_region = self
            .find_svsm_region()
            .or_else(|_| self.find_kernel_region_e820())?;

        // Make sure that the kernel region doesn't overlap with the loader.
        if kernel_region.start < 640 * 1024 {
            return Err(SvsmError::FwCfg(FwCfgError::KernelRegion));
        }

        Ok(kernel_region)
    }

    // This needs to be &mut self to prevent iterator invalidation, where the caller
    // could do fw_cfg.select() while iterating. Having a mutable reference prevents
    // other references.
    pub fn iter_flash_regions(&mut self) -> impl Iterator<Item = MemoryRegion> + '_ {
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

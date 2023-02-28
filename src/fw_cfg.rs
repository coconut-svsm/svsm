// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

extern crate alloc;

use super::io::IOPort;
use super::string::FixedString;
use core::mem::size_of;
use alloc::vec::Vec;

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
            + core::convert::From<u8>
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
            + core::convert::From<u8>
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

    pub fn file_selector(&self, name: &str) -> Result<FwCfgFile, ()> {
        let mut ret: Result<FwCfgFile, ()> = Err(());
        self.select(FW_CFG_FILE_DIR);
        let mut n: u32 = self.read_be();

        while n != 0 {
            let size: u32 = self.read_be();
            let select: u16 = self.read_be();
            let _unused: u16 = self.read_be();
            let mut fs = FixedString::<56>::new();
            for _ in 0..56 {
                let c = self.read_char();
                fs.push(c);
            }

    //        log::info!("FwCfg File: {} Size: {}", fs, size);

            if fs == name {
                ret = Ok(FwCfgFile {
                    size: size,
                    selector: select,
                });
            }
            n -= 1;
        }
        ret
    }

    fn find_svsm_region(&self) -> Result<MemoryRegion, ()> {
        let file = self.file_selector("etc/sev/svsm")?;

        if file.size != 16 {
            return Err(());
        }

        self.select(file.selector);
        Ok(self.read_memory_region())
    }

    fn read_memory_region(&self) -> MemoryRegion {
        let start: u64 = self.read_le();
        let size: u64 = self.read_le();
        MemoryRegion { start, end: start + size }
    }

    pub fn get_memory_regions(&self) -> Result<Vec<MemoryRegion>, ()> {
        let mut regions: Vec::<MemoryRegion> = Vec::new();
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

    fn find_kernel_region_e820(&self) -> Result<MemoryRegion, ()> {
        let regions = self.get_memory_regions()?;
        let mut kernel_region = regions.iter()
            .max_by_key(|region| region.start)
            .copied()
            .ok_or(())?;

        let start = (kernel_region.end - KERNEL_REGION_SIZE) & KERNEL_REGION_SIZE_MASK;

        if start < kernel_region.start {
            return Err(());
        }

        kernel_region.start = start;

        Ok(kernel_region)
    }

    pub fn find_kernel_region(&self) -> Result<MemoryRegion, ()> {
        match self.find_svsm_region() {
            Ok(region) => Ok(region),
            Err(_) => self.find_kernel_region_e820()
        }
    }

    pub fn flash_region_count(&self) -> u32 {
        let result = self.file_selector("etc/flash");

        if let Err(_) = result {
            return 0;
        }

        let file = result.unwrap();

        return file.size / 16;
    }

    pub fn get_flash_region(&self, index : u32) -> Result<MemoryRegion, ()> {
        let file = self.file_selector("etc/flash")?;

        if index * 16 > file.size - 16 {
            return Err(());
        }

        self.select(file.selector);

        // skip over unwanted entries
        for _ in 0..index*2 {
            let _ = self.read_le::<u64>();
        }

        Ok(self.read_memory_region())
    }
}

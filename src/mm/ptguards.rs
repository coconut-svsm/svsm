// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::{VirtAddr, PhysAddr, PAGE_SIZE, PAGE_SIZE_2M};
use super::pagetable::{PageTable, get_init_pgtable_locked};
use crate::cpu::tlb::{flush_tlb_global_sync, flush_address_sync};

struct RawPTMappingGuard {
    start: VirtAddr,
    end: VirtAddr,
}

impl RawPTMappingGuard {
    pub const fn new(start: VirtAddr, end: VirtAddr) -> Self {
        RawPTMappingGuard {
            start: start,
            end: end,
        }
    }
}

pub struct PTMappingGuard {
    mapping: Option<RawPTMappingGuard>,
}

impl PTMappingGuard {
    pub fn create(start: VirtAddr, end: VirtAddr, phys: PhysAddr) -> Self {
        let raw_mapping = RawPTMappingGuard::new(start, end);
        match get_init_pgtable_locked().map_region_4k(
                start,
                end,
                phys,
                PageTable::data_flags()) {
            Ok(()) => PTMappingGuard {
                mapping: Some(raw_mapping),
            },
            Err(()) => PTMappingGuard { mapping: None },
        }
    }

    pub fn check_mapping(&self) -> Result<(), ()> {
        match self.mapping {
            Some(_) => Ok(()),
            None => Err(()),
        }
    }
}

impl Drop for PTMappingGuard {
    fn drop(&mut self) {
        if let Some(m) = &self.mapping {
            get_init_pgtable_locked().unmap_region_4k(m.start, m.end).expect("Failed guarded region");
            flush_tlb_global_sync();
        }
    }
}

pub struct PageMappingGuard {
    mapping: Option<RawPTMappingGuard>,
    huge : bool,
}

impl PageMappingGuard {
    pub fn create(vaddr: VirtAddr, paddr: PhysAddr, huge : bool) -> Self {
        let size = if huge { PAGE_SIZE_2M } else { PAGE_SIZE };
        let result = match huge {
            false => get_init_pgtable_locked().map_4k(vaddr, paddr, &PageTable::data_flags()),
            true  => get_init_pgtable_locked().map_2m(vaddr, paddr, &PageTable::data_flags()),
        };

        match result {
            Ok(()) => PageMappingGuard { mapping: Some(RawPTMappingGuard::new(vaddr, vaddr + size)), huge: huge },
            Err(()) => PageMappingGuard { mapping: None, huge: huge },
        }
    }

    pub fn check_mapping(&self) -> Result<(), ()> {
        match self.mapping {
            Some(_) => Ok(()),
            None => Err(()),
        }
    }
}

impl Drop for PageMappingGuard {
    fn drop(&mut self) {
        if let Some(m) = &self.mapping {
            match self.huge {
                false => get_init_pgtable_locked().unmap_4k(m.start).expect("Failed to unmap 4k page"),
                true => get_init_pgtable_locked().unmap_2m(m.start).expect("Failed to unmap 2M page"),
            }
            flush_address_sync(m.start);
        }
    }
}

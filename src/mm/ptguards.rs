// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::pagetable::{get_init_pgtable_locked, PageTable};
use crate::cpu::percpu::this_cpu_mut;
use crate::cpu::tlb::{flush_address_sync, flush_tlb_global_sync};
use crate::error::SvsmError;
use crate::mm::virtualrange::{ virt_alloc_range_4k, virt_alloc_range_2m, virt_free_range_4k, virt_free_range_2m};
use crate::types::{PhysAddr, VirtAddr, PAGE_SIZE_2M, PAGE_SIZE};

struct RawPTMappingGuard {
    start: VirtAddr,
    end: VirtAddr,
}

impl RawPTMappingGuard {
    pub const fn new(start: VirtAddr, end: VirtAddr) -> Self {
        RawPTMappingGuard { start, end }
    }
}

pub struct PerCPUPageMappingGuard {
    mapping: Option<RawPTMappingGuard>,
    huge: bool
}

impl PerCPUPageMappingGuard {
    pub fn create(paddr_start: PhysAddr, paddr_end: PhysAddr, alignment: usize) -> Result<Self, SvsmError> {
        let align_mask = (PAGE_SIZE << alignment) - 1;
        let size = paddr_end - paddr_start;
        assert!((size & align_mask) == 0);
        assert!((paddr_start & align_mask) == 0);
        assert!((paddr_end & align_mask) == 0);

        let flags = PageTable::data_flags();
        let huge = ((paddr_start & (PAGE_SIZE_2M - 1)) == 0) && ((paddr_end & (PAGE_SIZE_2M - 1)) == 0);
        let vaddr = if huge {
            let vaddr = virt_alloc_range_2m(size, 0)?;
            if this_cpu_mut().get_pgtable().map_region_2m(vaddr, vaddr + size, paddr_start, flags).is_err() {
                virt_free_range_2m(vaddr, size);
                return Err(SvsmError::Mem);
            }
            vaddr
        } else {
            let vaddr = virt_alloc_range_4k(size, 0)?;
            if this_cpu_mut().get_pgtable().map_region_4k(vaddr, vaddr + size, paddr_start, flags).is_err() {
                virt_free_range_4k(vaddr, size);
                return Err(SvsmError::Mem);
            }
            vaddr
        };

        let raw_mapping = RawPTMappingGuard::new(vaddr, vaddr + size);
        Ok(PerCPUPageMappingGuard {
            mapping: Some(raw_mapping),
            huge,
        })
    }

    pub fn create_4k(paddr: PhysAddr) -> Result<Self, SvsmError> {
        Self::create(paddr, paddr + PAGE_SIZE, 0)
    }

    pub fn virt_addr(&self) -> VirtAddr {
        self.mapping.as_ref().unwrap().start
    }
}

impl Drop for PerCPUPageMappingGuard {
    fn drop(&mut self) {
        if let Some(m) = &self.mapping {
            let size = m.end - m.start;
            if self.huge {
                this_cpu_mut().get_pgtable().unmap_region_2m(m.start, m.end);
                virt_free_range_2m(m.start, size);
            } else {
                this_cpu_mut().get_pgtable().unmap_region_4k(m.start, m.end);
                virt_free_range_4k(m.start, size);
            }
            flush_address_sync(m.start);
        }
    }
}

pub struct PTMappingGuard {
    mapping: Option<RawPTMappingGuard>,
}

impl PTMappingGuard {
    pub fn create(start: VirtAddr, end: VirtAddr, phys: PhysAddr) -> Self {
        let raw_mapping = RawPTMappingGuard::new(start, end);
        match get_init_pgtable_locked().map_region_4k(start, end, phys, PageTable::data_flags()) {
            Ok(()) => PTMappingGuard {
                mapping: Some(raw_mapping),
            },
            Err(_e) => PTMappingGuard { mapping: None },
        }
    }

    pub fn check_mapping(&self) -> Result<(), SvsmError> {
        match self.mapping {
            Some(_) => Ok(()),
            None => Err(SvsmError::Mem),
        }
    }
}

impl Drop for PTMappingGuard {
    fn drop(&mut self) {
        if let Some(m) = &self.mapping {
            get_init_pgtable_locked().unmap_region_4k(m.start, m.end);
            flush_tlb_global_sync();
        }
    }
}

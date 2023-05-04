// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::pagetable::PageTable;
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::percpu::this_cpu_mut;
use crate::cpu::tlb::flush_address_sync;
use crate::error::SvsmError;
use crate::mm::virtualrange::{
    virt_alloc_range_2m, virt_alloc_range_4k, virt_free_range_2m, virt_free_range_4k,
};
use crate::types::{PAGE_SIZE, PAGE_SIZE_2M};

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
    huge: bool,
}

impl PerCPUPageMappingGuard {
    pub fn create(
        paddr_start: PhysAddr,
        paddr_end: PhysAddr,
        alignment: usize,
    ) -> Result<Self, SvsmError> {
        let align_mask = (PAGE_SIZE << alignment) - 1;
        let size = paddr_end - paddr_start;
        assert!((size & align_mask) == 0);
        assert!((paddr_start.bits() & align_mask) == 0);
        assert!((paddr_end.bits() & align_mask) == 0);

        let flags = PageTable::data_flags();
        let huge = ((paddr_start.bits() & (PAGE_SIZE_2M - 1)) == 0)
            && ((paddr_end.bits() & (PAGE_SIZE_2M - 1)) == 0);
        let vaddr = if huge {
            let vaddr = virt_alloc_range_2m(size, 0)?;
            if this_cpu_mut()
                .get_pgtable()
                .map_region_2m(vaddr, vaddr.offset(size), paddr_start, flags)
                .is_err()
            {
                virt_free_range_2m(vaddr, size);
                return Err(SvsmError::Mem);
            }
            vaddr
        } else {
            let vaddr = virt_alloc_range_4k(size, 0)?;
            if this_cpu_mut()
                .get_pgtable()
                .map_region_4k(vaddr, vaddr.offset(size), paddr_start, flags)
                .is_err()
            {
                virt_free_range_4k(vaddr, size);
                return Err(SvsmError::Mem);
            }
            vaddr
        };

        let raw_mapping = RawPTMappingGuard::new(vaddr, vaddr.offset(size));

        Ok(PerCPUPageMappingGuard {
            mapping: Some(raw_mapping),
            huge,
        })
    }

    pub fn create_4k(paddr: PhysAddr) -> Result<Self, SvsmError> {
        Self::create(paddr, paddr.offset(PAGE_SIZE), 0)
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

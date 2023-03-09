// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use super::pagetable::{get_init_pgtable_locked, PageTable};
use crate::cpu::percpu::this_cpu_mut;
use crate::cpu::tlb::{flush_address_sync, flush_tlb_global_sync};
use crate::mm::{percpu_2m_slot_addr, percpu_4k_slot_addr};
use crate::types::{PhysAddr, VirtAddr, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::is_aligned;

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
}

impl PerCPUPageMappingGuard {
    pub fn create(paddr: VirtAddr, slot: usize, huge: bool) -> Result<Self, ()> {
        let size = if huge { PAGE_SIZE_2M } else { PAGE_SIZE };

        assert!(is_aligned(paddr, size));

        let vaddr = if huge {
            percpu_2m_slot_addr(slot)?
        } else {
            percpu_4k_slot_addr(slot)?
        };
        let flags = PageTable::data_flags();

        if huge {
            this_cpu_mut().get_pgtable().map_2m(vaddr, paddr, flags)?;
        } else {
            this_cpu_mut().get_pgtable().map_4k(vaddr, paddr, flags)?;
        }

        let raw_mapping = RawPTMappingGuard::new(vaddr, vaddr + size);

        Ok(PerCPUPageMappingGuard {
            mapping: Some(raw_mapping),
        })
    }

    pub fn virt_addr(&self) -> VirtAddr {
        self.mapping.as_ref().unwrap().start
    }
}

impl Drop for PerCPUPageMappingGuard {
    fn drop(&mut self) {
        if let Some(m) = &self.mapping {
            let size = m.end - m.start;
            if size == PAGE_SIZE {
                this_cpu_mut().get_pgtable().unmap_4k(m.start);
            } else if size == PAGE_SIZE_2M {
                this_cpu_mut().get_pgtable().unmap_2m(m.start);
            } else {
                unreachable!();
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
            get_init_pgtable_locked().unmap_region_4k(m.start, m.end);
            flush_tlb_global_sync();
        }
    }
}

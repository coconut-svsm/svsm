// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{PhysAddr, VirtAddr};
use crate::mm::pagetable::{PageFrame, PageTable};
use crate::utils::immut_after_init::ImmutAfterInitCell;

#[derive(Debug, Copy, Clone)]
#[cfg_attr(not(any(test, target_os = "none")), expect(dead_code))]
pub struct FixedAddressMappingRange {
    virt_start: VirtAddr,
    virt_end: VirtAddr,
    phys_start: PhysAddr,
}

impl FixedAddressMappingRange {
    pub fn new(virt_start: VirtAddr, virt_end: VirtAddr, phys_start: PhysAddr) -> Self {
        Self {
            virt_start,
            virt_end,
            phys_start,
        }
    }

    #[cfg(target_os = "none")]
    fn phys_to_virt(&self, paddr: PhysAddr) -> Option<VirtAddr> {
        if paddr < self.phys_start {
            None
        } else {
            let size: usize = self.virt_end - self.virt_start;
            if paddr >= self.phys_start + size {
                None
            } else {
                let offset: usize = paddr - self.phys_start;
                Some(self.virt_start + offset)
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[cfg_attr(not(target_os = "none"), expect(dead_code))]
pub struct FixedAddressMapping {
    kernel_mapping: FixedAddressMappingRange,
    heap_mapping: Option<FixedAddressMappingRange>,
}

static FIXED_MAPPING: ImmutAfterInitCell<FixedAddressMapping> = ImmutAfterInitCell::uninit();

pub fn init_kernel_mapping_info(
    kernel_mapping: FixedAddressMappingRange,
    heap_mapping: Option<FixedAddressMappingRange>,
) {
    let mapping = FixedAddressMapping {
        kernel_mapping,
        heap_mapping,
    };
    FIXED_MAPPING
        .init_from_ref(&mapping)
        .expect("Already initialized fixed mapping info");
}

#[cfg(target_os = "none")]
pub fn virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
    match PageTable::virt_to_frame(vaddr) {
        Some(paddr) => paddr.address(),
        None => {
            panic!("Invalid virtual address {:#018x}", vaddr);
        }
    }
}

pub fn virt_to_frame(vaddr: VirtAddr) -> PageFrame {
    match PageTable::virt_to_frame(vaddr) {
        Some(paddr) => paddr,
        None => {
            panic!("Invalid virtual address {:#018x}", vaddr);
        }
    }
}

#[cfg(target_os = "none")]
pub fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
    if let Some(addr) = FIXED_MAPPING.kernel_mapping.phys_to_virt(paddr) {
        return addr;
    }
    if let Some(ref mapping) = FIXED_MAPPING.heap_mapping {
        if let Some(addr) = mapping.phys_to_virt(paddr) {
            return addr;
        }
    }

    panic!("Invalid physical address {:#018x}", paddr);
}

#[cfg(not(target_os = "none"))]
pub fn virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
    use crate::address::Address;
    PhysAddr::from(vaddr.bits())
}

#[cfg(not(target_os = "none"))]
pub fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
    use crate::address::Address;
    VirtAddr::from(paddr.bits())
}

// Address space definitions for SVSM virtual memory layout

/// Size helpers
pub const SIZE_1K: usize = 1024;
pub const SIZE_1M: usize = SIZE_1K * 1024;
pub const SIZE_1G: usize = SIZE_1M * 1024;

/// Pagesize definitions
pub const PAGE_SIZE: usize = SIZE_1K * 4;
pub const PAGE_SIZE_2M: usize = SIZE_1M * 2;

/// More size helpers
pub const SIZE_LEVEL3: usize = 1usize << ((9 * 3) + 12);
pub const SIZE_LEVEL2: usize = 1usize << ((9 * 2) + 12);
#[expect(clippy::identity_op)]
pub const SIZE_LEVEL1: usize = 1usize << ((9 * 1) + 12);
#[expect(clippy::erasing_op, clippy::identity_op)]
pub const SIZE_LEVEL0: usize = 1usize << ((9 * 0) + 12);

// Stack definitions
pub const STACK_PAGES: usize = 8;
pub const STACK_SIZE: usize = PAGE_SIZE * STACK_PAGES;
pub const STACK_GUARD_SIZE: usize = STACK_SIZE;
pub const STACK_TOTAL_SIZE: usize = STACK_SIZE + STACK_GUARD_SIZE;

pub const fn virt_from_idx(idx: usize) -> VirtAddr {
    VirtAddr::new(idx << ((3 * 9) + 12))
}

/// Level3 page-table index shared between all CPUs
pub const PGTABLE_LVL3_IDX_SHARED: usize = 511;

/// Base Address of shared memory region
pub const SVSM_GLOBAL_BASE: VirtAddr = virt_from_idx(PGTABLE_LVL3_IDX_SHARED);

/// Shared mappings region start
pub const SVSM_GLOBAL_MAPPING_BASE: VirtAddr = SVSM_GLOBAL_BASE.const_add(256 * SIZE_1G);

/// Shared mappings region end
pub const SVSM_GLOBAL_MAPPING_END: VirtAddr = SVSM_GLOBAL_MAPPING_BASE.const_add(SIZE_1G);

/// Mapping address for Hyper-V hypercall page.
pub const SVSM_HYPERCALL_CODE_PAGE: VirtAddr = SVSM_GLOBAL_MAPPING_BASE.const_sub(PAGE_SIZE);

/// PerCPU mappings level 3 index
pub const PGTABLE_LVL3_IDX_PERCPU: usize = 510;

/// Base Address of shared memory region
pub const SVSM_PERCPU_BASE: VirtAddr = virt_from_idx(PGTABLE_LVL3_IDX_PERCPU);

/// End Address of per-cpu memory region
pub const SVSM_PERCPU_END: VirtAddr = SVSM_PERCPU_BASE.const_add(SIZE_LEVEL3);

/// PerCPU CAA mappings
pub const SVSM_PERCPU_CAA_BASE: VirtAddr = SVSM_PERCPU_BASE.const_add(2 * SIZE_LEVEL0);

/// PerCPU VMSA mappings
pub const SVSM_PERCPU_VMSA_BASE: VirtAddr = SVSM_PERCPU_BASE.const_add(4 * SIZE_LEVEL0);

/// Region for PerCPU Stacks
pub const SVSM_PERCPU_STACKS_BASE: VirtAddr = SVSM_PERCPU_BASE.const_add(SIZE_LEVEL1);

/// Shadow stack address of the per-cpu init task
pub const SVSM_SHADOW_STACKS_INIT_TASK: VirtAddr = SVSM_PERCPU_STACKS_BASE;

/// Stack address to use during context switches
pub const SVSM_CONTEXT_SWITCH_STACK: VirtAddr = SVSM_SHADOW_STACKS_INIT_TASK.const_add(PAGE_SIZE);

/// Shadow stack address to use during context switches
pub const SVSM_CONTEXT_SWITCH_SHADOW_STACK: VirtAddr =
    SVSM_CONTEXT_SWITCH_STACK.const_add(STACK_TOTAL_SIZE);

///  IST Stacks base address
pub const SVSM_STACKS_IST_BASE: VirtAddr = SVSM_CONTEXT_SWITCH_SHADOW_STACK.const_add(PAGE_SIZE);

/// DoubleFault IST stack base address
pub const SVSM_STACK_IST_DF_BASE: VirtAddr = SVSM_STACKS_IST_BASE;
/// DoubleFault ISST shadow stack base address
pub const SVSM_SHADOW_STACK_ISST_DF_BASE: VirtAddr =
    SVSM_STACKS_IST_BASE.const_add(STACK_TOTAL_SIZE);

/// PerCPU XSave Context area base address
pub const SVSM_XSAVE_AREA_BASE: VirtAddr = SVSM_SHADOW_STACK_ISST_DF_BASE.const_add(PAGE_SIZE);

/// Base Address for temporary mappings - used by page-table guards
pub const SVSM_PERCPU_TEMP_BASE: VirtAddr = SVSM_PERCPU_BASE.const_add(SIZE_LEVEL2);

// Below is space for 512 temporary 4k mappings and 511 temporary 2M mappings

/// Start and End for PAGE_SIZEed temporary mappings
pub const SVSM_PERCPU_TEMP_BASE_4K: VirtAddr = SVSM_PERCPU_TEMP_BASE;
pub const SVSM_PERCPU_TEMP_END_4K: VirtAddr = SVSM_PERCPU_TEMP_BASE_4K.const_add(SIZE_LEVEL1);

/// Start and End for PAGE_SIZEed temporary mappings
pub const SVSM_PERCPU_TEMP_BASE_2M: VirtAddr = SVSM_PERCPU_TEMP_BASE.const_add(SIZE_LEVEL1);
pub const SVSM_PERCPU_TEMP_END_2M: VirtAddr = SVSM_PERCPU_TEMP_BASE.const_add(SIZE_LEVEL2);

/// Task mappings level 3 index
pub const PGTABLE_LVL3_IDX_PERTASK: usize = 508;

/// Base address of task memory region
pub const SVSM_PERTASK_BASE: VirtAddr = virt_from_idx(PGTABLE_LVL3_IDX_PERTASK);

/// End address of task memory region
pub const SVSM_PERTASK_END: VirtAddr = SVSM_PERTASK_BASE.const_add(SIZE_LEVEL3);

/// Kernel stack for a task
pub const SVSM_PERTASK_STACK_BASE_OFFSET: usize = 0;

/// Kernel shadow stack for normal execution of a task
pub const SVSM_PERTASK_SHADOW_STACK_BASE_OFFSET: usize =
    SVSM_PERTASK_STACK_BASE_OFFSET + STACK_TOTAL_SIZE;

/// SSE context save area for a task
pub const SVSM_PERTASK_XSAVE_AREA_BASE: usize = SVSM_PERTASK_SHADOW_STACK_BASE_OFFSET + PAGE_SIZE;

/// Page table self-map level 3 index
pub const PGTABLE_LVL3_IDX_PTE_SELFMAP: usize = 493;

pub const SVSM_PTE_BASE: VirtAddr = virt_from_idx(PGTABLE_LVL3_IDX_PTE_SELFMAP);

//
// User-space mapping constants
//

/// Start of user memory address range
pub const USER_MEM_START: VirtAddr = VirtAddr::new(0);

/// End of user memory address range
pub const USER_MEM_END: VirtAddr = USER_MEM_START.const_add(256 * SIZE_LEVEL3);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locking::SpinLock;

    static KERNEL_MAPPING_TEST: ImmutAfterInitCell<FixedAddressMapping> =
        ImmutAfterInitCell::uninit();
    static INITIALIZED: SpinLock<bool> = SpinLock::new(false);

    #[test]
    #[cfg_attr(test_in_svsm, ignore = "Offline testing")]
    fn init_km_testing() {
        let mut initialized = INITIALIZED.lock();
        if *initialized {
            return;
        }
        let kernel_mapping = FixedAddressMappingRange::new(
            VirtAddr::new(0x1000),
            VirtAddr::new(0x2000),
            PhysAddr::new(0x3000),
        );
        let mapping = FixedAddressMapping {
            kernel_mapping,
            heap_mapping: None,
        };
        KERNEL_MAPPING_TEST.init_from_ref(&mapping).unwrap();
        *initialized = true;
    }

    #[test]
    #[cfg_attr(test_in_svsm, ignore = "Offline testing")]
    fn test_init_kernel_mapping_info() {
        init_km_testing();

        let km = &KERNEL_MAPPING_TEST;

        assert_eq!(km.kernel_mapping.virt_start, VirtAddr::new(0x1000));
        assert_eq!(km.kernel_mapping.virt_end, VirtAddr::new(0x2000));
        assert_eq!(km.kernel_mapping.phys_start, PhysAddr::new(0x3000));
    }

    #[test]
    #[cfg(target_os = "none")]
    #[cfg_attr(test_in_svsm, ignore = "Offline testing")]
    fn test_virt_to_phys() {
        let vaddr = VirtAddr::new(0x1500);
        let paddr = virt_to_phys(vaddr);

        assert_eq!(paddr, PhysAddr::new(0x4500));
    }

    #[test]
    #[cfg(not(target_os = "none"))]
    #[cfg_attr(test_in_svsm, ignore = "Offline testing")]
    fn test_virt_to_phys() {
        let vaddr = VirtAddr::new(0x1500);
        let paddr = virt_to_phys(vaddr);

        assert_eq!(paddr, PhysAddr::new(0x1500));
    }

    #[test]
    #[cfg(target_os = "none")]
    #[cfg_attr(test_in_svsm, ignore = "Offline testing")]
    fn test_phys_to_virt() {
        let paddr = PhysAddr::new(0x4500);
        let vaddr = phys_to_virt(paddr);

        assert_eq!(vaddr, VirtAddr::new(0x1500));
    }

    #[test]
    #[cfg(not(target_os = "none"))]
    #[cfg_attr(test_in_svsm, ignore = "Offline testing")]
    fn test_phys_to_virt() {
        let paddr = PhysAddr::new(0x4500);
        let vaddr = phys_to_virt(paddr);

        assert_eq!(vaddr, VirtAddr::new(0x4500));
    }
}

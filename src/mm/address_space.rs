// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#[cfg(test)]
use crate::address::Address;
use crate::address::{PhysAddr, VirtAddr};
use crate::utils::immut_after_init::ImmutAfterInitCell;

#[derive(Copy, Clone)]
#[allow(dead_code)]
struct KernelMapping {
    virt_start: VirtAddr,
    virt_end: VirtAddr,
    phys_start: PhysAddr,
}

static KERNEL_MAPPING: ImmutAfterInitCell<KernelMapping> = ImmutAfterInitCell::uninit();

pub fn init_kernel_mapping_info(vstart: VirtAddr, vend: VirtAddr, pstart: PhysAddr) {
    let km = KernelMapping {
        virt_start: vstart,
        virt_end: vend,
        phys_start: pstart,
    };
    KERNEL_MAPPING
        .init(&km)
        .expect("Already initialized kernel mapping info");
}

#[cfg(not(test))]
pub fn virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
    if vaddr < KERNEL_MAPPING.virt_start || vaddr >= KERNEL_MAPPING.virt_end {
        panic!("Invalid physical address {:#018x}", vaddr);
    }

    let offset: usize = vaddr - KERNEL_MAPPING.virt_start;

    KERNEL_MAPPING.phys_start + offset
}

#[cfg(not(test))]
pub fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
    let size: usize = KERNEL_MAPPING.virt_end - KERNEL_MAPPING.virt_start;
    if paddr < KERNEL_MAPPING.phys_start || paddr >= KERNEL_MAPPING.phys_start + size {
        panic!("Invalid physical address {:#018x}", paddr);
    }

    let offset: usize = paddr - KERNEL_MAPPING.phys_start;

    KERNEL_MAPPING.virt_start + offset
}

#[cfg(test)]
pub fn virt_to_phys(vaddr: VirtAddr) -> PhysAddr {
    PhysAddr::from(vaddr.bits())
}

#[cfg(test)]
pub fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
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
#[allow(clippy::identity_op)]
pub const SIZE_LEVEL1: usize = 1usize << ((9 * 1) + 12);
#[allow(clippy::erasing_op, clippy::identity_op)]
pub const SIZE_LEVEL0: usize = 1usize << ((9 * 0) + 12);

// Stack definitions
// The GDB stub requires a larger stack.
#[cfg(feature = "enable-gdb")]
pub const STACK_PAGES: usize = 16;
#[cfg(not(feature = "enable-gdb"))]
pub const STACK_PAGES: usize = 4;

pub const STACK_SIZE: usize = PAGE_SIZE * STACK_PAGES;
pub const STACK_GUARD_SIZE: usize = STACK_SIZE;
pub const STACK_TOTAL_SIZE: usize = STACK_SIZE + STACK_GUARD_SIZE;

const SIGN_BIT: usize = 47;

const fn sign_extend(addr: usize) -> usize {
    let mask = 1usize << SIGN_BIT;
    if (addr & mask) == mask {
        addr | 0xffff_0000_0000_0000
    } else {
        addr
    }
}

/// Level3 page-table index shared between all CPUs
pub const PGTABLE_LVL3_IDX_SHARED: usize = 511;

/// Base Address of shared memory region
pub const SVSM_SHARED_BASE: usize = sign_extend(PGTABLE_LVL3_IDX_SHARED << ((3 * 9) + 12));

/// Mapping range for shared stacks
pub const SVSM_SHARED_STACK_BASE: usize = SVSM_SHARED_BASE + (256 * SIZE_1G);
pub const SVSM_SHARED_STACK_END: usize = SVSM_SHARED_STACK_BASE + SIZE_1G;

/// PerCPU mappings level 3 index
pub const PGTABLE_LVL3_IDX_PERCPU: usize = 510;

/// Base Address of shared memory region
pub const SVSM_PERCPU_BASE: usize = sign_extend(PGTABLE_LVL3_IDX_PERCPU << ((3 * 9) + 12));

/// PerCPU CAA mappings
pub const SVSM_PERCPU_CAA_BASE: usize = SVSM_PERCPU_BASE + (2 * SIZE_LEVEL0);

/// PerCPU VMSA mappings
pub const SVSM_PERCPU_VMSA_BASE: usize = SVSM_PERCPU_BASE + (4 * SIZE_LEVEL0);

/// Region for PerCPU Stacks
pub const SVSM_PERCPU_STACKS_BASE: usize = SVSM_PERCPU_BASE + SIZE_LEVEL1;

/// Stack address of the per-cpu init task
pub const SVSM_STACKS_INIT_TASK: usize = SVSM_PERCPU_STACKS_BASE;

///  IST Stacks base address
pub const SVSM_STACKS_IST_BASE: usize = SVSM_STACKS_INIT_TASK + STACK_TOTAL_SIZE;

/// DoubleFault IST stack base address
pub const SVSM_STACK_IST_DF_BASE: usize = SVSM_STACKS_IST_BASE;

/// Base Address for temporary mappings - used by page-table guards
pub const SVSM_PERCPU_TEMP_BASE: usize = SVSM_PERCPU_BASE + SIZE_LEVEL2;

// Below is space for 512 temporary 4k mappings and 511 temporary 2M mappings

/// Start and End for PAGE_SIZEed temporary mappings
pub const SVSM_PERCPU_TEMP_BASE_4K: usize = SVSM_PERCPU_TEMP_BASE;
pub const SVSM_PERCPU_TEMP_END_4K: usize = SVSM_PERCPU_TEMP_BASE_4K + SIZE_LEVEL1;

/// Start and End for PAGE_SIZEed temporary mappings
pub const SVSM_PERCPU_TEMP_BASE_2M: usize = SVSM_PERCPU_TEMP_BASE + SIZE_LEVEL1;
pub const SVSM_PERCPU_TEMP_END_2M: usize = SVSM_PERCPU_TEMP_BASE + SIZE_LEVEL2;

/// Per-task memory map
/// Use the region from 0xfffffe0000000000 - 0xffffff0000000000 for tasks
pub const PGTABLE_LVL3_IDX_PERTASK: usize = 508;
/// Layout of the per-task memory space is:
///
/// +------------------+------------------+-------------------------------------+
/// | Start            | End              | Size | Description                  |
/// +------------------+------------------+------+------------------------------+
/// | fffffeffffff0000 | ffffff0000000000 | 64K  | Task stack                   |
/// +------------------+------------------+------+------------------------------+
/// | fffffe0000000000 | fffffe0004000000 | 64M  | Dynamic memory allocation    |
/// +------------------+------------------+------+------------------------------+
pub const SVSM_PERTASK_BASE: usize = sign_extend(PGTABLE_LVL3_IDX_PERTASK << ((3 * 9) + 12));

/// Virtual addresses for dynamic memory allocation
pub const SVSM_PERTASK_DYNAMIC_MEMORY: usize = SVSM_PERTASK_BASE;

/// Task stack
pub const SVSM_PERTASK_STACK_BASE: usize = SVSM_PERTASK_BASE + 0xffffff0000;
pub const SVSM_PERTASK_STACK_TOP: usize = SVSM_PERTASK_STACK_BASE + 0x10000;

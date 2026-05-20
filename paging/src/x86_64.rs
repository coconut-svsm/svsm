// SPDX-License-Identifier: MIT OR Apache-2.0

//! x86_64-specific page table entry flags.

use bitflags::bitflags;

use crate::traits::GenericPageTableFlags;

bitflags! {
    /// x86_64 page table entry flags.
    ///
    /// Bit positions follow the Intel/AMD architecture manuals for
    /// 4-level (PML4) and 5-level (PML5) paging modes.
    #[derive(Copy, Clone, Debug, Default)]
    pub struct PTEntryFlags: usize {
        const PRESENT       = 1 << 0;
        const WRITABLE      = 1 << 1;
        const USER          = 1 << 2;
        const WRITE_THROUGH = 1 << 3;
        const NO_CACHE      = 1 << 4;
        const ACCESSED      = 1 << 5;
        const DIRTY         = 1 << 6;
        const HUGE          = 1 << 7;
        const GLOBAL        = 1 << 8;
        const NX            = 1 << 63;
    }
}

impl GenericPageTableFlags for PTEntryFlags {
    const PRESENT: Self = Self::PRESENT;
    const USER: Self = Self::USER;
    const HUGE: Self = Self::HUGE;

    /// present, writable, user-accessible, and accessed.
    fn parent_flags() -> Self {
        Self::PRESENT | Self::WRITABLE | Self::USER | Self::ACCESSED
    }

    /// page table is not accessible by user mode, and is not executable.
    fn self_map_table_flags() -> Self {
        Self::PRESENT | Self::WRITABLE | Self::ACCESSED | Self::DIRTY | Self::NX
    }
}

impl PTEntryFlags {
    /// Check if the page table entry is writable.
    pub fn writable(&self) -> bool {
        self.contains(Self::WRITABLE)
    }

    /// Check if the page table entry is user-accessible.
    pub fn user(&self) -> bool {
        self.contains(Self::USER)
    }

    /// Check if the page table entry is NX (no-execute).
    pub fn nx(&self) -> bool {
        self.contains(Self::NX)
    }

    /// Check if the page table entry is global.
    pub fn global(&self) -> bool {
        self.contains(Self::GLOBAL)
    }

    pub fn exec() -> Self {
        Self::PRESENT | Self::GLOBAL | Self::ACCESSED
    }

    pub fn data() -> Self {
        Self::PRESENT | Self::GLOBAL | Self::WRITABLE | Self::NX | Self::ACCESSED | Self::DIRTY
    }

    pub fn data_ro() -> Self {
        Self::PRESENT | Self::GLOBAL | Self::NX | Self::ACCESSED
    }

    pub fn task_exec() -> Self {
        Self::PRESENT | Self::ACCESSED
    }

    pub fn task_data() -> Self {
        Self::PRESENT | Self::WRITABLE | Self::NX | Self::ACCESSED | Self::DIRTY
    }

    pub fn task_data_ro() -> Self {
        Self::PRESENT | Self::NX | Self::ACCESSED
    }
}

/// x86_64 4-level paging (PML4).
pub type Pml4Level = crate::traits::PagingLevel3;

/// x86-64 PDPT-rooted 3-level page table sub-tree.
pub type PdptLevel = crate::traits::PagingLevel2;

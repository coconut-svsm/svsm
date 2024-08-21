// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::control_regs::write_cr3;
use crate::cpu::flush_tlb_global_sync;
use crate::error::SvsmError;
use crate::mm::PageBox;
use crate::mm::{phys_to_virt, virt_to_phys, PGTABLE_LVL3_IDX_SHARED};
use crate::platform::SvsmPlatform;
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::immut_after_init::{ImmutAfterInitCell, ImmutAfterInitResult};
use crate::utils::MemoryRegion;
use bitflags::bitflags;
use core::ops::{Deref, DerefMut, Index, IndexMut};
use core::ptr::NonNull;
use core::{cmp, ptr};

extern crate alloc;
use alloc::boxed::Box;

/// Number of entries in a page table (4KB/8B).
const ENTRY_COUNT: usize = 512;

/// Mask for private page table entry.
static PRIVATE_PTE_MASK: ImmutAfterInitCell<usize> = ImmutAfterInitCell::new(0);

/// Mask for shared page table entry.
static SHARED_PTE_MASK: ImmutAfterInitCell<usize> = ImmutAfterInitCell::new(0);

/// Maximum physical address supported by the system.
static MAX_PHYS_ADDR: ImmutAfterInitCell<u64> = ImmutAfterInitCell::uninit();

/// Physical address for the Launch VMSA (Virtual Machine Saving Area).
pub const LAUNCH_VMSA_ADDR: PhysAddr = PhysAddr::new(0xFFFFFFFFF000);

/// Feature mask for page table entry flags.
static FEATURE_MASK: ImmutAfterInitCell<PTEntryFlags> =
    ImmutAfterInitCell::new(PTEntryFlags::empty());

/// Re-initializes early paging settings.
pub fn paging_init_early(platform: &dyn SvsmPlatform) -> ImmutAfterInitResult<()> {
    init_encrypt_mask(platform)?;

    let mut feature_mask = PTEntryFlags::all();
    feature_mask.remove(PTEntryFlags::NX);
    feature_mask.remove(PTEntryFlags::GLOBAL);
    FEATURE_MASK.reinit(&feature_mask)
}

/// Initializes paging settings.
pub fn paging_init(platform: &dyn SvsmPlatform) -> ImmutAfterInitResult<()> {
    init_encrypt_mask(platform)?;

    let feature_mask = PTEntryFlags::all();
    FEATURE_MASK.reinit(&feature_mask)
}

/// Initializes the encrypt mask.
fn init_encrypt_mask(platform: &dyn SvsmPlatform) -> ImmutAfterInitResult<()> {
    let masks = platform.get_page_encryption_masks();

    PRIVATE_PTE_MASK.reinit(&masks.private_pte_mask)?;
    SHARED_PTE_MASK.reinit(&masks.shared_pte_mask)?;

    let guest_phys_addr_size = (masks.phys_addr_sizes >> 16) & 0xff;
    let host_phys_addr_size = masks.phys_addr_sizes & 0xff;
    let phys_addr_size = if guest_phys_addr_size == 0 {
        // When [GuestPhysAddrSize] is zero, refer to the PhysAddrSize field
        // for the maximum guest physical address size.
        // - APM3, E.4.7 Function 8000_0008h - Processor Capacity Parameters and Extended Feature Identification
        host_phys_addr_size
    } else {
        guest_phys_addr_size
    };

    // If the C-bit is a physical address bit however, the guest physical
    // address space is effectively reduced by 1 bit.
    // - APM2, 15.34.6 Page Table Support
    let effective_phys_addr_size = cmp::min(masks.addr_mask_width, phys_addr_size);

    let max_addr = 1 << effective_phys_addr_size;
    MAX_PHYS_ADDR.reinit(&max_addr)
}

/// Returns the private encrypt mask value.
fn private_pte_mask() -> usize {
    *PRIVATE_PTE_MASK
}

/// Returns the shared encrypt mask value.
fn shared_pte_mask() -> usize {
    *SHARED_PTE_MASK
}

/// Returns the exclusive end of the physical address space.
pub fn max_phys_addr() -> PhysAddr {
    PhysAddr::from(*MAX_PHYS_ADDR)
}

/// Returns the supported flags considering the feature mask.
fn supported_flags(flags: PTEntryFlags) -> PTEntryFlags {
    flags & *FEATURE_MASK
}

/// Set address as shared via mask.
fn make_shared_address(paddr: PhysAddr) -> PhysAddr {
    PhysAddr::from(paddr.bits() & !private_pte_mask() | shared_pte_mask())
}

/// Set address as private via mask.
fn make_private_address(paddr: PhysAddr) -> PhysAddr {
    PhysAddr::from(paddr.bits() & !shared_pte_mask() | private_pte_mask())
}

fn strip_confidentiality_bits(paddr: PhysAddr) -> PhysAddr {
    PhysAddr::from(paddr.bits() & !(shared_pte_mask() | private_pte_mask()))
}

bitflags! {
    #[derive(Copy, Clone, Debug, Default)]
    pub struct PTEntryFlags: u64 {
        const PRESENT       = 1 << 0;
        const WRITABLE      = 1 << 1;
        const USER      = 1 << 2;
        const ACCESSED      = 1 << 5;
        const DIRTY     = 1 << 6;
        const HUGE      = 1 << 7;
        const GLOBAL        = 1 << 8;
        const NX        = 1 << 63;
    }
}

impl PTEntryFlags {
    pub fn exec() -> Self {
        Self::PRESENT | Self::GLOBAL | Self::ACCESSED | Self::DIRTY
    }

    pub fn data() -> Self {
        Self::PRESENT | Self::GLOBAL | Self::WRITABLE | Self::NX | Self::ACCESSED | Self::DIRTY
    }

    pub fn data_ro() -> Self {
        Self::PRESENT | Self::GLOBAL | Self::NX | Self::ACCESSED | Self::DIRTY
    }

    pub fn task_exec() -> Self {
        Self::PRESENT | Self::ACCESSED | Self::DIRTY
    }

    pub fn task_data() -> Self {
        Self::PRESENT | Self::WRITABLE | Self::NX | Self::ACCESSED | Self::DIRTY
    }

    pub fn task_data_ro() -> Self {
        Self::PRESENT | Self::NX | Self::ACCESSED | Self::DIRTY
    }
}

/// Represents a page table entry.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct PTEntry(PhysAddr);

impl PTEntry {
    /// Check if the page table entry is clear (null).
    pub fn is_clear(&self) -> bool {
        self.0.is_null()
    }

    /// Clear the page table entry.
    pub fn clear(&mut self) {
        self.0 = PhysAddr::null();
    }

    /// Check if the page table entry is present.
    pub fn present(&self) -> bool {
        self.flags().contains(PTEntryFlags::PRESENT)
    }

    /// Get the raw bits (`u64`) of the page table entry.
    pub fn raw(&self) -> u64 {
        self.0.bits() as u64
    }

    /// Get the flags of the page table entry.
    pub fn flags(&self) -> PTEntryFlags {
        PTEntryFlags::from_bits_truncate(self.0.bits() as u64)
    }

    /// Set the page table entry with the specified address and flags.
    pub fn set(&mut self, addr: PhysAddr, flags: PTEntryFlags) {
        let addr = addr.bits() as u64;
        assert_eq!(addr & !0x000f_ffff_ffff_f000, 0);
        self.0 = PhysAddr::from(addr | supported_flags(flags).bits());
    }

    /// Get the address from the page table entry, excluding the C bit.
    pub fn address(&self) -> PhysAddr {
        let addr = PhysAddr::from(self.0.bits() & 0x000f_ffff_ffff_f000);
        strip_confidentiality_bits(addr)
    }
}

/// A pagetable page with multiple entries.
#[repr(C)]
#[derive(Debug)]
pub struct PTPage {
    entries: [PTEntry; ENTRY_COUNT],
}

impl PTPage {
    /// Allocates a zeroed pagetable page and returns a mutable reference to
    /// it, plus its physical address.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError`] if the page cannot be allocated.
    fn alloc() -> Result<(&'static mut Self, PhysAddr), SvsmError> {
        let page = PageBox::try_new(PTPage::default())?;
        let paddr = virt_to_phys(page.vaddr());
        Ok((PageBox::leak(page), paddr))
    }

    /// Frees a pagetable page.
    ///
    /// # Safety
    ///
    /// The given reference must correspond to a valid previously allocated
    /// page table page.
    unsafe fn free(page: &'static Self) {
        let _ = PageBox::from_raw(NonNull::from(page));
    }

    /// Converts a pagetable entry to a mutable reference to a [`PTPage`],
    /// if the entry is present and not huge.
    fn from_entry(entry: PTEntry) -> Option<&'static mut Self> {
        let flags = entry.flags();
        if !flags.contains(PTEntryFlags::PRESENT) || flags.contains(PTEntryFlags::HUGE) {
            return None;
        }

        let address = phys_to_virt(entry.address());
        Some(unsafe { &mut *address.as_mut_ptr::<PTPage>() })
    }
}

impl Default for PTPage {
    fn default() -> Self {
        let entries = [PTEntry::default(); ENTRY_COUNT];
        PTPage { entries }
    }
}

/// Can be used to access page table entries by index.
impl Index<usize> for PTPage {
    type Output = PTEntry;

    fn index(&self, index: usize) -> &PTEntry {
        &self.entries[index]
    }
}

/// Can be used to modify page table entries by index.
impl IndexMut<usize> for PTPage {
    fn index_mut(&mut self, index: usize) -> &mut PTEntry {
        &mut self.entries[index]
    }
}

/// Mapping levels of page table entries.
#[derive(Debug)]
pub enum Mapping<'a> {
    Level3(&'a mut PTEntry),
    Level2(&'a mut PTEntry),
    Level1(&'a mut PTEntry),
    Level0(&'a mut PTEntry),
}

/// Page table structure containing a root page with multiple entries.
#[repr(C)]
#[derive(Default, Debug)]
pub struct PageTable {
    root: PTPage,
}

impl PageTable {
    /// Load the current page table into the CR3 register.
    pub fn load(&self) {
        write_cr3(self.cr3_value());
    }

    /// Get the CR3 register value for the current page table.
    pub fn cr3_value(&self) -> PhysAddr {
        let pgtable = VirtAddr::from(self as *const Self);
        virt_to_phys(pgtable)
    }

    /// Clone the shared part of the page table; excluding the private
    /// parts.
    ///
    /// # Errors
    /// Returns [`SvsmError`] if the page cannot be allocated.
    pub fn clone_shared(&self) -> Result<PageBox<PageTable>, SvsmError> {
        let mut pgtable = PageBox::try_new(PageTable::default())?;
        pgtable.root.entries[PGTABLE_LVL3_IDX_SHARED] = self.root.entries[PGTABLE_LVL3_IDX_SHARED];
        Ok(pgtable)
    }

    /// Copy an entry `entry` from another [`PageTable`].
    pub fn copy_entry(&mut self, other: &Self, entry: usize) {
        self.root.entries[entry] = other.root.entries[entry];
    }

    /// Computes the index within a page table at the given level for a
    /// virtual address `vaddr`.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address to compute the index for.
    ///
    /// # Returns
    /// The index within the page table.
    pub fn index<const L: usize>(vaddr: VirtAddr) -> usize {
        vaddr.to_pgtbl_idx::<L>()
        //vaddr.bits() >> (12 + L * 9) & 0x1ff
    }

    /// Walks a page table at level 0 to find a mapping.
    ///
    /// # Parameters
    /// - `page`: A mutable reference to the root page table.
    /// - `vaddr`: The virtual address to find a mapping for.
    ///
    /// # Returns
    /// A `Mapping` representing the found mapping.
    fn walk_addr_lvl0(page: &mut PTPage, vaddr: VirtAddr) -> Mapping<'_> {
        let idx = Self::index::<0>(vaddr);
        Mapping::Level0(&mut page[idx])
    }

    /// Walks a page table at level 1 to find a mapping.
    ///
    /// # Parameters
    /// - `page`: A mutable reference to the root page table.
    /// - `vaddr`: The virtual address to find a mapping for.
    ///
    /// # Returns
    /// A `Mapping` representing the found mapping.
    fn walk_addr_lvl1(page: &mut PTPage, vaddr: VirtAddr) -> Mapping<'_> {
        let idx = Self::index::<1>(vaddr);
        let entry = page[idx];
        match PTPage::from_entry(entry) {
            Some(page) => Self::walk_addr_lvl0(page, vaddr),
            None => Mapping::Level1(&mut page[idx]),
        }
    }

    /// Walks a page table at level 2 to find a mapping.
    ///
    /// # Parameters
    /// - `page`: A mutable reference to the root page table.
    /// - `vaddr`: The virtual address to find a mapping for.
    ///
    /// # Returns
    /// A `Mapping` representing the found mapping.
    fn walk_addr_lvl2(page: &mut PTPage, vaddr: VirtAddr) -> Mapping<'_> {
        let idx = Self::index::<2>(vaddr);
        let entry = page[idx];
        match PTPage::from_entry(entry) {
            Some(page) => Self::walk_addr_lvl1(page, vaddr),
            None => Mapping::Level2(&mut page[idx]),
        }
    }

    /// Walks the page table to find a mapping for a given virtual address.
    ///
    /// # Parameters
    /// - `page`: A mutable reference to the root page table.
    /// - `vaddr`: The virtual address to find a mapping for.
    ///
    /// # Returns
    /// A `Mapping` representing the found mapping.
    fn walk_addr_lvl3(page: &mut PTPage, vaddr: VirtAddr) -> Mapping<'_> {
        let idx = Self::index::<3>(vaddr);
        let entry = page[idx];
        match PTPage::from_entry(entry) {
            Some(page) => Self::walk_addr_lvl2(page, vaddr),
            None => Mapping::Level3(&mut page[idx]),
        }
    }

    /// Walk the virtual address and return the corresponding mapping.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address to find a mapping for.
    ///
    /// # Returns
    /// A `Mapping` representing the found mapping.
    fn walk_addr(&mut self, vaddr: VirtAddr) -> Mapping<'_> {
        Self::walk_addr_lvl3(&mut self.root, vaddr)
    }

    fn alloc_pte_lvl3(entry: &mut PTEntry, vaddr: VirtAddr, size: PageSize) -> Mapping<'_> {
        let flags = entry.flags();

        if flags.contains(PTEntryFlags::PRESENT) {
            return Mapping::Level3(entry);
        }

        let Ok((page, paddr)) = PTPage::alloc() else {
            return Mapping::Level3(entry);
        };

        let flags = PTEntryFlags::PRESENT
            | PTEntryFlags::WRITABLE
            | PTEntryFlags::USER
            | PTEntryFlags::ACCESSED;
        entry.set(paddr, flags);

        let idx = Self::index::<2>(vaddr);
        Self::alloc_pte_lvl2(&mut page[idx], vaddr, size)
    }

    fn alloc_pte_lvl2(entry: &mut PTEntry, vaddr: VirtAddr, size: PageSize) -> Mapping<'_> {
        let flags = entry.flags();

        if flags.contains(PTEntryFlags::PRESENT) {
            return Mapping::Level2(entry);
        }

        let Ok((page, paddr)) = PTPage::alloc() else {
            return Mapping::Level2(entry);
        };

        let flags = PTEntryFlags::PRESENT
            | PTEntryFlags::WRITABLE
            | PTEntryFlags::USER
            | PTEntryFlags::ACCESSED;
        entry.set(paddr, flags);

        let idx = Self::index::<1>(vaddr);
        Self::alloc_pte_lvl1(&mut page[idx], vaddr, size)
    }

    fn alloc_pte_lvl1(entry: &mut PTEntry, vaddr: VirtAddr, size: PageSize) -> Mapping<'_> {
        let flags = entry.flags();

        if size == PageSize::Huge || flags.contains(PTEntryFlags::PRESENT) {
            return Mapping::Level1(entry);
        }

        let Ok((page, paddr)) = PTPage::alloc() else {
            return Mapping::Level1(entry);
        };

        let flags = PTEntryFlags::PRESENT
            | PTEntryFlags::WRITABLE
            | PTEntryFlags::USER
            | PTEntryFlags::ACCESSED;
        entry.set(paddr, flags);

        let idx = Self::index::<0>(vaddr);
        Mapping::Level0(&mut page[idx])
    }

    /// Allocates a 4KB page table entry for a given virtual address.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address for which to allocate the PTE.
    ///
    /// # Returns
    /// A `Mapping` representing the allocated or existing PTE for the address.
    fn alloc_pte_4k(&mut self, vaddr: VirtAddr) -> Mapping<'_> {
        let m = self.walk_addr(vaddr);

        match m {
            Mapping::Level0(entry) => Mapping::Level0(entry),
            Mapping::Level1(entry) => Self::alloc_pte_lvl1(entry, vaddr, PageSize::Regular),
            Mapping::Level2(entry) => Self::alloc_pte_lvl2(entry, vaddr, PageSize::Regular),
            Mapping::Level3(entry) => Self::alloc_pte_lvl3(entry, vaddr, PageSize::Regular),
        }
    }

    /// Allocates a 2MB page table entry for a given virtual address.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address for which to allocate the PTE.
    ///
    /// # Returns
    /// A `Mapping` representing the allocated or existing PTE for the address.
    fn alloc_pte_2m(&mut self, vaddr: VirtAddr) -> Mapping<'_> {
        let m = self.walk_addr(vaddr);

        match m {
            Mapping::Level0(entry) => Mapping::Level0(entry),
            Mapping::Level1(entry) => Mapping::Level1(entry),
            Mapping::Level2(entry) => Self::alloc_pte_lvl2(entry, vaddr, PageSize::Huge),
            Mapping::Level3(entry) => Self::alloc_pte_lvl3(entry, vaddr, PageSize::Huge),
        }
    }

    /// Splits a 2MB page into 4KB pages.
    ///
    /// # Parameters
    /// - `entry`: The 2M page table entry to split.
    ///
    /// # Returns
    /// A result indicating success or an error [`SvsmError`] in failure.
    fn do_split_4k(entry: &mut PTEntry) -> Result<(), SvsmError> {
        let (page, paddr) = PTPage::alloc()?;
        let mut flags = entry.flags();

        assert!(flags.contains(PTEntryFlags::HUGE));

        let addr_2m = PhysAddr::from(entry.address().bits() & 0x000f_ffff_fff0_0000);

        flags.remove(PTEntryFlags::HUGE);

        // Prepare PTE leaf page
        for (i, e) in page.entries.iter_mut().enumerate() {
            let addr_4k = addr_2m + (i * PAGE_SIZE);
            e.clear();
            e.set(make_private_address(addr_4k), flags);
        }

        entry.set(make_private_address(paddr), flags);

        flush_tlb_global_sync();

        Ok(())
    }

    /// Splits a page into 4KB pages if it is part of a larger mapping.
    ///
    /// # Parameters
    /// - `mapping`: The mapping to split.
    ///
    /// # Returns
    /// A result indicating success or an error [`SvsmError`].
    fn split_4k(mapping: Mapping<'_>) -> Result<(), SvsmError> {
        match mapping {
            Mapping::Level0(_entry) => Ok(()),
            Mapping::Level1(entry) => Self::do_split_4k(entry),
            Mapping::Level2(_entry) => Err(SvsmError::Mem),
            Mapping::Level3(_entry) => Err(SvsmError::Mem),
        }
    }

    fn make_pte_shared(entry: &mut PTEntry) {
        let flags = entry.flags();
        let addr = entry.address();

        // entry.address() returned with c-bit clear already
        entry.set(make_shared_address(addr), flags);
    }

    fn make_pte_private(entry: &mut PTEntry) {
        let flags = entry.flags();
        let addr = entry.address();

        // entry.address() returned with c-bit clear already
        entry.set(make_private_address(addr), flags);
    }

    /// Sets the shared state for a 4KB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address of the page.
    ///
    /// # Returns
    /// A result indicating success or an error [`SvsmError`] if the
    /// operation fails.
    pub fn set_shared_4k(&mut self, vaddr: VirtAddr) -> Result<(), SvsmError> {
        let mapping = self.walk_addr(vaddr);
        Self::split_4k(mapping)?;

        if let Mapping::Level0(entry) = self.walk_addr(vaddr) {
            Self::make_pte_shared(entry);
            Ok(())
        } else {
            Err(SvsmError::Mem)
        }
    }

    /// Sets the encryption state for a 4KB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address of the page.
    ///
    /// # Returns
    /// A result indicating success or an error [`SvsmError`].
    pub fn set_encrypted_4k(&mut self, vaddr: VirtAddr) -> Result<(), SvsmError> {
        let mapping = self.walk_addr(vaddr);
        Self::split_4k(mapping)?;

        if let Mapping::Level0(entry) = self.walk_addr(vaddr) {
            Self::make_pte_private(entry);
            Ok(())
        } else {
            Err(SvsmError::Mem)
        }
    }

    /// Gets the physical address for a mapped `vaddr` or `None` if
    /// no such mapping exists.
    pub fn check_mapping(&mut self, vaddr: VirtAddr) -> Option<PhysAddr> {
        match self.walk_addr(vaddr) {
            Mapping::Level0(entry) => Some(entry.address()),
            Mapping::Level1(entry) => Some(entry.address()),
            _ => None,
        }
    }

    /// Maps a 2MB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address to map.
    /// - `paddr`: The physical address to map to.
    /// - `flags`: The flags to apply to the mapping.
    ///
    /// # Returns
    /// A result indicating success or failure ([`SvsmError`]).
    ///
    /// # Panics
    /// Panics if either `vaddr` or `paddr` is not aligned to a 2MB boundary.
    pub fn map_2m(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PTEntryFlags,
    ) -> Result<(), SvsmError> {
        assert!(vaddr.is_aligned(PAGE_SIZE_2M));
        assert!(paddr.is_aligned(PAGE_SIZE_2M));

        let mapping = self.alloc_pte_2m(vaddr);

        if let Mapping::Level1(entry) = mapping {
            entry.set(make_private_address(paddr), flags | PTEntryFlags::HUGE);
            Ok(())
        } else {
            Err(SvsmError::Mem)
        }
    }

    /// Unmaps a 2MB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address of the mapping to unmap.
    ///
    /// # Panics
    /// Panics if `vaddr` is not aligned to a 2MB boundary.
    pub fn unmap_2m(&mut self, vaddr: VirtAddr) {
        assert!(vaddr.is_aligned(PAGE_SIZE_2M));

        let mapping = self.walk_addr(vaddr);

        match mapping {
            Mapping::Level0(_) => unreachable!(),
            Mapping::Level1(entry) => entry.clear(),
            Mapping::Level2(entry) => assert!(!entry.present()),
            Mapping::Level3(entry) => assert!(!entry.present()),
        }
    }

    /// Maps a 4KB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address to map.
    /// - `paddr`: The physical address to map to.
    /// - `flags`: The flags to apply to the mapping.
    ///
    /// # Returns
    /// A result indicating success or failure ([`SvsmError`]).
    pub fn map_4k(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PTEntryFlags,
    ) -> Result<(), SvsmError> {
        let mapping = self.alloc_pte_4k(vaddr);

        if let Mapping::Level0(entry) = mapping {
            entry.set(make_private_address(paddr), flags);
            Ok(())
        } else {
            Err(SvsmError::Mem)
        }
    }

    /// Unmaps a 4KB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address of the mapping to unmap.
    pub fn unmap_4k(&mut self, vaddr: VirtAddr) {
        let mapping = self.walk_addr(vaddr);

        match mapping {
            Mapping::Level0(entry) => entry.clear(),
            Mapping::Level1(entry) => assert!(!entry.present()),
            Mapping::Level2(entry) => assert!(!entry.present()),
            Mapping::Level3(entry) => assert!(!entry.present()),
        }
    }

    /// Retrieves the physical address of a mapping.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address to query.
    ///
    /// # Returns
    /// The physical address of the mapping if present; otherwise, an error
    /// ([`SvsmError`]).
    pub fn phys_addr(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, SvsmError> {
        let mapping = self.walk_addr(vaddr);

        match mapping {
            Mapping::Level0(entry) => {
                let offset = vaddr.page_offset();
                if !entry.flags().contains(PTEntryFlags::PRESENT) {
                    return Err(SvsmError::Mem);
                }
                Ok(entry.address() + offset)
            }
            Mapping::Level1(entry) => {
                let offset = vaddr.bits() & (PAGE_SIZE_2M - 1);
                if !entry.flags().contains(PTEntryFlags::PRESENT)
                    || !entry.flags().contains(PTEntryFlags::HUGE)
                {
                    return Err(SvsmError::Mem);
                }

                Ok(entry.address() + offset)
            }
            Mapping::Level2(_entry) => Err(SvsmError::Mem),
            Mapping::Level3(_entry) => Err(SvsmError::Mem),
        }
    }

    /// Maps a region of memory using 4KB pages.
    ///
    /// # Parameters
    /// - `vregion`: The virtual memory region to map.
    /// - `phys`: The starting physical address to map to.
    /// - `flags`: The flags to apply to the mapping.
    ///
    /// # Returns
    /// A result indicating success or failure ([`SvsmError`]).
    pub fn map_region_4k(
        &mut self,
        vregion: MemoryRegion<VirtAddr>,
        phys: PhysAddr,
        flags: PTEntryFlags,
    ) -> Result<(), SvsmError> {
        for addr in vregion.iter_pages(PageSize::Regular) {
            let offset = addr - vregion.start();
            self.map_4k(addr, phys + offset, flags)?;
        }
        Ok(())
    }

    /// Unmaps a region of memory using 4KB pages.
    ///
    /// # Parameters
    /// - `vregion`: The virtual memory region to unmap.
    pub fn unmap_region_4k(&mut self, vregion: MemoryRegion<VirtAddr>) {
        for addr in vregion.iter_pages(PageSize::Regular) {
            self.unmap_4k(addr);
        }
    }

    /// Maps a region of memory using 2MB pages.
    ///
    /// # Parameters
    /// - `vregion`: The virtual memory region to map.
    /// - `phys`: The starting physical address to map to.
    /// - `flags`: The flags to apply to the mapping.
    ///
    /// # Returns
    /// A result indicating success or failure ([`SvsmError`]).
    pub fn map_region_2m(
        &mut self,
        vregion: MemoryRegion<VirtAddr>,
        phys: PhysAddr,
        flags: PTEntryFlags,
    ) -> Result<(), SvsmError> {
        for addr in vregion.iter_pages(PageSize::Huge) {
            let offset = addr - vregion.start();
            self.map_2m(addr, phys + offset, flags)?;
        }
        Ok(())
    }

    /// Unmaps a region `vregion` of 2MB pages. The region must be
    /// 2MB-aligned and correspond to a set of huge mappings.
    pub fn unmap_region_2m(&mut self, vregion: MemoryRegion<VirtAddr>) {
        for addr in vregion.iter_pages(PageSize::Huge) {
            self.unmap_2m(addr);
        }
    }

    /// Maps a memory region to physical memory with specified flags.
    ///
    /// # Parameters
    /// - `region`: The virtual memory region to map.
    /// - `phys`: The starting physical address to map to.
    /// - `flags`: The flags to apply to the page table entries.
    ///
    /// # Returns
    /// A result indicating success (`Ok`) or failure (`Err`).
    pub fn map_region(
        &mut self,
        region: MemoryRegion<VirtAddr>,
        phys: PhysAddr,
        flags: PTEntryFlags,
    ) -> Result<(), SvsmError> {
        let mut vaddr = region.start();
        let end = region.end();
        let mut paddr = phys;

        while vaddr < end {
            if vaddr.is_aligned(PAGE_SIZE_2M)
                && paddr.is_aligned(PAGE_SIZE_2M)
                && vaddr + PAGE_SIZE_2M <= end
                && self.map_2m(vaddr, paddr, flags).is_ok()
            {
                vaddr = vaddr + PAGE_SIZE_2M;
                paddr = paddr + PAGE_SIZE_2M;
                continue;
            }

            self.map_4k(vaddr, paddr, flags)?;
            vaddr = vaddr + PAGE_SIZE;
            paddr = paddr + PAGE_SIZE;
        }

        Ok(())
    }

    /// Unmaps the virtual memory region `vregion`.
    pub fn unmap_region(&mut self, vregion: MemoryRegion<VirtAddr>) {
        let mut vaddr = vregion.start();
        let end = vregion.end();

        while vaddr < end {
            let mapping = self.walk_addr(vaddr);

            match mapping {
                Mapping::Level0(entry) => {
                    entry.clear();
                    vaddr = vaddr + PAGE_SIZE;
                }
                Mapping::Level1(entry) => {
                    entry.clear();
                    vaddr = vaddr + PAGE_SIZE_2M;
                }
                _ => {
                    log::error!("Can't unmap - address not mapped {:#x}", vaddr);
                }
            }
        }
    }

    /// Populates this paghe table with the contents of the given subtree
    /// in `part`.
    pub fn populate_pgtbl_part(&mut self, part: &PageTablePart) {
        if let Some(paddr) = part.address() {
            let idx = part.index();
            let flags = PTEntryFlags::PRESENT
                | PTEntryFlags::WRITABLE
                | PTEntryFlags::USER
                | PTEntryFlags::ACCESSED;
            let entry = &mut self.root[idx];
            // The C bit is not required here because all page table fetches are
            // made as C=1.
            entry.set(paddr, flags);
        }
    }
}

/// A reference wrapper for a [`PageTable`].
#[derive(Debug)]
pub enum PageTableRef {
    Owned(PageBox<PageTable>),
    Shared(*mut PageTable),
}

impl PageTableRef {
    /// Creates a new shared [`PageTableRef`] from a raw pointer.
    #[inline]
    pub const fn shared(ptr: *mut PageTable) -> Self {
        Self::Shared(ptr)
    }

    /// Allocates an empty owned [`PageTableRef`].
    pub fn alloc() -> Result<Self, SvsmError> {
        let table = PageBox::try_new(PageTable::default())?;
        Ok(Self::Owned(table))
    }

    /// Creates a new shared and unset (i.e. NULL) [`PageTableRef`].
    #[inline]
    pub const fn unset() -> Self {
        Self::shared(ptr::null_mut())
    }

    /// Checks if the [`PageTableRef`] is set, i.e. not NULL.
    #[inline]
    fn is_set(&self) -> bool {
        match self {
            Self::Owned(..) => true,
            Self::Shared(p) => !p.is_null(),
        }
    }

    pub fn leak(self) -> &'static mut PageTable {
        match self {
            PageTableRef::Owned(p) => PageBox::leak(p),
            PageTableRef::Shared(p) => unsafe { &mut *p },
        }
    }
}

impl Deref for PageTableRef {
    type Target = PageTable;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(p) => p,
            // SAFETY: nobody else has access to `ptr` so it cannot be aliased.
            Self::Shared(p) => unsafe { p.as_ref().unwrap() },
        }
    }
}

impl DerefMut for PageTableRef {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Owned(p) => p,
            // SAFETY: nobody else has access to `ptr` so it cannot be aliased.
            Self::Shared(p) => unsafe { p.as_mut().unwrap() },
        }
    }
}

/// SAFETY: `PageTableRef` is more or less equivalent to a mutable reference to
///         a PageTable and so if `&mut PageTable` implements `Send` so does
///         `PageTableRef`.
unsafe impl Send for PageTableRef where &'static mut PageTable: Send {}

/// Represents a sub-tree of a page-table which can be mapped at a top-level index
#[derive(Default, Debug)]
struct RawPageTablePart {
    page: PTPage,
}

impl RawPageTablePart {
    /// Frees a level 1 page table.
    fn free_lvl1(page: &PTPage) {
        for entry in page.entries.iter() {
            if let Some(page) = PTPage::from_entry(*entry) {
                // SAFETY: the page comes from an entry in the page table,
                // which we allocated using `PTPage::alloc()`, so this is
                // safe.
                unsafe { PTPage::free(page) };
            }
        }
    }

    /// Frees a level 2 page table, including all level 1 tables beneath it.
    fn free_lvl2(page: &PTPage) {
        for entry in page.entries.iter() {
            if let Some(l1_page) = PTPage::from_entry(*entry) {
                Self::free_lvl1(l1_page);
                // SAFETY: the page comes from an entry in the page table,
                // which we allocated using `PTPage::alloc()`, so this is
                // safe.
                unsafe { PTPage::free(l1_page) };
            }
        }
    }

    /// Frees the resources associated with this page table part.
    fn free(&self) {
        RawPageTablePart::free_lvl2(&self.page);
    }

    /// Returns the physical address of this page table part.
    fn address(&self) -> PhysAddr {
        virt_to_phys(VirtAddr::from(self as *const RawPageTablePart))
    }

    /// Walks the page table at level 3 to find the mapping for a given
    /// virtual address.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address to find the mapping for.
    ///
    /// # Returns
    /// The [`Mapping`] for the given virtual address.
    fn walk_addr(&mut self, vaddr: VirtAddr) -> Mapping<'_> {
        PageTable::walk_addr_lvl2(&mut self.page, vaddr)
    }

    /// Allocates a 4KB page table entry for a given virtual address.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address for which to allocate the PTE.
    ///
    /// # Returns
    /// The [`Mapping`] representing the allocated or existing PTE for the address.
    ///
    /// # Panics
    /// Panics if a level 3 mapping is attempted in a [`RawPageTablePart`].
    fn alloc_pte_4k(&mut self, vaddr: VirtAddr) -> Mapping<'_> {
        let m = self.walk_addr(vaddr);

        match m {
            Mapping::Level0(entry) => Mapping::Level0(entry),
            Mapping::Level1(entry) => PageTable::alloc_pte_lvl1(entry, vaddr, PageSize::Regular),
            Mapping::Level2(entry) => PageTable::alloc_pte_lvl2(entry, vaddr, PageSize::Regular),
            Mapping::Level3(_) => panic!("PT level 3 not possible in PageTablePart"),
        }
    }

    /// Allocates a 2MB page table entry for a given virtual address.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address for which to allocate the PTE.
    ///
    /// # Returns
    /// The [`Mapping`] representing the allocated or existing PTE for the
    /// address.
    fn alloc_pte_2m(&mut self, vaddr: VirtAddr) -> Mapping<'_> {
        let m = self.walk_addr(vaddr);

        match m {
            Mapping::Level0(entry) => Mapping::Level0(entry),
            Mapping::Level1(entry) => Mapping::Level1(entry),
            Mapping::Level2(entry) => PageTable::alloc_pte_lvl2(entry, vaddr, PageSize::Huge),
            Mapping::Level3(entry) => PageTable::alloc_pte_lvl3(entry, vaddr, PageSize::Huge),
        }
    }

    /// Maps a 4KB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address to map.
    /// - `paddr`: The physical address to map to.
    /// - `flags`: The flags to apply to the mapping.
    /// - `shared`: Indicates whether the mapping is shared.
    ///
    /// # Returns
    /// A result indicating success (`Ok`) or failure (`Err`).
    fn map_4k(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PTEntryFlags,
        shared: bool,
    ) -> Result<(), SvsmError> {
        let mapping = self.alloc_pte_4k(vaddr);

        let addr = if !shared {
            make_private_address(paddr)
        } else {
            make_shared_address(paddr)
        };

        if let Mapping::Level0(entry) = mapping {
            entry.set(addr, flags);
            Ok(())
        } else {
            Err(SvsmError::Mem)
        }
    }

    /// Unmaps a 4KB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address of the mapping to unmap.
    ///
    /// # Returns
    /// An optional [`PTEntry`] representing the unmapped page table entry.
    fn unmap_4k(&mut self, vaddr: VirtAddr) -> Option<PTEntry> {
        let mapping = self.walk_addr(vaddr);

        match mapping {
            Mapping::Level0(entry) => {
                let e = *entry;
                entry.clear();
                Some(e)
            }
            Mapping::Level1(entry) => {
                assert!(!entry.present());
                None
            }
            Mapping::Level2(entry) => {
                assert!(!entry.present());
                None
            }
            Mapping::Level3(entry) => {
                assert!(!entry.present());
                None
            }
        }
    }

    /// Maps a 2MB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address to map.
    /// - `paddr`: The physical address to map to.
    /// - `flags`: The flags to apply to the mapping.
    /// - `shared`: Indicates whether the mapping is shared
    ///
    /// # Returns
    /// A result indicating success (`Ok`) or failure (`Err`).
    ///
    /// # Panics
    ///
    /// Panics if `vaddr` or `paddr` are not 2MB-aligned
    fn map_2m(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PTEntryFlags,
        shared: bool,
    ) -> Result<(), SvsmError> {
        assert!(vaddr.is_aligned(PAGE_SIZE_2M));
        assert!(paddr.is_aligned(PAGE_SIZE_2M));

        let mapping = self.alloc_pte_2m(vaddr);
        let addr = if !shared {
            make_private_address(paddr)
        } else {
            make_shared_address(paddr)
        };

        if let Mapping::Level1(entry) = mapping {
            entry.set(addr, flags | PTEntryFlags::HUGE);
            Ok(())
        } else {
            Err(SvsmError::Mem)
        }
    }

    /// Unmaps a 2MB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address of the mapping to unmap.
    ///
    /// # Returns
    /// An optional [`PTEntry`] representing the unmapped page table entry.
    ///
    /// # Panics
    ///
    /// Panics if `vaddr` is not memory aligned.
    fn unmap_2m(&mut self, vaddr: VirtAddr) -> Option<PTEntry> {
        assert!(vaddr.is_aligned(PAGE_SIZE_2M));

        let mapping = self.walk_addr(vaddr);

        match mapping {
            Mapping::Level0(_) => None,
            Mapping::Level1(entry) => {
                entry.clear();
                Some(*entry)
            }
            Mapping::Level2(entry) => {
                assert!(!entry.present());
                None
            }
            Mapping::Level3(entry) => {
                assert!(!entry.present());
                None
            }
        }
    }
}

impl Drop for RawPageTablePart {
    fn drop(&mut self) {
        self.free();
    }
}

/// Sub-tree of a page table that can be populated at the top-level
/// used for virtual memory management
#[derive(Debug)]
pub struct PageTablePart {
    /// The root of the page-table sub-tree
    raw: Option<Box<RawPageTablePart>>,
    /// The top-level index this PageTablePart is populated at
    idx: usize,
}

impl PageTablePart {
    /// Create a new PageTablePart and allocate a root page for the page-table sub-tree.
    ///
    /// # Arguments
    ///
    /// - `start`: Virtual start address this PageTablePart maps
    ///
    /// # Returns
    ///
    /// A new instance of PageTablePart
    pub fn new(start: VirtAddr) -> Self {
        PageTablePart {
            raw: None,
            idx: PageTable::index::<3>(start),
        }
    }

    pub fn alloc(&mut self) {
        self.get_or_init_mut();
    }

    fn get_or_init_mut(&mut self) -> &mut RawPageTablePart {
        self.raw.get_or_insert_with(Box::default)
    }

    fn get_mut(&mut self) -> Option<&mut RawPageTablePart> {
        self.raw.as_deref_mut()
    }

    fn get(&self) -> Option<&RawPageTablePart> {
        self.raw.as_deref()
    }

    /// Request PageTable index to populate this instance to
    ///
    /// # Returns
    ///
    /// Index of the top-level PageTable this sub-tree is populated to
    pub fn index(&self) -> usize {
        self.idx
    }

    /// Request physical base address of the page-table sub-tree. This is
    /// needed to populate the PageTablePart.
    ///
    /// # Returns
    ///
    /// Physical base address of the page-table sub-tree
    pub fn address(&self) -> Option<PhysAddr> {
        self.get().map(|p| p.address())
    }

    /// Map a 4KiB page in the page table sub-tree
    ///
    /// # Arguments
    ///
    /// * `vaddr` - Virtual address to create the mapping. Must be aligned to 4KiB.
    /// * `paddr` - Physical address to map. Must be aligned to 4KiB.
    /// * `flags` - PTEntryFlags used for the mapping
    /// * `shared` - Defines whether the page is mapped shared or private
    ///
    /// # Returns
    ///
    /// OK(()) on Success, Err(SvsmError::Mem) on error.
    ///
    /// This function can fail when there not enough memory to allocate pages for the mapping.
    ///
    /// # Panics
    ///
    /// This method panics when either `vaddr` or `paddr` are not aligned to 4KiB.
    pub fn map_4k(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PTEntryFlags,
        shared: bool,
    ) -> Result<(), SvsmError> {
        assert!(PageTable::index::<3>(vaddr) == self.idx);

        self.get_or_init_mut().map_4k(vaddr, paddr, flags, shared)
    }

    /// Unmaps a 4KiB page from the page table sub-tree
    ///
    /// # Arguments
    ///
    /// * `vaddr` - The virtual address to unmap. Must be aligned to 4KiB.
    ///
    /// # Returns
    ///
    /// Returns a copy of the PTEntry that mapped the virtual address, if any.
    ///
    /// # Panics
    ///
    /// This method panics when `vaddr` is not aligned to 4KiB.
    pub fn unmap_4k(&mut self, vaddr: VirtAddr) -> Option<PTEntry> {
        assert!(PageTable::index::<3>(vaddr) == self.idx);

        self.get_mut().and_then(|r| r.unmap_4k(vaddr))
    }

    /// Map a 2MiB page in the page table sub-tree
    ///
    /// # Arguments
    ///
    /// * `vaddr` - Virtual address to create the mapping. Must be aligned to 2MiB.
    /// * `paddr` - Physical address to map. Must be aligned to 2MiB.
    /// * `flags` - PTEntryFlags used for the mapping
    /// * `shared` - Defines whether the page is mapped shared or private
    ///
    /// # Returns
    ///
    /// OK(()) on Success, Err(SvsmError::Mem) on error.
    ///
    /// This function can fail when there not enough memory to allocate pages for the mapping.
    ///
    /// # Panics
    ///
    /// This method panics when either `vaddr` or `paddr` are not aligned to 2MiB.
    pub fn map_2m(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PTEntryFlags,
        shared: bool,
    ) -> Result<(), SvsmError> {
        assert!(PageTable::index::<3>(vaddr) == self.idx);

        self.get_or_init_mut().map_2m(vaddr, paddr, flags, shared)
    }

    /// Unmaps a 2MiB page from the page table sub-tree
    ///
    /// # Arguments
    ///
    /// * `vaddr` - The virtual address to unmap. Must be aligned to 2MiB.
    ///
    /// # Returns
    ///
    /// Returns a copy of the PTEntry that mapped the virtual address, if any.
    ///
    /// # Panics
    ///
    /// This method panics when `vaddr` is not aligned to 2MiB.
    pub fn unmap_2m(&mut self, vaddr: VirtAddr) -> Option<PTEntry> {
        assert!(PageTable::index::<3>(vaddr) == self.idx);

        self.get_mut().and_then(|r| r.unmap_2m(vaddr))
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::BIT_MASK;
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::control_regs::write_cr3;
use crate::cpu::flush_tlb_global_sync;
use crate::cpu::idt::common::PageFaultError;
use crate::cpu::registers::RFlags;
use crate::error::SvsmError;
use crate::mm::{
    PGTABLE_LVL3_IDX_PTE_SELFMAP, PGTABLE_LVL3_IDX_SHARED, PageBox, phys_to_virt, virt_to_phys,
};
use crate::platform::SvsmPlatform;
use crate::types::{PAGE_SIZE, PAGE_SIZE_2M, PageSize};
use crate::utils::MemoryRegion;
use crate::utils::immut_after_init::{ImmutAfterInitCell, ImmutAfterInitResult};
use bitflags::bitflags;
use core::cmp;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use cpuarch::x86::CR0Flags;
use cpuarch::x86::CR4Flags;
use cpuarch::x86::EFERFlags;
use zerocopy::FromBytes;
use zerocopy::FromZeros;

// Re-export types from the paging crate.
pub use paging::pagetable::{
    ArchPagingMeta, GenericPageTable, GenericPageTableFlags, PageLevel, PagingError, PagingHandler,
    PagingLevel, SelfMap,
};
pub use paging::x86_64::{PTEntryFlags, PdptLevel, Pml4Level};

/// Mask for private page table entry.
static PRIVATE_PTE_MASK: ImmutAfterInitCell<usize> = ImmutAfterInitCell::uninit();

/// Mask for shared page table entry.
static SHARED_PTE_MASK: ImmutAfterInitCell<usize> = ImmutAfterInitCell::uninit();

/// Maximum physical address supported by the system.
static MAX_PHYS_ADDR: ImmutAfterInitCell<u64> = ImmutAfterInitCell::uninit();

/// Maximum physical address bits supported by the system.
static PHYS_ADDR_SIZE: ImmutAfterInitCell<u32> = ImmutAfterInitCell::uninit();

/// Physical address for the Launch VMSA (Virtual Machine Saving Area).
pub const LAUNCH_VMSA_ADDR: PhysAddr = PhysAddr::new(0xFFFFFFFFF000);

/// Feature mask for page table entry flags.
static FEATURE_MASK: ImmutAfterInitCell<PTEntryFlags> = ImmutAfterInitCell::uninit();

/// Initializes paging settings.
pub fn paging_init(platform: &dyn SvsmPlatform, suppress_global: bool) -> ImmutAfterInitResult<()> {
    init_encrypt_mask(platform)?;

    let mut feature_mask = PTEntryFlags::all();
    if suppress_global {
        feature_mask.remove(PTEntryFlags::GLOBAL);
    }
    FEATURE_MASK.init(feature_mask)
}

/// Initializes the encrypt mask.
fn init_encrypt_mask(platform: &dyn SvsmPlatform) -> ImmutAfterInitResult<()> {
    let masks = platform.get_page_encryption_masks();

    PRIVATE_PTE_MASK.init(masks.private_pte_mask)?;
    SHARED_PTE_MASK.init(masks.shared_pte_mask)?;

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

    PHYS_ADDR_SIZE.init(phys_addr_size)?;

    // If the C-bit is a physical address bit however, the guest physical
    // address space is effectively reduced by 1 bit.
    // - APM2, 15.34.6 Page Table Support
    let effective_phys_addr_size = cmp::min(masks.addr_mask_width, phys_addr_size);

    let max_addr = 1 << effective_phys_addr_size;
    MAX_PHYS_ADDR.init(max_addr)
}

/// Returns the private encrypt mask value.
pub fn private_pte_mask() -> usize {
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

/// Set address as private via mask.
pub fn make_private_address(paddr: PhysAddr) -> PhysAddr {
    SvsmPaging::make_private_address(paddr)
}

/// The SVSM page table provider: frame mapping, allocation, and encryption masks.
#[derive(Debug, Clone, Copy, FromBytes)]
pub struct SvsmPaging;

impl ArchPagingMeta for SvsmPaging {
    type PTFlags = PTEntryFlags;

    fn private_pte_mask() -> usize {
        private_pte_mask()
    }

    fn shared_pte_mask() -> usize {
        shared_pte_mask()
    }

    fn address_mask() -> usize {
        0x000f_ffff_ffff_f000
    }

    fn flush_tlb_global() {
        flush_tlb_global_sync();
    }

    fn supported_flags() -> PTEntryFlags {
        *FEATURE_MASK
    }
}

// SAFETY: paddr_to_vaddr correctly maps physical addresses via phys_to_virt,
// and allocate_physical_page returns unique zeroed frames via PageBox.
unsafe impl PagingHandler for SvsmPaging {
    fn paddr_to_vaddr(paddr: PhysAddr) -> VirtAddr {
        phys_to_virt(paddr)
    }

    fn allocate_physical_page() -> Result<PhysAddr, PagingError> {
        let page = pt_page_alloc_box().map_err(|_| PagingError::AllocFrame)?;
        let paddr = virt_to_phys(page.vaddr());
        let _ = PageBox::leak(page);
        Ok(paddr)
    }

    unsafe fn deallocate_physical_page(paddr: PhysAddr) {
        let vaddr = phys_to_virt(paddr);
        // SAFETY: paddr was returned by allocate_physical_page (via PageBox::leak),
        // so reconstructing the PageBox from the same pointer is valid.
        unsafe {
            let ptr = NonNull::new(vaddr.as_mut_ptr::<PTPage>()).unwrap();
            let _ = PageBox::from_raw(ptr);
        }
    }
}

impl SelfMap for SvsmPaging {
    const SELFMAP_IDX: usize = PGTABLE_LVL3_IDX_PTE_SELFMAP;
}

/// Represents paging mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PagingMode {
    // Paging mode is disabled
    NoPaging,
    // 32bit legacy paging mode
    NonPAE,
    // 32bit PAE paging mode
    PAE,
    // 4 level paging mode
    PML4,
    // 5 level paging mode
    PML5,
}

impl PagingMode {
    pub fn new(efer: EFERFlags, cr0: CR0Flags, cr4: CR4Flags) -> Self {
        if !cr0.contains(CR0Flags::PG) {
            // Paging is disabled
            PagingMode::NoPaging
        } else if efer.contains(EFERFlags::LMA) {
            // Long mode is activated
            if cr4.contains(CR4Flags::LA57) {
                PagingMode::PML5
            } else {
                PagingMode::PML4
            }
        } else if cr4.contains(CR4Flags::PAE) {
            // PAE mode
            PagingMode::PAE
        } else {
            // Non PAE mode
            PagingMode::NonPAE
        }
    }
}

/// Represents a page table entry.
pub type PTEntry = paging::pagetable::PTEntry<SvsmPaging>;

/// A pagetable page with multiple entries.
pub type PTPage = paging::pagetable::PTPage<SvsmPaging, SvsmPaging>;

/// Mapping levels of page table entries.
pub type Mapping<'a> = paging::pagetable::Mapping<'a, SvsmPaging>;

/// A physical address within a page frame
pub type PageFrame = paging::pagetable::PageFrame<SvsmPaging>;

trait PTEntryExt {
    /// Check if the page table entry has reserved bits set.
    fn has_reserved_bits(&self, pm: PagingMode, level: usize) -> bool;
}

impl PTEntryExt for PTEntry {
    fn has_reserved_bits(&self, pm: PagingMode, level: usize) -> bool {
        let reserved_mask = match pm {
            PagingMode::NoPaging => unreachable!("NoPaging does not have page table"),
            PagingMode::NonPAE => {
                match level {
                    // No reserved bits in 4k PTE.
                    0 => 0,
                    1 => {
                        if self.huge() {
                            // Bit21 is reserved in 4M PDE.
                            BIT_MASK!(21, 21)
                        } else {
                            // No reserved bits in PDE.
                            0
                        }
                    }
                    _ => unreachable!("Invalid NonPAE page table level"),
                }
            }
            PagingMode::PAE => {
                // Bit62 ~ MAXPHYSADDR are reserved for each
                // level in PAE page table.
                BIT_MASK!(62, *PHYS_ADDR_SIZE)
                    | match level {
                        // No additional reserved bits in 4k PTE.
                        0 => 0,
                        1 => {
                            if self.huge() {
                                // Bit20 ~ Bit13 are reserved in 2M PDE.
                                BIT_MASK!(20, 13)
                            } else {
                                // No additional reserved bits in PDE.
                                0
                            }
                        }
                        // Bit63 and Bit8 ~ Bit5 are reserved in PDPTE.
                        2 => BIT_MASK!(63, 63) | BIT_MASK!(8, 5),
                        _ => unreachable!("Invalid PAE page table level"),
                    }
            }
            PagingMode::PML4 | PagingMode::PML5 => {
                // Bit51 ~ MAXPHYSADDR are reserved for each level
                // in PML4 and PML5 page table.
                let common = if *PHYS_ADDR_SIZE > 51 {
                    0
                } else {
                    // Remove the encryption mask bit as this bit is not reserved
                    BIT_MASK!(51, *PHYS_ADDR_SIZE)
                        & !((shared_pte_mask() | private_pte_mask()) as u64)
                };

                common
                    | match level {
                        // No additional reserved bits in 4k PTE.
                        0 => 0,
                        1 => {
                            if self.huge() {
                                // Bit20 ~ Bit13 are reserved in 2M PDE.
                                BIT_MASK!(20, 13)
                            } else {
                                // No additional reserved bits in PDE.
                                0
                            }
                        }
                        2 => {
                            if self.huge() {
                                // Bit29 ~ Bit13 are reserved in 1G PDPTE.
                                BIT_MASK!(29, 13)
                            } else {
                                // No additional reserved bits in PDPTE.
                                0
                            }
                        }
                        // Bit8 ~ Bit7 are reserved in PML4E.
                        3 => BIT_MASK!(8, 7),
                        4 => {
                            if pm == PagingMode::PML4 {
                                unreachable!("Invalid PML4 page table level");
                            } else {
                                // Bit8 ~ Bit7 are reserved in PML5E.
                                BIT_MASK!(8, 7)
                            }
                        }
                        _ => unreachable!("Invalid PML4/PML5 page table level"),
                    }
            }
        };

        self.raw() & reserved_mask as usize != 0
    }
}

fn pt_page_alloc_box() -> Result<PageBox<PTPage>, SvsmError> {
    PageBox::try_new_zeroed()
}

/// Inner type alias to simplify references to the fully-parameterized generic page table.
type SvsmPageTable = GenericPageTable<SvsmPaging, SvsmPaging, Pml4Level>;

/// Represents a sub-tree of a page-table which can be mapped at a top-level index
type RawPageTablePart = GenericPageTable<SvsmPaging, SvsmPaging, PdptLevel>;

/// Page table structure containing a root page with multiple entries.
#[repr(C)]
#[derive(Debug, FromZeros)]
pub struct PageTable(SvsmPageTable);

impl Deref for PageTable {
    type Target = SvsmPageTable;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PageTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PageTable {
    /// Load the current page table into the CR3 register.
    ///
    /// # Safety
    ///
    /// The caller must ensure to take other actions to make sure a memory safe
    /// execution state is warranted (e.g. changing the stack and register state)
    pub unsafe fn load(&self) {
        // SAFETY: demanded to the caller
        unsafe {
            write_cr3(self.cr3_value());
        }
    }

    /// Get the CR3 register value for the current page table.
    pub fn cr3_value(&self) -> PhysAddr {
        let pgtable = VirtAddr::from(self as *const Self);
        virt_to_phys(pgtable)
    }

    /// Computes the index within a page table at the given level for a
    /// virtual address `vaddr`.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address to compute the index for.
    ///
    /// # Returns
    /// The index within the page table.
    #[inline]
    pub fn index<const L: usize>(vaddr: VirtAddr) -> usize {
        SvsmPageTable::index::<L>(vaddr)
    }

    /// Perform a virtual to physical translation using the self-map.
    ///
    /// # Parameters
    /// - `vaddr': The virtual address to translate.
    ///
    /// # Returns
    /// Some(PageFrame) if the virtual address is valid.
    /// None if the virtual address is not valid.
    #[inline]
    pub fn virt_to_frame(vaddr: VirtAddr) -> Option<PageFrame> {
        SvsmPageTable::virt_to_frame(vaddr)
    }

    /// Allocate a new page table root.
    ///
    /// # Errors
    /// Returns [`SvsmError`] if the page cannot be allocated.
    fn allocate_new() -> Result<PageBox<Self>, SvsmError> {
        let mut pgtable: PageBox<Self> = PageBox::try_new_zeroed()?;
        let paddr = virt_to_phys(pgtable.vaddr());
        pgtable.init_self_map(paddr);
        Ok(pgtable)
    }

    /// Clone the shared part of the page table; excluding the private
    /// parts.
    ///
    /// # Errors
    /// Returns [`SvsmError`] if the page cannot be allocated.
    pub fn clone_shared(&self) -> Result<PageBox<PageTable>, SvsmError> {
        let mut pgtable = Self::allocate_new()?;
        pgtable.copy_entry(self, PGTABLE_LVL3_IDX_SHARED);
        Ok(pgtable)
    }

    /// Splits a page into 4KB pages if it is part of a larger mapping.
    ///
    /// # Parameters
    /// - `mapping`: The mapping to split.
    ///
    /// # Returns
    /// A result indicating success or an error [`SvsmError`].
    pub fn split_4k(mapping: Mapping<'_>) -> Result<(), SvsmError> {
        SvsmPageTable::split_4k(mapping)?;
        Ok(())
    }

    /// Gets the physical address for a mapped `vaddr` or `None` if
    /// no such mapping exists.
    pub fn check_mapping(&mut self, vaddr: VirtAddr) -> Option<PhysAddr> {
        let mapping = self.walk_addr(vaddr);
        match mapping.level {
            PageLevel::Level0 | PageLevel::Level1 => Some(mapping.entry.address()),
            _ => None,
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
    /// A result indicating success or failure ([`SvsmError`]).
    pub fn map_4k(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PTEntryFlags,
        shared: bool,
    ) -> Result<(), SvsmError> {
        self.0.map_4k(vaddr, paddr, flags, shared)?;
        Ok(())
    }

    /// Maps a region of memory using 4KB pages.
    ///
    /// # Parameters
    /// - `vregion`: The virtual memory region to map.
    /// - `phys`: The starting physical address to map to.
    /// - `flags`: The flags to apply to the mapping.
    /// - `shared`: Indicates whether the mapping is shared.
    ///
    /// # Returns
    /// A result indicating success or failure ([`SvsmError`]).
    pub fn map_region_4k(
        &mut self,
        vregion: MemoryRegion<VirtAddr>,
        phys: PhysAddr,
        flags: PTEntryFlags,
        shared: bool,
    ) -> Result<(), SvsmError> {
        for addr in vregion.iter_pages(PageSize::Regular) {
            let offset = addr - vregion.start();
            self.map_4k(addr, phys + offset, flags, shared)?;
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
    /// - `shared`: Indicates whether the mapping is shared.
    ///
    /// # Returns
    /// A result indicating success or failure ([`SvsmError`]).
    pub fn map_region_2m(
        &mut self,
        vregion: MemoryRegion<VirtAddr>,
        phys: PhysAddr,
        flags: PTEntryFlags,
        shared: bool,
    ) -> Result<(), SvsmError> {
        for addr in vregion.iter_pages(PageSize::Huge) {
            let offset = addr - vregion.start();
            self.map_2m(addr, phys + offset, flags, shared)?;
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
                && self.map_2m(vaddr, paddr, flags, false).is_ok()
            {
                vaddr = vaddr + PAGE_SIZE_2M;
                paddr = paddr + PAGE_SIZE_2M;
                continue;
            }

            self.map_4k(vaddr, paddr, flags, false)?;
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

            match mapping.level {
                PageLevel::Level0 => {
                    mapping.entry.clear();
                    vaddr = vaddr + PAGE_SIZE;
                }
                PageLevel::Level1 => {
                    mapping.entry.clear();
                    vaddr = vaddr + PAGE_SIZE_2M;
                }
                _ => {
                    log::error!("Can't unmap - address not mapped {vaddr:#x}");
                }
            }
        }
    }

    /// Populates this page table with the contents of the given subtree
    /// in `part`.
    ///
    /// Returns `true` if the PTE contents were updated.
    pub fn populate_pgtbl_part(&mut self, part: &PageTablePart) -> bool {
        let Some(paddr) = part.address() else {
            return false;
        };
        let idx = part.index();
        let flags = PTEntryFlags::PRESENT
            | PTEntryFlags::WRITABLE
            | PTEntryFlags::USER
            | PTEntryFlags::ACCESSED;
        self.set_entry(idx, SvsmPaging::make_private_address(paddr), flags)
    }

    /// Makes the memory region pages read-only.
    /// This method is meant for global pages only.
    ///
    /// # Safety
    ///
    /// The caller should verify that `region` can be made read-only, i.e. that
    /// no write can happen or that a #PF raised by any tentative write is
    /// expected.
    /// The caller must also ensure that the region start and size are 4k
    /// aligned.
    pub unsafe fn make_region_ro_4k(
        &mut self,
        region: MemoryRegion<VirtAddr>,
    ) -> Result<(), SvsmError> {
        for page in region.iter_pages(PageSize::Regular) {
            match self.walk_addr(page) {
                Mapping {
                    level: PageLevel::Level0,
                    entry,
                } => {
                    if !entry.present() || !entry.flags().global() {
                        return Err(SvsmError::Mem);
                    }

                    let flags = PTEntryFlags::data_ro();

                    let paddr_field = entry.paddr_field();

                    entry.set(paddr_field, flags);
                }
                Mapping {
                    level: PageLevel::Level1 | PageLevel::Level2,
                    entry,
                } => {
                    // Ensure we never fell on a huge page while iterating over the region pages.
                    if entry.huge() {
                        return Err(SvsmError::Mem);
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}

/// Sub-tree of a page table that can be populated at the top-level
/// used for virtual memory management
#[derive(Debug)]
pub struct PageTablePart {
    /// The root of the page-table sub-tree
    raw: Option<PageBox<RawPageTablePart>>,
    /// The top-level index this PageTablePart is populated at
    idx: usize,
}

impl Drop for PageTablePart {
    fn drop(&mut self) {
        if let Some(raw) = self.raw.as_deref() {
            raw.free()
        }
    }
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
        self.raw.get_or_insert_with(|| {
            PageBox::try_new_zeroed().expect("Failed to allocate page table page")
        })
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
        self.get()
            .map(|p| virt_to_phys(VirtAddr::from(p as *const RawPageTablePart)))
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

        self.get_or_init_mut()
            .map_4k(vaddr, paddr, flags, shared)
            .map_err(|_| SvsmError::Mem)
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
        self.get_mut()?.unmap_4k(vaddr)
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

        self.get_or_init_mut()
            .map_2m(vaddr, paddr, flags, shared)
            .map_err(|_| SvsmError::Mem)
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
        self.get_mut()?.unmap_2m(vaddr)
    }
}

bitflags! {
    /// Flags to represent how memory is accessed, e.g. write data to the
    /// memory or fetch code from the memory.
    #[derive(Clone, Copy, Debug)]
    pub struct MemAccessMode: u32 {
        const WRITE     = 1 << 0;
        const FETCH     = 1 << 1;
    }
}

/// Attributes to determin Whether a memory access (write/fetch) is permitted
/// by a translation which includes the paging-mode modifiers in CR0, CR4 and
/// EFER; EFLAGS.AC; and the supervisor/user mode access.
#[derive(Clone, Copy, Debug)]
pub struct PTWalkAttr {
    cr0: CR0Flags,
    cr4: CR4Flags,
    efer: EFERFlags,
    flags: RFlags,
    user_mode_access: bool,
    pm: PagingMode,
}

impl PTWalkAttr {
    /// Creates a new `PTWalkAttr` instance with the specified attributes.
    ///
    /// # Arguments
    ///
    /// * `cr0`, `cr4`, and `efer` - Represent the control register
    ///   flags for CR0, CR4, and EFER respectively.
    /// * `flags` - Represents the CPU Flags.
    /// * `user_mode_access` - Indicates whether the access is in user mode.
    ///
    /// Returns a new `PTWalkAttr` instance.
    pub fn new(
        cr0: CR0Flags,
        cr4: CR4Flags,
        efer: EFERFlags,
        flags: RFlags,
        user_mode_access: bool,
    ) -> Self {
        Self {
            cr0,
            cr4,
            efer,
            flags,
            user_mode_access,
            pm: PagingMode::new(efer, cr0, cr4),
        }
    }

    /// Checks the access rights for a page table entry.
    ///
    /// # Arguments
    ///
    /// * `entry` - The page table entry to check.
    /// * `mem_am` - Indicates how to access the memory.
    /// * `last_level` - Indicates whether the entry is at the last level
    ///   of the page table.
    /// * `pteflags` - The PTE flags to indicate if the corresponding page
    ///   table entry allows the access rights.
    ///
    /// # Returns
    ///
    /// Returns `Ok((entry, leaf))` if the access rights are valid, where
    /// `entry` is the modified page table entry and `leaf` is a boolean
    /// indicating whether the entry is a leaf node, or `Err(PageFaultError)`
    /// to indicate the page fault error code if the access rights are invalid.
    pub fn check_access_rights(
        &self,
        entry: PTEntry,
        mem_am: MemAccessMode,
        level: usize,
        pteflags: &mut PTEntryFlags,
    ) -> Result<(PTEntry, bool), PageFaultError> {
        let pf_err = self.default_pf_err(mem_am) | PageFaultError::P;

        if !entry.present() {
            // Entry is not present.
            return Err(pf_err & !PageFaultError::P);
        }

        if entry.has_reserved_bits(self.pm, level) {
            // Reserved bits have been set.
            return Err(pf_err | PageFaultError::R);
        }

        // SDM 4.6.1 Determination of Access Rights:
        // If the U/S flag (bit 2) is 0 in at least one of the
        // paging-structure entries, the address is a supervisor-mode
        // address. Otherwise, the address is a user-mode address.
        // So by-default assume the address is user mode address.
        if !entry.user() {
            *pteflags &= !PTEntryFlags::USER;
        }

        // SDM 4.6.1 Determination of Access Rights:
        // R/W flag (bit 1) is 1 in every paging-structure entry controlling
        // the translation and with a protection key for which write access is
        // permitted; data may not be written to any supervisor-mode
        // address with a translation for which the R/W flag is 0 in any
        // paging-structure entry controlling the translation.
        // The same for user mode address
        if !entry.flags().writable() {
            *pteflags &= !PTEntryFlags::WRITABLE;
        }

        // SDM 4.6.1 Determination of Access Rights:
        // For non 32-bit paging modes with IA32_EFER.NXE = 1, instructions
        // may be fetched from any supervisormode address with a translation
        // for which the XD flag (bit 63) is 0 in every paging-structure entry
        // controlling the translation; instructions may not be fetched from
        // any supervisor-mode address with a translation for which the XD flag
        // is 1 in any paging-structure entry controlling the translation
        if self.efer.contains(EFERFlags::NXE) && entry.flags().nx() {
            *pteflags |= PTEntryFlags::NX;
        } else if !self.efer.contains(EFERFlags::NXE) && entry.flags().nx() {
            // XD bit must be 0 if efer.NXE = 0
            return Err(pf_err | PageFaultError::R);
        }

        let leaf = if level == 0 || entry.huge() {
            // User mode cannot access any supervisor mode addresses
            if self.user_mode_access && !pteflags.contains(PTEntryFlags::USER) {
                return Err(pf_err);
            }

            // Always check for reading. For the case of supervisor mode read user
            // mode addresses, do special checking. For other cases, read is allowed.
            if !self.user_mode_access && pteflags.contains(PTEntryFlags::USER) {
                // Read not allowed with SMAP = 1 && flags.ac = 0
                if self.cr4.contains(CR4Flags::SMAP) && !self.flags.contains(RFlags::AC) {
                    return Err(pf_err);
                }
            }

            if mem_am.contains(MemAccessMode::WRITE) {
                if !self.user_mode_access && pteflags.contains(PTEntryFlags::USER) {
                    // Check supervisor mode write user mode addresses
                    if !self.cr0.contains(CR0Flags::WP) {
                        // Check write with CR0.WP = 0
                        if self.cr4.contains(CR4Flags::SMAP) && !self.flags.contains(RFlags::AC) {
                            // Write not allowed with SMAP = 1 && flags.ac = 0
                            return Err(pf_err);
                        }
                    } else {
                        // Check write with CR0.WP = 1
                        if !self.cr4.contains(CR4Flags::SMAP) {
                            // SMAP = 0
                            if !pteflags.contains(PTEntryFlags::WRITABLE) {
                                // Write not allowed R/W = 0
                                return Err(pf_err);
                            }
                        } else {
                            // SMAP = 1
                            if !self.flags.contains(RFlags::AC)
                                || !pteflags.contains(PTEntryFlags::WRITABLE)
                            {
                                // Write not allowed with flags.AC = 0 || R/W = 0
                                return Err(pf_err);
                            }
                        }
                    }
                } else if !self.user_mode_access && !pteflags.contains(PTEntryFlags::USER) {
                    // Check supervisor mode write supervisor mode addresses
                    if self.cr0.contains(CR0Flags::WP) && !pteflags.contains(PTEntryFlags::WRITABLE)
                    {
                        // Write not allowed with CR0.WP = 1 && R/W = 0
                        return Err(pf_err);
                    }
                } else if self.user_mode_access && pteflags.contains(PTEntryFlags::USER) {
                    // Check user mode write user mode addresses
                    if !pteflags.contains(PTEntryFlags::WRITABLE) {
                        // Write not allowed R/W = 0
                        return Err(pf_err);
                    }
                }
                // User mode write supervisor mode addresses is checked already
            }

            if mem_am.contains(MemAccessMode::FETCH) {
                // For instruction fetch, the rule is the same except for the case of
                // supervisor mode fetch user mode addresses
                if !self.user_mode_access && pteflags.contains(PTEntryFlags::USER) {
                    // Fetch not allowed with SMEP = 1
                    if self.cr4.contains(CR4Flags::SMEP) {
                        return Err(pf_err);
                    }
                }

                // For non-32bit paging mode, fetch not allowed with efer.NXE = 1 && XD = 1
                if self.cr4.contains(CR4Flags::PAE)
                    && self.efer.contains(EFERFlags::NXE)
                    && pteflags.contains(PTEntryFlags::NX)
                {
                    return Err(pf_err);
                }
            }
            true
        } else {
            false
        };

        Ok((entry, leaf))
    }

    fn default_pf_err(&self, mem_am: MemAccessMode) -> PageFaultError {
        let mut err = PageFaultError::empty();

        if mem_am.contains(MemAccessMode::WRITE) {
            err |= PageFaultError::W;
        }

        if mem_am.contains(MemAccessMode::FETCH) {
            err |= PageFaultError::I;
        }

        if self.user_mode_access {
            err |= PageFaultError::U;
        }

        err
    }
}

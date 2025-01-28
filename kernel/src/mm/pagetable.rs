// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::control_regs::{write_cr3, CR0Flags, CR4Flags};
use crate::cpu::efer::EFERFlags;
use crate::cpu::flush_tlb_global_sync;
use crate::cpu::idt::common::PageFaultError;
use crate::cpu::registers::RFlags;
use crate::error::SvsmError;
use crate::mm::{
    phys_to_virt, virt_to_phys, PageBox, PGTABLE_LVL3_IDX_PTE_SELFMAP, PGTABLE_LVL3_IDX_SHARED,
    SVSM_PTE_BASE,
};
use crate::platform::SvsmPlatform;
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_1G, PAGE_SIZE_2M};
use crate::utils::immut_after_init::{ImmutAfterInitCell, ImmutAfterInitResult};
use crate::utils::MemoryRegion;
use crate::BIT_MASK;
use bitflags::bitflags;
use core::cmp;
use core::ops::{Index, IndexMut};
use core::ptr::NonNull;

extern crate alloc;
use alloc::boxed::Box;

/// Number of entries in a page table (4KB/8B).
const ENTRY_COUNT: usize = 512;

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

    /// Check if the page table entry is huge.
    pub fn huge(&self) -> bool {
        self.flags().contains(PTEntryFlags::HUGE)
    }

    /// Check if the page table entry is writable.
    pub fn writable(&self) -> bool {
        self.flags().contains(PTEntryFlags::WRITABLE)
    }

    /// Check if the page table entry is NX (no-execute).
    pub fn nx(&self) -> bool {
        self.flags().contains(PTEntryFlags::NX)
    }

    /// Check if the page table entry is user-accessible.
    pub fn user(&self) -> bool {
        self.flags().contains(PTEntryFlags::USER)
    }

    /// Check if the page table entry has reserved bits set.
    pub fn has_reserved_bits(&self, pm: PagingMode, level: usize) -> bool {
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

        self.raw() & reserved_mask != 0
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

    /// Read a page table entry from the specified virtual address.
    ///
    /// # Safety
    ///
    /// Reads from an arbitrary virtual address, making this essentially a
    /// raw pointer read.  The caller must be certain to calculate the correct
    /// address.
    pub unsafe fn read_pte(vaddr: VirtAddr) -> Self {
        unsafe { *vaddr.as_ptr::<Self>() }
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
        unsafe {
            let _ = PageBox::from_raw(NonNull::from(page));
        }
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

/// A physical address within a page frame
#[derive(Clone, Copy, Debug)]
pub enum PageFrame {
    Size4K(PhysAddr),
    Size2M(PhysAddr),
    Size1G(PhysAddr),
}

impl PageFrame {
    pub fn address(&self) -> PhysAddr {
        match *self {
            Self::Size4K(pa) => pa,
            Self::Size2M(pa) => pa,
            Self::Size1G(pa) => pa,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::Size4K(_) => PAGE_SIZE,
            Self::Size2M(_) => PAGE_SIZE_2M,
            Self::Size1G(_) => PAGE_SIZE_1G,
        }
    }

    pub fn start(&self) -> PhysAddr {
        let end = self.address().bits() & !(self.size() - 1);
        end.into()
    }

    pub fn end(&self) -> PhysAddr {
        self.start() + self.size()
    }
}

/// Page table structure containing a root page with multiple entries.
#[repr(C)]
#[derive(Default, Debug)]
pub struct PageTable {
    root: PTPage,
}

impl PageTable {
    /// Load the current page table into the CR3 register.
    ///
    /// # Safety
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

    /// Allocate a new page table root.
    ///
    /// # Errors
    /// Returns [`SvsmError`] if the page cannot be allocated.
    pub fn allocate_new() -> Result<PageBox<Self>, SvsmError> {
        let mut pgtable = PageBox::try_new(PageTable::default())?;
        let paddr = virt_to_phys(pgtable.vaddr());

        // Set the self-map entry.
        let entry = &mut pgtable.root[PGTABLE_LVL3_IDX_PTE_SELFMAP];
        let flags = PTEntryFlags::PRESENT
            | PTEntryFlags::WRITABLE
            | PTEntryFlags::ACCESSED
            | PTEntryFlags::DIRTY
            | PTEntryFlags::NX;
        entry.set(make_private_address(paddr), flags);

        Ok(pgtable)
    }

    /// Clone the shared part of the page table; excluding the private
    /// parts.
    ///
    /// # Errors
    /// Returns [`SvsmError`] if the page cannot be allocated.
    pub fn clone_shared(&self) -> Result<PageBox<PageTable>, SvsmError> {
        let mut pgtable = Self::allocate_new()?;
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

    /// Calculate the virtual address of a PTE in the self-map, which maps a
    /// specified virtual address.
    ///
    /// # Parameters
    /// - `vaddr': The virtual address whose PTE should be located.
    ///
    /// # Returns
    /// The virtual address of the PTE.
    fn get_pte_address(vaddr: VirtAddr) -> VirtAddr {
        SVSM_PTE_BASE + ((usize::from(vaddr) & 0x0000_FFFF_FFFF_F000) >> 9)
    }

    /// Perform a virtual to physical translation using the self-map.
    ///
    /// # Parameters
    /// - `vaddr': The virtual address to translate.
    ///
    /// # Returns
    /// Some(PageFrame) if the virtual address is valid.
    /// None if the virtual address is not valid.
    pub fn virt_to_frame(vaddr: VirtAddr) -> Option<PageFrame> {
        // Calculate the virtual addresses of each level of the paging
        // hierarchy in the self-map.
        let pte_addr = Self::get_pte_address(vaddr);
        let pde_addr = Self::get_pte_address(pte_addr);
        let pdpe_addr = Self::get_pte_address(pde_addr);
        let pml4e_addr = Self::get_pte_address(pdpe_addr);

        // Check each entry in the paging hierarchy to determine whether this
        // address is mapped.  Because the hierarchy is read from the top
        // down using self-map addresses that were calculated correctly,
        // the reads are safe to perform.
        let pml4e = unsafe { PTEntry::read_pte(pml4e_addr) };
        if !pml4e.present() {
            return None;
        }

        // There is no need to check for a large page in the PML4E because
        // the architecture does not support the large bit at the top-level
        // entry.  If a large page is detected at a lower level of the
        // hierarchy, the low bits from the virtual address must be combined
        // with the physical address from the PDE/PDPE.
        let pdpe = unsafe { PTEntry::read_pte(pdpe_addr) };
        if !pdpe.present() {
            return None;
        }
        if pdpe.huge() {
            let pa = pdpe.address() + (usize::from(vaddr) & 0x3FFF_FFFF);
            return Some(PageFrame::Size1G(pa));
        }

        let pde = unsafe { PTEntry::read_pte(pde_addr) };
        if !pde.present() {
            return None;
        }
        if pde.huge() {
            let pa = pde.address() + (usize::from(vaddr) & 0x001F_FFFF);
            return Some(PageFrame::Size2M(pa));
        }

        let pte = unsafe { PTEntry::read_pte(pte_addr) };
        if pte.present() {
            let pa = pte.address() + (usize::from(vaddr) & 0xFFF);
            Some(PageFrame::Size4K(pa))
        } else {
            None
        }
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
        entry.set(make_private_address(paddr), flags);

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
        entry.set(make_private_address(paddr), flags);

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
        entry.set(make_private_address(paddr), flags);

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
            let phys_final = if shared {
                make_shared_address(phys + offset)
            } else {
                make_private_address(phys + offset)
            };
            self.map_4k(addr, phys_final, flags)?;
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
            let phys_final = if shared {
                make_shared_address(phys + offset)
            } else {
                make_private_address(phys + offset)
            };
            self.map_2m(addr, phys_final, flags)?;
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
            entry.set(make_private_address(paddr), flags);
        }
    }
}

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
        if !entry.writable() {
            *pteflags &= !PTEntryFlags::WRITABLE;
        }

        // SDM 4.6.1 Determination of Access Rights:
        // For non 32-bit paging modes with IA32_EFER.NXE = 1, instructions
        // may be fetched from any supervisormode address with a translation
        // for which the XD flag (bit 63) is 0 in every paging-structure entry
        // controlling the translation; instructions may not be fetched from
        // any supervisor-mode address with a translation for which the XD flag
        // is 1 in any paging-structure entry controlling the translation
        if self.efer.contains(EFERFlags::NXE) && entry.nx() {
            *pteflags |= PTEntryFlags::NX;
        } else if !self.efer.contains(EFERFlags::NXE) && entry.nx() {
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

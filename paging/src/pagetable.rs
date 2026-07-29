// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generic page table types and structures for 4 KiB granule paging.
//!
//! They are designed for different OS or architectures.
//!
//! The implementation assumes a 4 KiB base page granule with a 4-level
//! page table hierarchy (8-byte PTEntry and 512 entries per page), supporting three page
//! sizes: 4 KiB, 2 MiB, and 1 GiB. This covers x86_64 (PML4) and
//! ARM64 with 4 KiB granule. Other granule sizes (16 KiB, 64 KiB on
//! ARM64) are not supported.

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::sizes::{PAGE_SHIFT, PAGE_SIZE, PAGE_SIZE_1G, PAGE_SIZE_2M, PageSize};
pub use crate::tlb::MayNeedFlush;
pub use crate::traits::{
    ArchPagingMeta, GenericPageTableFlags, PageLevel, PagingError, PagingHandler, PagingLevel,
    PagingLevel2, PagingLevel3, SelfMap,
};
use bitflags::Flags;
use core::marker::PhantomData;
use core::ops::{Index, IndexMut};
use zerocopy::{FromBytes, FromZeros};

/// Number of virtual-address bits indexed by a single page-table level.
/// Assume 8-byte page table entries and page granularity = 1 << PAGE_SHIFT
pub(crate) const PTE_SHIFT: usize = PAGE_SHIFT - 3;

/// Number of entries in a page table (4KB/8B).
pub(crate) const ENTRY_COUNT: usize = 1 << PTE_SHIFT;

const fn virt_from_lvl_idx(idx: usize, level: PageLevel) -> VirtAddr {
    VirtAddr::new(idx << ((level as usize * PTE_SHIFT) + PAGE_SHIFT))
}

const _: () = assert!(
    core::mem::size_of::<PhysAddr>() == 8,
    "Only supports 8 bytes PTE entry",
);

/// Represents a page table entry.
#[repr(C)]
#[derive(Copy, Clone, Debug, FromBytes)]
pub struct PTEntry<A: ArchPagingMeta> {
    entry: PhysAddr,
    _phantom: PhantomData<A>,
}

impl<A: ArchPagingMeta> PTEntry<A> {
    /// Check if the page table entry is clear (null).
    pub fn is_clear(&self) -> bool {
        self.entry.is_null()
    }

    /// Clear the page table entry.
    pub fn clear(&mut self) {
        self.entry = PhysAddr::null();
    }

    /// Check if the page table entry is present.
    pub fn present(&self) -> bool {
        self.flags().present()
    }

    /// Check if the page table entry is huge.
    pub fn huge(&self) -> bool {
        self.flags().huge()
    }

    /// Check if the page table entry is user-accessible.
    pub fn user(&self) -> bool {
        self.flags().user()
    }

    /// Get the raw bits (`usize`) of the page table entry.
    pub fn raw(&self) -> usize {
        self.entry.bits()
    }

    /// Get the flags of the page table entry.
    pub fn flags(&self) -> A::PTFlags {
        A::PTFlags::from_bits_truncate(self.entry.bits())
    }

    /// Set the page table entry with the specified address and flags.
    pub fn set_unrestricted(&mut self, addr: PhysAddr, flags: A::PTFlags) {
        let addr = addr.bits();
        assert_eq!(addr & !A::address_mask(), 0);
        self.entry = PhysAddr::from(addr | flags.bits());
    }

    /// Set the page table entry with the specified address, with flags
    /// constrained to the supported feature flags.
    pub fn set(&mut self, addr: PhysAddr, flags: A::PTFlags) {
        self.set_unrestricted(addr, flags & A::supported_flags());
    }

    /// Inserts the private address mask if the page is present.
    pub fn make_private_if_present(&mut self) {
        if self.flags().contains(A::PTFlags::PRESENT) {
            self.entry = A::make_private_address(self.entry);
        }
    }

    /// Get the paddr field from the entry.
    ///
    /// Returns bits `[51:12]` of the entry — the address *including* any
    /// encryption/confidentiality bits the hardware stores in the upper
    /// physical address bits.
    pub fn paddr_field(&self) -> PhysAddr {
        PhysAddr::from(self.raw() & A::address_mask())
    }

    /// Get the address from the page table entry, including the shared bit.
    pub fn page_frame(&self) -> PhysAddr {
        A::strip_confidentiality_bits(self.paddr_field())
    }

    /// Get the address from the page table entry, excluding the C/shared bit.
    pub fn address(&self) -> PhysAddr {
        A::strip_shared_address_bits(self.page_frame())
    }

    // Returns true if the address is shared.
    pub fn is_shared(&self) -> bool {
        A::is_shared_address(self.paddr_field())
    }

    /// Read a page table entry from the specified virtual address.
    ///
    /// # Safety
    ///
    /// Reads from an arbitrary virtual address, making this essentially a
    /// raw pointer read.  The caller must be certain to calculate the correct
    /// address.
    pub unsafe fn read_pte(vaddr: VirtAddr) -> Self {
        // SAFETY: When the methods safety requirements are met, the raw
        // pointer read is safe.
        unsafe { *vaddr.as_ptr::<Self>() }
    }
}

/// A pagetable page with multiple entries.
#[repr(C)]
#[derive(Debug, FromBytes)]
pub struct PTPage<A: ArchPagingMeta, P: PagingHandler> {
    pub entries: [PTEntry<A>; ENTRY_COUNT],
    _phantom: PhantomData<P>,
}

impl<A: ArchPagingMeta, P: PagingHandler> PTPage<A, P> {
    /// Allocates a zeroed pagetable page and returns a mutable reference to
    /// it, plus its physical address.
    ///
    /// # Errors
    ///
    /// Returns [`PagingError`] if the page cannot be allocated.
    fn alloc() -> Result<(&'static mut Self, PhysAddr), PagingError> {
        let paddr = P::allocate_physical_page()?;
        let vaddr = P::paddr_to_vaddr(paddr);
        // SAFETY: allocate_physical_page returns a unique, zeroed frame and
        // paddr_to_vaddr returns a valid virtual mapping for it.
        let page = unsafe { Self::from_vaddr(vaddr) };
        Ok((page, paddr))
    }

    /// Converts a pagetable entry to a mutable reference to a [`PTPage`],
    /// if the entry is present and not huge.
    pub fn from_entry(entry: PTEntry<A>) -> Option<&'static mut Self> {
        if !entry.present() || entry.huge() {
            return None;
        }

        let address = P::paddr_to_vaddr(entry.address());
        // SAFETY: Every PTEntry points to a previously allocated page-table
        // page, so this pointer dereference is safe.
        Some(unsafe { Self::from_vaddr(address) })
    }

    /// Generates a `PTPage` from a virtual address.
    /// # Safety
    /// The caller must ensure that the virtual address is a valid page table.
    pub unsafe fn from_vaddr(vaddr: VirtAddr) -> &'static mut Self {
        // SAFETY: the caller guarantees the correctness of the virtual
        // address.
        unsafe { &mut *vaddr.as_mut_ptr::<Self>() }
    }
}

/// Can be used to access page table entries by index.
impl<A: ArchPagingMeta, P: PagingHandler> Index<usize> for PTPage<A, P> {
    type Output = PTEntry<A>;

    fn index(&self, index: usize) -> &PTEntry<A> {
        &self.entries[index]
    }
}

/// Can be used to modify page table entries by index.
impl<A: ArchPagingMeta, P: PagingHandler> IndexMut<usize> for PTPage<A, P> {
    fn index_mut(&mut self, index: usize) -> &mut PTEntry<A> {
        &mut self.entries[index]
    }
}

/// Mapping levels of page table entries.
#[derive(Debug)]
pub struct Mapping<'a, P: ArchPagingMeta> {
    pub level: PageLevel,
    pub entry: &'a mut PTEntry<P>,
}

impl<'a, P: ArchPagingMeta> Mapping<'a, P> {
    /// Construct a `Mapping` at the given level.
    pub fn new(level: PageLevel, entry: &'a mut PTEntry<P>) -> Self {
        Self { level, entry }
    }
}

/// A physical address within a page frame
#[derive(Clone, Copy, Debug)]
pub enum PageFrame<A: ArchPagingMeta> {
    Size4K(PhysAddr),
    Size2M(PhysAddr),
    Size1G(PhysAddr, PhantomData<A>),
}

impl<A: ArchPagingMeta> PageFrame<A> {
    /// Get the address from the page frame, including the shared bit.
    pub fn page_frame(&self) -> PhysAddr {
        let paddr = match *self {
            Self::Size4K(pa) => pa,
            Self::Size2M(pa) => pa,
            Self::Size1G(pa, _) => pa,
        };
        // Redundant but explicit.
        A::strip_confidentiality_bits(paddr)
    }

    /// Get the address from the page frame, excluding the C/shared bit.
    pub fn address(&self) -> PhysAddr {
        A::strip_shared_address_bits(self.page_frame())
    }

    pub fn size(&self) -> usize {
        match self {
            Self::Size4K(_) => PAGE_SIZE,
            Self::Size2M(_) => PAGE_SIZE_2M,
            Self::Size1G(_, _) => PAGE_SIZE_1G,
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

/// A page table hierarchy rooted at `L::TOP_LEVEL`.
///
/// The root is a concrete page-table page (`PTPage`) whose level is described
/// by `L`. This can represent either a complete top-level page table, such as
/// a PML4-rooted table, or a lower-level subtree, such as a PDPT-rooted table
/// that is installed into a top-level page table.
///
/// Ownership and synchronization are left to the OS-specific code.
/// If a lower-level subtree is shared between multiple top-level page tables,
/// all users of that subtree must coordinate updates to avoid concurrent
/// modifications to the same page-table entries.
#[repr(C)]
#[derive(Debug, FromZeros)]
pub struct GenericPageTable<A: ArchPagingMeta, P: PagingHandler, L: PagingLevel> {
    root: PTPage<A, P>,
    _level: PhantomData<L>,
}

/// Methods for page table hierarchies, independent of the self-map.
impl<A: ArchPagingMeta, P: PagingHandler, L: PagingLevel> GenericPageTable<A, P, L> {
    /// Recursively free all page table pages starting from the root page.
    fn free_lvl(page: &PTPage<A, P>, level: PageLevel) {
        if level <= PageLevel::Level0 {
            return;
        }
        for entry in page.entries.iter() {
            if let Some(child) = PTPage::from_entry(*entry) {
                if let Some(next) = level.next_down() {
                    Self::free_lvl(child, next);
                }
                let paddr = entry.address();
                // SAFETY: the page was allocated via PagingHandler::allocate_physical_page.
                unsafe { P::deallocate_physical_page(paddr) };
            }
        }
    }

    /// Free all page table pages starting from the root page.
    /// We do not set it as a destructor because a page table may contain
    /// shared sub-trees that may be in use by other root table.
    ///
    /// # Safety
    /// The caller must ensure that the page table is not in use by any other thread.
    pub fn free(&self) {
        Self::free_lvl(&self.root, L::TOP_LEVEL);
    }

    /// Get a copy of the entry at the specified index.
    pub fn entry(&mut self, idx: usize) -> PTEntry<A> {
        self.root.entries[idx]
    }

    /// Set the entry at the specified index.
    ///
    /// Returns `true` if the entry was updated, `false` otherwise.
    pub fn set_entry(
        &mut self,
        idx: usize,
        addr: PhysAddr,
        flags: A::PTFlags,
    ) -> (bool, MayNeedFlush<A::TlbFlushTok>) {
        let old_entry = self.root.entries[idx];
        self.root.entries[idx].set(addr, flags);
        let updated = old_entry.raw() != self.root.entries[idx].raw();
        let flush = if updated && old_entry.present() {
            MayNeedFlush::all()
        } else {
            MayNeedFlush::none()
        };
        (updated, flush)
    }

    /// Copy an entry at `entry` from another `GenericPageTable`.
    pub fn copy_entry(&mut self, other: &Self, idx: usize) {
        let entry = &mut self.root.entries[idx];
        assert!(!entry.present()); // No TLB flush needed
        *entry = other.root.entries[idx];
    }

    /// Computes the index within a page table at the given level for a
    /// virtual address `vaddr`.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address to compute the index for.
    ///
    /// # Returns
    /// The index within the page table.
    pub fn index<const LVL: usize>(vaddr: VirtAddr) -> usize {
        vaddr.to_pgtbl_idx::<LVL>()
    }

    /// Walks a page table at level 0 to find a mapping.
    ///
    /// # Parameters
    /// - `page`: A mutable reference to the root page table.
    /// - `vaddr`: The virtual address to find a mapping for.
    ///
    /// # Returns
    /// A `Mapping` representing the found mapping.
    fn walk_addr_lvl0(page: &mut PTPage<A, P>, vaddr: VirtAddr) -> Mapping<'_, A> {
        let idx = vaddr.to_pgtbl_idx::<0>();
        Mapping::new(PageLevel::Level0, &mut page[idx])
    }

    /// Walks a page table at level 1 to find a mapping.
    ///
    /// # Parameters
    /// - `page`: A mutable reference to the root page table.
    /// - `vaddr`: The virtual address to find a mapping for.
    ///
    /// # Returns
    /// A `Mapping` representing the found mapping.
    fn walk_addr_lvl1<'a>(page: &'a mut PTPage<A, P>, vaddr: VirtAddr) -> Mapping<'a, A> {
        let idx = vaddr.to_pgtbl_idx::<1>();
        let entry = page[idx];
        match PTPage::from_entry(entry) {
            Some(next) => Self::walk_addr_lvl0(next, vaddr),
            None => Mapping::new(PageLevel::Level1, &mut page[idx]),
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
    fn walk_addr_lvl2<'a>(page: &'a mut PTPage<A, P>, vaddr: VirtAddr) -> Mapping<'a, A> {
        let idx = vaddr.to_pgtbl_idx::<2>();
        let entry = page[idx];
        match PTPage::from_entry(entry) {
            Some(next) => Self::walk_addr_lvl1(next, vaddr),
            None => Mapping::new(PageLevel::Level2, &mut page[idx]),
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
    fn walk_addr_lvl3<'a>(page: &'a mut PTPage<A, P>, vaddr: VirtAddr) -> Mapping<'a, A> {
        let idx = vaddr.to_pgtbl_idx::<3>();
        let entry = page[idx];
        match PTPage::from_entry(entry) {
            Some(next) => Self::walk_addr_lvl2(next, vaddr),
            None => Mapping::new(PageLevel::Level3, &mut page[idx]),
        }
    }

    /// Walk the virtual address and return the corresponding mapping.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address to find a mapping for.
    ///
    /// # Returns
    /// A `Mapping` representing the found mapping.
    pub fn walk_addr(&mut self, vaddr: VirtAddr) -> Mapping<'_, A> {
        match L::TOP_LEVEL {
            PageLevel::Level3 => Self::walk_addr_lvl3(&mut self.root, vaddr),
            PageLevel::Level2 => Self::walk_addr_lvl2(&mut self.root, vaddr),
            _ => unreachable!(),
        }
    }
}

/// Methods that use the self-map to inspect the *active* top-level page table.
///
/// Self-mapped address calculations assume a PML4-rooted table.
impl<A: ArchPagingMeta, P: PagingHandler + SelfMap> GenericPageTable<A, P, PagingLevel3> {
    /// Install the self-map entry in a freshly zeroed page table.
    ///
    /// `paddr` is the physical address of *this* page table's root page.
    /// The self-map PML4 entry is written at [`SelfMap::SELFMAP_IDX`].
    pub fn init_self_map(&mut self, paddr: PhysAddr) {
        let entry = &mut self.root[P::SELFMAP_IDX];
        let flags = A::PTFlags::self_map_table_flags();
        entry.set(A::make_private_address(paddr), flags);
    }

    const fn pte_base_vaddr() -> VirtAddr {
        virt_from_lvl_idx(P::SELFMAP_IDX, PagingLevel3::TOP_LEVEL)
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
        Self::pte_base_vaddr() + ((usize::from(vaddr) & 0x0000_FFFF_FFFF_F000) >> PTE_SHIFT)
    }

    /// Perform a virtual to physical translation using the self-map.
    ///
    /// # Parameters
    /// - `vaddr': The virtual address to translate.
    ///
    /// # Returns
    /// Some(PageFrame) if the virtual address is valid.
    /// None if the virtual address is not valid.
    pub fn virt_to_frame(vaddr: VirtAddr) -> Option<PageFrame<A>> {
        let pte_addr = Self::get_pte_address(vaddr);
        let pde_addr = Self::get_pte_address(pte_addr);
        let pdpe_addr = Self::get_pte_address(pde_addr);
        let pml4e_addr = Self::get_pte_address(pdpe_addr);

        // SAFETY: Check each entry in the paging hierarchy to ensure it is
        // safe to read the next entry.
        let pml4e = unsafe { PTEntry::<A>::read_pte(pml4e_addr) };
        if !pml4e.present() {
            return None;
        }

        // There is no need to check for a large page in the PML4E because
        // the architecture does not support the large bit at the top-level
        // entry.  If a large page is detected at a lower level of the
        // hierarchy, the low bits from the virtual address must be combined
        // with the physical address from the PDE/PDPE.

        // SAFETY: The PML4E was checked to be present, so the PDPE exists
        // and can be read safely.
        let pdpe = unsafe { PTEntry::<A>::read_pte(pdpe_addr) };
        if !pdpe.present() {
            return None;
        }
        if pdpe.huge() {
            let pa = pdpe.page_frame() + (usize::from(vaddr) & 0x3FFF_FFFF);
            return Some(PageFrame::Size1G(pa, PhantomData));
        }

        // SAFETY: The PDPE was checked to be present and not to be a huge
        // page. So the PDE exists and can be read safely.
        let pde = unsafe { PTEntry::<A>::read_pte(pde_addr) };
        if !pde.present() {
            return None;
        }
        if pde.huge() {
            let pa = pde.page_frame() + (usize::from(vaddr) & 0x001F_FFFF);
            return Some(PageFrame::Size2M(pa));
        }

        // SAFETY: The PDE was checked to be present and not to be a huge
        // page. So the PTE exists and can be read safely.
        let pte = unsafe { PTEntry::<A>::read_pte(pte_addr) };
        if pte.present() {
            let pa = pte.page_frame() + (usize::from(vaddr) & 0xFFF);
            Some(PageFrame::Size4K(pa))
        } else {
            None
        }
    }
}

impl<A: ArchPagingMeta, P: PagingHandler, L: PagingLevel> GenericPageTable<A, P, L> {
    /// Allocate from level 3 (PML4E) down to the target level.
    fn alloc_pte_lvl3(entry: &mut PTEntry<A>, vaddr: VirtAddr, size: PageSize) -> Mapping<'_, A> {
        if entry.flags().contains(A::PTFlags::PRESENT) {
            return Mapping::new(PageLevel::Level3, entry);
        }

        let Ok((page, paddr)) = PTPage::<A, P>::alloc() else {
            return Mapping::new(PageLevel::Level3, entry);
        };

        entry.set(A::make_private_address(paddr), A::PTFlags::parent_flags());

        let idx = vaddr.to_pgtbl_idx::<2>();
        Self::alloc_pte_lvl2(&mut page[idx], vaddr, size)
    }

    /// Allocate from level 2 (PDPTE) down to the target level.
    fn alloc_pte_lvl2(entry: &mut PTEntry<A>, vaddr: VirtAddr, size: PageSize) -> Mapping<'_, A> {
        if entry.flags().contains(A::PTFlags::PRESENT) {
            return Mapping::new(PageLevel::Level2, entry);
        }

        let Ok((page, paddr)) = PTPage::<A, P>::alloc() else {
            return Mapping::new(PageLevel::Level2, entry);
        };

        entry.set(A::make_private_address(paddr), A::PTFlags::parent_flags());

        let idx = vaddr.to_pgtbl_idx::<1>();
        Self::alloc_pte_lvl1(&mut page[idx], vaddr, size)
    }

    /// Allocate from level 1 (PDE) down to level 0.
    /// Returns at level 1 if `size` is `Huge` (2 MiB page).
    fn alloc_pte_lvl1(entry: &mut PTEntry<A>, vaddr: VirtAddr, size: PageSize) -> Mapping<'_, A> {
        let flags = entry.flags();
        if size == PageSize::Huge || flags.contains(A::PTFlags::PRESENT) {
            return Mapping::new(PageLevel::Level1, entry);
        }

        let Ok((page, paddr)) = PTPage::<A, P>::alloc() else {
            return Mapping::new(PageLevel::Level1, entry);
        };

        entry.set(A::make_private_address(paddr), A::PTFlags::parent_flags());

        let idx = vaddr.to_pgtbl_idx::<0>();
        Mapping::new(PageLevel::Level0, &mut page[idx])
    }

    /// Allocates a 4KB page table entry for a given virtual address.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address for which to allocate the PTE.
    /// # Returns
    /// A `Mapping` representing the allocated or existing PTE for the address.
    fn alloc_pte_4k(&mut self, vaddr: VirtAddr) -> Mapping<'_, A> {
        let m = self.walk_addr(vaddr);
        match m.level {
            PageLevel::Level0 => m,
            PageLevel::Level1 => Self::alloc_pte_lvl1(m.entry, vaddr, PageSize::Regular),
            PageLevel::Level2 => Self::alloc_pte_lvl2(m.entry, vaddr, PageSize::Regular),
            PageLevel::Level3 => Self::alloc_pte_lvl3(m.entry, vaddr, PageSize::Regular),
        }
    }

    /// Allocates a 2MB page table entry for a given virtual address.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address for which to allocate the PTE.
    /// # Returns
    /// A `Mapping` representing the allocated or existing PTE for the address.
    fn alloc_pte_2m(&mut self, vaddr: VirtAddr) -> Mapping<'_, A> {
        let m = self.walk_addr(vaddr);
        match m.level {
            PageLevel::Level0 | PageLevel::Level1 => m,
            PageLevel::Level2 => Self::alloc_pte_lvl2(m.entry, vaddr, PageSize::Huge),
            PageLevel::Level3 => Self::alloc_pte_lvl3(m.entry, vaddr, PageSize::Huge),
        }
    }

    /// Splits a 2MB page into 4KB pages.
    ///
    /// # Parameters
    /// - `entry`: The 2M page table entry to split.
    ///
    /// # Returns
    /// A result indicating success or an error [`PagingError`] in failure.
    ///
    /// Does not flush the TLB itself: splitting only republishes the same
    /// physical range through a new subtable, so the resulting `PTEntry`
    /// still translates the same addresses. The caller who ultimately edits
    /// the split-out leaf is responsible for deciding whether that edit
    /// needs a flush, via the [`MayNeedFlush`] token it returns.
    fn do_split_4k(entry: &mut PTEntry<A>) -> Result<&mut PTPage<A, P>, PagingError> {
        let (page, paddr) = PTPage::<A, P>::alloc()?;
        let mut flags = entry.flags();

        assert!(flags.huge());

        let addr_2m = PhysAddr::from(entry.address().bits() & 0x000f_ffff_fff0_0000);

        flags.remove(A::PTFlags::HUGE);

        // Prepare PTE leaf page
        for (i, e) in page.entries.iter_mut().enumerate() {
            let addr_4k = addr_2m + (i * PAGE_SIZE);
            e.clear();
            e.set(A::make_private_address(addr_4k), flags);
        }

        entry.set(A::make_private_address(paddr), flags);

        Ok(page)
    }

    /// Splits a page into 4KB pages for a specific virtual address.
    ///
    /// # Parameters
    /// - `mapping`: The mapping to split.
    /// - `vaddr`: The virtual address for which to split the page.
    ///
    /// # Returns
    /// A result containing the updated mapping for the virtual address, or an error
    /// [`PagingError`] in failure.
    fn split_4k(mapping: Mapping<'_, A>, vaddr: VirtAddr) -> Result<Mapping<'_, A>, PagingError> {
        match mapping.level {
            PageLevel::Level0 => Ok(mapping),
            PageLevel::Level1 => {
                let next = Self::do_split_4k(mapping.entry)?;
                let idx = vaddr.to_pgtbl_idx::<0>();
                Ok(Mapping::new(PageLevel::Level0, &mut next.entries[idx]))
            }
            _ => Err(PagingError::NotMapped),
        }
    }

    fn make_pte_shared(entry: &mut PTEntry<A>) {
        let flags = entry.flags();
        let addr = entry.address();

        // entry.address() returned with c-bit clear already
        entry.set(A::make_shared_address(addr), flags);
    }

    fn make_pte_private(entry: &mut PTEntry<A>) {
        let flags = entry.flags();
        let addr = entry.address();

        // entry.address() returned with c-bit clear already
        entry.set(A::make_private_address(addr), flags);
    }

    /// Sets the shared state for a 4KB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address of the page.
    ///
    /// # Returns
    /// The [`MayNeedFlush`] TLB-flush obligation for the now-stale
    /// translation on success, or a [`PagingError`] on failure.
    pub fn set_shared_4k(
        &mut self,
        vaddr: VirtAddr,
    ) -> Result<MayNeedFlush<A::TlbFlushTok>, PagingError> {
        let mapping = self.walk_addr(vaddr);
        let old_level = mapping.level;

        // We create the copy to avoid updating reachable entries twice.
        let mut entry_copy = *mapping.entry;
        let mapping_copy = Mapping::new(old_level, &mut entry_copy);
        let mapping_4k = Self::split_4k(mapping_copy, vaddr)?;

        if let Mapping {
            level: PageLevel::Level0,
            entry,
        } = mapping_4k
        {
            Self::make_pte_shared(entry);

            // Update the original entry with the new address and flags.
            mapping.entry.clear();
            mapping.entry.set(entry_copy.address(), entry_copy.flags());
            if old_level != PageLevel::Level0 {
                // conservative: if we split a page, flush all TLB
                Ok(MayNeedFlush::all())
            } else {
                Ok(MayNeedFlush::new(vaddr, old_level))
            }
        } else {
            Err(PagingError::NotMapped)
        }
    }

    /// Sets the encryption state for a 4KB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address of the page.
    ///
    /// # Returns
    /// The [`MayNeedFlush`] TLB-flush obligation for the now-stale
    /// translation on success, or a [`PagingError`] on failure.
    pub fn set_encrypted_4k(
        &mut self,
        vaddr: VirtAddr,
    ) -> Result<MayNeedFlush<A::TlbFlushTok>, PagingError> {
        let mapping = self.walk_addr(vaddr);
        let old_level = mapping.level;

        // We create the copy to avoid updating reachable entries twice.
        let mut entry_copy = *mapping.entry;
        let mapping_copy = Mapping::new(old_level, &mut entry_copy);
        let mapping_4k = Self::split_4k(mapping_copy, vaddr)?;

        if let Mapping {
            level: PageLevel::Level0,
            entry,
        } = mapping_4k
        {
            Self::make_pte_private(entry);

            // Update the original entry with the new address and flags.
            mapping.entry.clear();
            mapping.entry.set(entry_copy.address(), entry_copy.flags());
            if old_level != PageLevel::Level0 {
                // conservative: if we split a page, flush all TLB
                Ok(MayNeedFlush::all())
            } else {
                Ok(MayNeedFlush::new(vaddr, old_level))
            }
        } else {
            Err(PagingError::NotMapped)
        }
    }

    /// Maps a 2MB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address to map.
    /// - `paddr`: The physical address to map to.
    /// - `flags`: The flags to apply to the mapping.
    /// - `shared`: Indicates whether the mapping is shared.
    ///
    /// # Returns
    /// A result indicating success or failure ([`PagingError`]).
    ///
    /// # Panics
    /// Panics if either `vaddr` or `paddr` is not aligned to a 2MB boundary.
    pub fn map_2m(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: A::PTFlags,
        shared: bool,
    ) -> Result<(), PagingError> {
        assert!(vaddr.is_aligned(PAGE_SIZE_2M));
        assert!(paddr.is_aligned(PAGE_SIZE_2M));
        let mapping = self.alloc_pte_2m(vaddr);
        let addr = if !shared {
            A::make_private_address(paddr)
        } else {
            A::make_shared_address(paddr)
        };

        if let Mapping {
            level: PageLevel::Level1,
            entry,
        } = mapping
        {
            assert!(!entry.present());
            entry.set(addr, flags | A::PTFlags::HUGE);
            Ok(())
        } else {
            Err(PagingError::AllocFrame)
        }
    }

    /// Unmaps a 2MB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address of the mapping to unmap.
    ///
    /// # Returns
    /// A copy of the [`PTEntry`] that mapped the virtual address together
    /// with the [`MayNeedFlush`] TLB-flush obligation for the now-stale
    /// translation, or [`None`] if no huge leaf was mapped.
    ///
    /// # Panics
    /// Panics if `vaddr` is not aligned to a 2MB boundary.
    pub fn unmap_2m(
        &mut self,
        vaddr: VirtAddr,
    ) -> (Option<PTEntry<A>>, MayNeedFlush<A::TlbFlushTok>) {
        assert!(vaddr.is_aligned(PAGE_SIZE_2M));

        let mapping = self.walk_addr(vaddr);

        let level = mapping.level;
        match mapping.level {
            PageLevel::Level0 => unreachable!(),
            PageLevel::Level1 => {
                let entry = *mapping.entry;
                mapping.entry.clear();
                (Some(entry), MayNeedFlush::new(vaddr, level))
            }
            _ => {
                assert!(!mapping.entry.present());
                (None, MayNeedFlush::none())
            }
        }
    }

    /// Maps a 4KB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address to map.
    /// - `paddr`: The physical address to map to.
    /// - `flags`: The flags to apply to the mapping.
    /// - `shared`: Indicates whether the mapping is shared.
    /// # Returns
    /// A result indicating success or failure ([`PagingError`]).
    pub fn map_4k(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: A::PTFlags,
        shared: bool,
    ) -> Result<(), PagingError> {
        let mapping = self.alloc_pte_4k(vaddr);
        let addr = if !shared {
            A::make_private_address(paddr)
        } else {
            A::make_shared_address(paddr)
        };

        if let Mapping {
            level: PageLevel::Level0,
            entry,
        } = mapping
        {
            assert!(!entry.present());
            entry.set(addr, flags);
            Ok(())
        } else {
            Err(PagingError::AllocFrame)
        }
    }

    /// Unmaps a 4KB page.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address of the mapping to unmap.
    ///
    /// # Returns
    /// A copy of the [`PTEntry`] that mapped the virtual address together
    /// with the [`MayNeedFlush`] TLB-flush obligation for the now-stale
    /// translation, or [`None`] if no leaf was mapped.
    pub fn unmap_4k(
        &mut self,
        vaddr: VirtAddr,
    ) -> (Option<PTEntry<A>>, MayNeedFlush<A::TlbFlushTok>) {
        let mapping = self.walk_addr(vaddr);
        let level = mapping.level;

        match mapping.level {
            PageLevel::Level0 => {
                let entry = *mapping.entry;
                mapping.entry.clear();
                (Some(entry), MayNeedFlush::new(vaddr, level))
            }
            _ => {
                assert!(!mapping.entry.present());
                (None, MayNeedFlush::none())
            }
        }
    }

    /// Maps the half-open virtual range `[start, end)` using 4KB pages,
    /// starting at physical address `phys`.
    ///
    /// # Returns
    /// A result indicating success or failure ([`PagingError`]).
    pub fn map_region_4k(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
        phys: PhysAddr,
        flags: A::PTFlags,
        shared: bool,
    ) -> Result<(), PagingError> {
        let mut vaddr = start;
        while vaddr < end {
            let offset = vaddr - start;
            self.map_4k(vaddr, phys + offset, flags, shared)?;
            vaddr = vaddr + PAGE_SIZE;
        }
        Ok(())
    }

    /// Unmaps the half-open virtual range `[start, end)` mapped with 4KB
    /// pages, returning the combined [`MayNeedFlush`] TLB-flush obligation.
    pub fn unmap_region_4k(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
    ) -> MayNeedFlush<A::TlbFlushTok> {
        let mut flush = MayNeedFlush::none();
        let mut vaddr = start;
        while vaddr < end {
            let (_, f) = self.unmap_4k(vaddr);
            flush = flush.and(f);
            vaddr = vaddr + PAGE_SIZE;
        }
        flush
    }

    /// Maps the half-open virtual range `[start, end)` using 2MB pages,
    /// starting at physical address `phys`.
    ///
    /// # Returns
    /// A result indicating success or failure ([`PagingError`]).
    pub fn map_region_2m(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
        phys: PhysAddr,
        flags: A::PTFlags,
        shared: bool,
    ) -> Result<(), PagingError> {
        let mut vaddr = start;
        while vaddr < end {
            let offset = vaddr - start;
            self.map_2m(vaddr, phys + offset, flags, shared)?;
            vaddr = vaddr + PAGE_SIZE_2M;
        }
        Ok(())
    }

    /// Unmaps the half-open virtual range `[start, end)` mapped with 2MB
    /// pages, returning the combined [`MayNeedFlush`] TLB-flush obligation.
    ///
    /// The range must be 2MB-aligned and correspond to a set of huge mappings.
    pub fn unmap_region_2m(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
    ) -> MayNeedFlush<A::TlbFlushTok> {
        let mut flush = MayNeedFlush::none();
        let mut vaddr = start;
        while vaddr < end {
            let (_, f) = self.unmap_2m(vaddr);
            flush = flush.and(f);
            vaddr = vaddr + PAGE_SIZE_2M;
        }
        flush
    }

    /// Maps the half-open virtual range `[start, end)` to physical memory
    /// starting at `phys`, preferring 2MB pages where alignment and size
    /// allow and falling back to 4KB pages otherwise.
    ///
    /// # Returns
    /// A result indicating success or failure ([`PagingError`]).
    pub fn map_region(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
        phys: PhysAddr,
        flags: A::PTFlags,
    ) -> Result<(), PagingError> {
        let mut vaddr = start;
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

    /// Unmaps the half-open virtual range `[start, end)`, clearing both 4KB
    /// and 2MB leaf entries.
    ///
    /// # Returns
    /// 1. whether every page in the range was mapped (`true`) or not (`false`).
    /// 2. a [`MayNeedFlush`] indicating which TLB entries may need to be flushed.
    ///
    /// All mapped pages in the range are unmapped regardless.
    pub fn unmap_region(
        &mut self,
        start: VirtAddr,
        end: VirtAddr,
    ) -> (bool, MayNeedFlush<A::TlbFlushTok>) {
        let mut vaddr = start;
        let mut was_mapped = true;
        let mut flush = MayNeedFlush::none();
        while vaddr < end {
            let mapping = self.walk_addr(vaddr);
            let local_flush = MayNeedFlush::new(vaddr, mapping.level);
            match mapping.level {
                PageLevel::Level0 => {
                    mapping.entry.clear();
                    vaddr = vaddr + PAGE_SIZE;
                    flush = flush.and(local_flush);
                }
                level if mapping.entry.present() && mapping.entry.huge() => {
                    mapping.entry.clear();
                    vaddr = vaddr + level.size();
                    flush = flush.and(local_flush);
                }
                _ => {
                    was_mapped = false;
                    vaddr = vaddr + PAGE_SIZE;
                }
            }
        }

        (was_mapped, flush)
    }

    /// Retrieves the physical address of a mapping.
    ///
    /// # Parameters
    /// - `vaddr`: The virtual address to query.
    ///
    /// # Returns
    /// The physical address of the mapping if present; otherwise, an error
    /// ([`PagingError`]).
    pub fn phys_addr(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, PagingError> {
        let mapping = self.walk_addr(vaddr);

        match mapping.level {
            PageLevel::Level0 => {
                let offset = vaddr.page_offset();
                let entry = mapping.entry;
                if !entry.present() {
                    return Err(PagingError::NotMapped);
                }
                Ok(entry.address() + offset)
            }
            PageLevel::Level1 => {
                let offset = vaddr.bits() & (PAGE_SIZE_2M - 1);
                let entry = mapping.entry;
                if !entry.present() || !entry.huge() {
                    return Err(PagingError::NotMapped);
                }
                Ok(entry.address() + offset)
            }
            _ => Err(PagingError::NotMapped),
        }
    }
}

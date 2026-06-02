// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generic paging traits and marker types.

use crate::address::{Address, PhysAddr, VirtAddr};
use bitflags::Flags;
use zerocopy::FromBytes;

/// Page table levels (0-based).
///
/// Level0 is the leaf (PTE), Level3 is the root of 4-level paging (PML4E).
/// At most 4 levels are supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
pub enum PageLevel {
    Level0 = 0,
    Level1 = 1,
    Level2 = 2,
    Level3 = 3,
}

impl PageLevel {
    /// Returns the next level down, or `None` at Level0.
    pub fn next_down(self) -> Option<Self> {
        match self {
            Self::Level3 => Some(Self::Level2),
            Self::Level2 => Some(Self::Level1),
            Self::Level1 => Some(Self::Level0),
            Self::Level0 => None,
        }
    }
}

/// Describes how many levels a page table hierarchy has.
///
/// `TOP_LEVEL` is the highest (root) level, up to [`PageLevel::Level3`]
/// (i.e. at most 4 levels: L0-L3).
///
/// Architecture-specific ZSTs that implement this trait live in their
/// respective modules (e.g. `x86_64::Pml4Level`).
pub trait PagingLevel {
    /// Highest page table level.
    const TOP_LEVEL: PageLevel;
}

#[derive(Debug)]
pub struct PagingLevel3;

impl PagingLevel for PagingLevel3 {
    const TOP_LEVEL: PageLevel = PageLevel::Level3;
}

#[derive(Debug)]
pub struct PagingLevel2;

impl PagingLevel for PagingLevel2 {
    const TOP_LEVEL: PageLevel = PageLevel::Level2;
}

/// Errors that can occur during page table operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PagingError {
    /// Frame allocation failed.
    AllocFrame,
    /// The requested virtual address is not mapped.
    NotMapped,
}

/// Architecture-specific page table metadata for confidential computing.
///
/// Defines how encryption/confidentiality bits are managed in page table
/// entries. On AMD SEV-SNP the private mask is the C-bit and the shared mask
/// is zero (or vice-versa depending on convention). On platforms without
/// memory encryption both masks are zero.
///
/// # Required methods
///
/// * [`private_pte_mask`](Self::private_pte_mask) — bitmask ORed into PTEs
///   for private (encrypted) mappings.
/// * [`shared_pte_mask`](Self::shared_pte_mask) — bitmask ORed into PTEs
///   for shared (plaintext) mappings.
/// * [`flush_tlb_global`](Self::flush_tlb_global) — flush the TLB on all
///   CPUs; called after splitting or changing the encryption state of a page.
///
/// # Default methods
///
/// The remaining methods (`strip_*`, `make_*`, `is_shared_address`,
/// `supported_flags`) have default implementations derived from the masks.
/// Override only if the platform requires non-standard behaviour.
///
/// # Implementer requirements
///
/// * All methods must be stateless (no `&self`) — the type is used as a
///   zero-sized marker and never instantiated.
/// * `private_pte_mask` and `shared_pte_mask` must not share any set bits —
///   a page is either private *or* shared.
/// * `make_private_address` and `make_shared_address` must be idempotent.
pub trait ArchPagingMeta: 'static + Copy {
    type PTFlags: GenericPageTableFlags;

    /// Returns the bitmask ORed into physical addresses for private
    /// (encrypted) page table entries.
    fn private_pte_mask() -> usize;

    /// Returns the bitmask ORed into physical addresses for shared
    /// (plaintext) page table entries.
    fn shared_pte_mask() -> usize;

    /// Physical address mask.
    /// x64 supports 52-bit physical addresses, so the mask is usually 0x000f_ffff_ffff_f000.
    fn address_mask() -> usize;

    /// Flush the TLB globally and synchronize across all CPUs.
    ///
    /// Called after modifying live PTEs (e.g., splitting a 2M page or
    /// toggling the encryption state of a mapping).
    fn flush_tlb_global();

    /// Returns a bitmask of PTEntryFlags that the hardware supports.
    ///
    /// Override this method to filter unsupported bits (e.g., `GLOBAL` before CR4.PGE is enabled)
    /// so that they are silently cleared. The default allows all flags.
    fn supported_flags() -> Self::PTFlags {
        Self::PTFlags::all()
    }

    /// Clears the private encryption bit(s) from `paddr`.
    fn strip_confidentiality_bits(paddr: PhysAddr) -> PhysAddr {
        (paddr.bits() & !Self::private_pte_mask()).into()
    }

    /// Clears the shared bit(s) from `paddr`.
    fn strip_shared_address_bits(paddr: PhysAddr) -> PhysAddr {
        (paddr.bits() & !Self::shared_pte_mask()).into()
    }

    /// Returns `paddr` with the private encryption mask applied.
    ///
    /// Any shared bits are stripped first so the result is exclusively
    /// private.
    fn make_private_address(paddr: PhysAddr) -> PhysAddr {
        (Self::strip_shared_address_bits(paddr).bits() | Self::private_pte_mask()).into()
    }

    /// Returns `paddr` with the shared mask applied.
    ///
    /// Any confidentiality (private) bits are stripped first so the result
    /// is exclusively shared.
    fn make_shared_address(paddr: PhysAddr) -> PhysAddr {
        (Self::strip_confidentiality_bits(paddr).bits() | Self::shared_pte_mask()).into()
    }

    /// Returns `true` if `paddr` already has the shared mask applied.
    fn is_shared_address(paddr: PhysAddr) -> bool {
        paddr == Self::make_shared_address(paddr)
    }
}

/// OS-level page table services: address translation and frame management.
///
/// Bridges the generic page table code to the OS memory allocator and
/// virtual-address layout. Every method is an associated function (no
/// `&self`) — the implementing type is used as a zero-sized marker and
/// never instantiated.
///
/// # Safety
///
/// Implementers must guarantee:
///
/// * **`paddr_to_vaddr`** — the returned virtual address is a valid,
///   dereferenceable mapping of `paddr` for the lifetime of the page table.
///   `paddr` is always a *clean* physical address (no encryption bits).
///
/// * **`allocate_physical_page`** — every successful call returns a *unique*,
///   page-aligned, *zeroed* physical frame whose address is *clean* (no
///   encryption/confidentiality bits). The frame remains valid until a
///   matching `deallocate_physical_page` call.
///
/// * **`deallocate_physical_page`** — `paddr` is a value previously returned by
///   `allocate_physical_page` that has not yet been freed.
///
/// # Cross-method invariant
///
/// `paddr_to_vaddr` must return a valid, writable mapping for every
/// address returned by `allocate_physical_page`. The generic page table code
/// calls `allocate_physical_page` and immediately passes the result to
/// `paddr_to_vaddr` in order to zero-initialise and populate newly
/// allocated page table pages. This invariant can be satisfied either
/// by a linear map of all physical memory (so `paddr_to_vaddr` works
/// for any physical address) or by having `allocate_physical_page` return only
/// frames that are already mapped.
pub unsafe trait PagingHandler: 'static + FromBytes {
    /// Translate a clean physical address to a virtual address suitable for
    /// accessing page table pages.
    fn paddr_to_vaddr(paddr: PhysAddr) -> VirtAddr;

    /// Allocate a zeroed page-table frame.
    ///
    /// Returns the *clean* physical address of the frame — no encryption
    /// or confidentiality bits are set. Callers apply
    /// [`ArchPagingMeta::make_private_address`] when storing the address
    /// in a PTE.
    fn allocate_physical_page() -> Result<PhysAddr, PagingError>;

    /// Deallocate a page-table frame previously returned by
    /// [`allocate_physical_page`](Self::allocate_physical_page).
    ///
    /// # Safety
    ///
    /// `paddr` must be a clean physical address previously returned by
    /// `allocate_physical_page` and not yet freed.
    unsafe fn deallocate_physical_page(paddr: PhysAddr);
}

/// Self-map support for page tables.
///
/// When a page table contains a self-map entry (a PML4 entry that points
/// back to the page table root), the CPU's address translation creates a
/// virtual window through which every PTE of the *active* page table can
/// be read and written at a known virtual address.
///
/// # Implementer requirements
///
/// * `PTE_BASE_VADDR` must return the virtual base address of that self-map
///   window. For a self-map installed at PML4 index *N*, this is
///   `sign_extend(N << 39 | N << 30 | N << 21 | N << 12)`.
/// * The self-map entry must be installed before any method in the
///   `impl<..., P: PagingHandler + SelfMap>` block is called.
pub trait SelfMap {
    /// The PML4 index of the self-map entry.
    const SELFMAP_IDX: usize;
}

pub trait GenericPageTableFlags:
    bitflags::Flags<Bits = usize>
    + core::ops::BitAnd<Output = Self>
    + core::ops::BitOr<Output = Self>
    + Copy
    + Clone
{
    const PRESENT: Self;
    const USER: Self;
    const HUGE: Self;

    /// Default flags for newly created parent page table entries.
    ///
    /// These flags must be permissive enough to form a superset of all
    /// possible descendant leaf entry permissions, since effective access
    /// rights are constrained by both parent and leaf entries.
    fn parent_flags() -> Self;

    /// Flags for the self-map entry itself. This may differ from `parent_flags`
    fn self_map_table_flags() -> Self;

    fn huge(&self) -> bool {
        self.contains(Self::HUGE)
    }

    fn present(&self) -> bool {
        self.contains(Self::PRESENT)
    }

    fn user(&self) -> bool {
        self.contains(Self::USER)
    }
}

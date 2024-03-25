// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{PhysAddr, VirtAddr};
use crate::error::SvsmError;
use crate::globalbox_upcast;
use crate::locking::{RWLock, ReadLockGuard, WriteLockGuard};
use crate::mm::pagetable::PTEntryFlags;
use crate::mm::vm::VMR;
use crate::mm::GlobalBox;
use crate::types::{PageSize, PAGE_SHIFT};
use core::fmt;
use core::marker::PhantomData;

use intrusive_collections::rbtree::Link;
use intrusive_collections::{
    container_of, offset_of, Adapter, DefaultLinkOps, KeyAdapter, LinkOps, PointerOps,
};

use core::ops::Range;

extern crate alloc;
use alloc::sync::Arc;

/// Information required to resolve a page fault within a virtual mapping
#[derive(Debug, Copy, Clone)]
pub struct VMPageFaultResolution {
    /// The physical address of a page that must be mapped to the page fault
    /// virtual address to resolve the page fault.
    pub paddr: PhysAddr,

    /// The flags to use to map the virtual memory page.
    pub flags: PTEntryFlags,
}

pub trait VirtualMapping: fmt::Debug {
    /// Request the size of the virtual memory mapping
    ///
    /// # Returns
    ///
    /// Mapping size. Will always be a multiple of `VirtualMapping::page_size()`
    fn mapping_size(&self) -> usize;

    /// Indicates whether the mapping has any associated data.
    ///
    /// # Returns
    ///
    /// `true' if there is associated physical data, or `false' if there is
    /// none.
    fn has_data(&self) -> bool {
        // Defaults to true
        true
    }

    /// Request physical address to map for a given offset
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset into the virtual memory mapping
    ///
    /// # Returns
    ///
    /// Physical address to map for the given offset, if any. None is also a
    /// valid return value and does not indicate an error.
    fn map(&self, offset: usize) -> Option<PhysAddr>;

    /// Inform the virtual memory mapping about an offset being unmapped.
    /// Implementing `unmap()` is optional.
    ///
    /// # Arguments
    ///
    /// * `_offset`
    fn unmap(&self, _offset: usize) {
        // Provide default in case there is nothing to do
    }

    /// Request the PTEntryFlags used for this virtual memory mapping.
    ///
    /// # Arguments
    ///
    /// * 'offset' -> The offset in bytes into the `VirtualMapping`. The flags
    ///               returned from this function relate to the page at the
    ///               given offset
    ///
    /// # Returns
    ///
    /// A combination of:

    /// * PTEntryFlags::WRITABLE
    /// * PTEntryFlags::NX,
    /// * PTEntryFlags::ACCESSED
    /// * PTEntryFlags::DIRTY
    fn pt_flags(&self, offset: usize) -> PTEntryFlags;

    /// Request the page size used for mappings
    ///
    /// # Returns
    ///
    /// Either PAGE_SIZE or PAGE_SIZE_2M
    fn page_size(&self) -> PageSize {
        // Default to system page-size
        PageSize::Regular
    }

    /// Request whether the mapping is shared or private. Defaults to private
    /// unless overwritten by the specific type.
    ///
    /// # Returns
    ///
    /// * `True` - When mapping is shared
    /// * `False` - When mapping is private
    fn shared(&self) -> bool {
        // Shared with the HV - defaults not No
        false
    }

    /// Handle a page fault that occurred on a virtual memory address within
    /// this mapping.
    ///
    /// # Arguments
    ///
    /// * 'vmr' - Virtual memory range that contains the mapping. This
    ///           [`VirtualMapping`] can use this to insert/remove regions
    ///           as necessary to handle the page fault.
    ///
    /// * `offset` - Offset into the virtual mapping that was the subject of
    ///              the page fault.
    ///
    /// * 'write' - `true` if the fault was due to a write to the memory
    ///              location, or 'false' if the fault was due to a read.
    fn handle_page_fault(
        &mut self,
        _vmr: &VMR,
        _offset: usize,
        _write: bool,
    ) -> Result<VMPageFaultResolution, SvsmError> {
        Err(SvsmError::Mem)
    }
}

#[derive(Debug)]
pub struct Mapping {
    mapping: RWLock<GlobalBox<dyn VirtualMapping>>,
}

unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}

impl Mapping {
    pub fn new<T>(mapping: T) -> Result<Self, SvsmError>
    where
        T: VirtualMapping + 'static,
    {
        let boxed = globalbox_upcast!(GlobalBox::try_new(mapping)?, VirtualMapping);
        Ok(Self {
            mapping: RWLock::new(boxed),
        })
    }

    pub fn get(&self) -> ReadLockGuard<'_, GlobalBox<dyn VirtualMapping>> {
        self.mapping.lock_read()
    }

    pub fn get_mut(&self) -> WriteLockGuard<'_, GlobalBox<dyn VirtualMapping>> {
        self.mapping.lock_write()
    }
}

/// A single mapping of virtual memory in a virtual memory range
#[derive(Debug)]
pub struct VMM {
    /// Link for storing this instance in an RBTree
    link: Link,

    /// The virtual memory range covered by this mapping
    /// It is stored in a RefCell to check borrowing rules at runtime.
    /// This is safe as any modification to `range` is protected by a lock in
    /// the parent data structure. This is required because changes here also
    /// need changes in the parent data structure.
    range: Range<usize>,

    /// Pointer to the actual mapping
    /// It is protected by an RWLock to serialize concurent accesses.
    mapping: Arc<Mapping>,
}

impl VMM {
    /// Create a new VMM instance with at a given address and backing struct
    ///
    /// # Arguments
    ///
    /// * `start_pfn` - Virtual start pfn to store in the mapping
    /// * `mapping` - `Arc<Mapping>` pointer to the backing struct
    ///
    /// # Returns
    ///
    /// New instance of VMM
    pub fn new(start_pfn: usize, mapping: Arc<Mapping>) -> Self {
        let size = mapping.get().mapping_size() >> PAGE_SHIFT;
        VMM {
            link: Link::new(),
            range: Range {
                start: start_pfn,
                end: start_pfn + size,
            },
            mapping,
        }
    }

    /// Request the mapped range as page frame numbers
    ///
    /// # Returns
    ///
    /// The start and end (non-inclusive) virtual address for this virtual
    /// mapping, right-shifted by `PAGE_SHIFT`.
    pub fn range_pfn(&self) -> (usize, usize) {
        (self.range.start, self.range.end)
    }

    /// Request the mapped range
    ///
    /// # Returns
    ///
    /// The start and end virtual address for this virtual mapping.
    pub fn range(&self) -> (VirtAddr, VirtAddr) {
        (
            VirtAddr::from(self.range.start << PAGE_SHIFT),
            VirtAddr::from(self.range.end << PAGE_SHIFT),
        )
    }

    pub fn get_mapping(&self) -> ReadLockGuard<'_, GlobalBox<dyn VirtualMapping>> {
        self.mapping.get()
    }

    pub fn get_mapping_mut(&self) -> WriteLockGuard<'_, GlobalBox<dyn VirtualMapping>> {
        self.mapping.get_mut()
    }

    pub fn get_mapping_clone(&self) -> Arc<Mapping> {
        self.mapping.clone()
    }
}

/// A simple newtype wrapper around a [`PhantomData`] used as a workaround for
/// Rust's orphan rules, in order to implement [`PointerOps`].
///
/// Does a similar job as [`DefaultPointerOps`](intrusive_collections::DefaultPointerOps).
#[derive(Debug, Clone, Copy, Default)]
pub struct CustomPointerOps<T>(PhantomData<T>);

impl<T> CustomPointerOps<T> {
    const NEW: Self = Self(PhantomData);
}

/// An implementation of [`PointerOps`] for [`CustomPointerOps<GlobalBox<T>>`]
/// similar to the one for [`DefaultPointerOps<Box<T>>`](intrusive_collections::DefaultPointerOps).
unsafe impl<T> PointerOps for CustomPointerOps<GlobalBox<T>> {
    type Value = T;
    type Pointer = GlobalBox<T>;

    #[inline]
    unsafe fn from_raw(&self, raw: *const Self::Value) -> Self::Pointer {
        GlobalBox::from_raw(raw as *mut _)
    }

    #[inline]
    fn into_raw(&self, ptr: Self::Pointer) -> *const Self::Value {
        GlobalBox::into_raw(ptr)
    }
}

/// An adapter to insert a [`VMM`] in an intrusive collection, similar to the
/// one generated by the [`intrusive_adapter`](intrusive_collections::intrusive_adapter)
/// macro.
pub struct VMMAdapter {
    link_ops: <Link as DefaultLinkOps>::Ops,
    pointer_ops: CustomPointerOps<GlobalBox<VMM>>,
}

#[allow(dead_code)]
impl VMMAdapter {
    pub const NEW: Self = VMMAdapter {
        link_ops: <Link as DefaultLinkOps>::NEW,
        pointer_ops: CustomPointerOps::NEW,
    };

    #[inline]
    pub fn new() -> Self {
        Self::NEW
    }
}

impl Default for VMMAdapter {
    #[inline]
    fn default() -> Self {
        Self::NEW
    }
}

// Implement this manually because we have `deny(missing_debug_implementations)`
// but `link_ops` does not implement Debug.
impl fmt::Debug for VMMAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("VMMAdapter")
            .field("link_ops", &"_")
            .field("pointer_ops", &"_")
            .finish()
    }
}

/// Allows a [`VMM`] to be introduced in an intrusive collection. This is a
/// manual implementation of the code generated by the
/// [`intrusive_adapter`](intrusive_collections::intrusive_adapter) macro.
unsafe impl Adapter for VMMAdapter {
    type LinkOps = <Link as DefaultLinkOps>::Ops;
    type PointerOps = CustomPointerOps<GlobalBox<VMM>>;

    #[inline]
    unsafe fn get_value(
        &self,
        link: <Self::LinkOps as LinkOps>::LinkPtr,
    ) -> *const <Self::PointerOps as PointerOps>::Value {
        container_of!(link.as_ptr(), VMM, link)
    }

    #[inline]
    unsafe fn get_link(
        &self,
        value: *const <Self::PointerOps as PointerOps>::Value,
    ) -> <Self::LinkOps as LinkOps>::LinkPtr {
        let ptr = (value as *const u8).add(offset_of!(VMM, link));
        core::ptr::NonNull::new_unchecked(ptr as *mut _)
    }

    #[inline]
    fn link_ops(&self) -> &Self::LinkOps {
        &self.link_ops
    }

    #[inline]
    fn link_ops_mut(&mut self) -> &mut Self::LinkOps {
        &mut self.link_ops
    }

    #[inline]
    fn pointer_ops(&self) -> &Self::PointerOps {
        &self.pointer_ops
    }
}

impl<'a> KeyAdapter<'a> for VMMAdapter {
    type Key = usize;
    fn get_key(&self, node: &'a VMM) -> Self::Key {
        node.range.start
    }
}

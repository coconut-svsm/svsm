// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// Defines memory region permissions.
verus! {

spec fn spec_map_page_info_addr(map: LinearMap, pfn: usize) -> VirtAddr {
    let reserved_unit_size = size_of::<PageStorageType>();
    let start = map.virt_start;
    VirtAddr::from_spec((start@ + (pfn * reserved_unit_size)) as usize)
}

spec fn spec_map_page_info_ptr(map: LinearMap, pfn: usize) -> *const PageStorageType {
    let addr = spec_map_page_info_addr(map, pfn)@;
    vstd::raw_ptr::ptr_from_data(
        vstd::raw_ptr::PtrData { addr, provenance: allocator_provenance(), metadata: () },
    )
}

/// Defines ghost tracked memory region permissions.
///
/// `info` is a readonly share of reserved memory storing PageInfo which allows
/// the allocator to access the page info of all pfns in this region at any
/// time.
///
/// `free` contains permissions related to all free memory pages. Each memory
/// page should have the full permission to access the free memory page in this
/// region, and all remaining permission shares of page info for the free page.
/// Thus the allocator will be able to recover the full share of permission to
/// modify the PageInfo when the memory is not allocated. When allocating a
/// memory, the allocator will give one such permission set to the external.
///
/// `mr_map` defines all remaining shares of memory mapping permission for this
/// region. If the allocator has not yet allocated any memory, the allocator
/// will be able to merge all memory mapping permission to change the desired
/// base pointer and mapping for this region. If the allocator has allocated
/// memory, the allocator will not be able to change the base pointer and
/// mapping for this region.
tracked struct MemoryRegionPerms {
    info: PageInfoDb,  // readonly share of pginfo for all pfns in this region.
    free: MRFreePerms,  // free mem perms + remaining share of pginfo
    info_ptr_exposed: IsExposed,  // provenance of this region.
    mr_map: MemRegionMapping,  // The memory mapping for this region.
}

/// Defines the permission returned by the allocator when allocating memory.
#[allow(missing_debug_implementations)]
pub tracked struct AllocatedPagesPerm {
    perm: PgUnitPerm<DeallocUnit>,
    mr_map: MemRegionMapping,
}

impl AllocatedPagesPerm {
    spec fn pfn(&self) -> usize {
        self.perm.info.unit_start()
    }

    spec fn with_vaddr(&self, vaddr: VirtAddr) -> bool {
        self.mr_map@.map.get_pfn(vaddr) == Some(self.pfn())
    }

    spec fn vaddr(&self) -> VirtAddr {
        self.mr_map@.map.try_get_virt(self.pfn()).unwrap()
    }

    spec fn size(&self) -> nat {
        (self.perm.info.npages() * PAGE_SIZE as nat)
    }

    #[verifier::type_invariant]
    spec fn wf(&self) -> bool {
        let order = self.perm.info.order();
        let pfn = self.pfn();
        &&& order < MAX_ORDER
        &&& self.mr_map.pg_params().valid_pfn_order(pfn, order)
        &&& self.mr_map.shares() == self.size()
        &&& self.mr_map.base_ptr() === self.perm.info.base_ptr()
        &&& self.perm.wf_pfn_order(self.mr_map, pfn, order)
        &&& self.perm.page_type().spec_is_deallocatable()
    }
}

#[allow(missing_debug_implementations)]
pub ghost struct AllocatorUnit {}

#[allow(missing_debug_implementations)]
pub ghost struct DeallocUnit {}

pub trait UnitType {
    spec fn wf_share_total(shares: nat, total: nat) -> bool;
}

/// Defines the number of shares of PageInfo permission for deallocatable unit
/// for (to-be) allocated memory.
impl UnitType for DeallocUnit {
    closed spec fn wf_share_total(shares: nat, total: nat) -> bool {
        &&& shares == DEALLOC_PGINFO_SHARES
        &&& total == MAX_PGINFO_SHARES
        &&& 0 < shares < total
    }
}

/// Defines the number of shares of PageInfo permission remains in the allocator.
impl UnitType for AllocatorUnit {
    closed spec fn wf_share_total(shares: nat, total: nat) -> bool {
        &&& shares == total - DEALLOC_PGINFO_SHARES
        &&& total == MAX_PGINFO_SHARES
        &&& 0 < shares < total
    }
}

#[allow(missing_debug_implementations)]
pub tracked struct PgUnitPerm<T: UnitType> {
    mem: RawPerm,
    info: PageInfoDb,
    ghost typ: T,
}

#[allow(missing_debug_implementations)]
pub tracked struct UnitDeallocPerm(PgUnitPerm<DeallocUnit>);

impl UnitDeallocPerm {
    pub closed spec fn view(&self) -> PgUnitPerm<DeallocUnit> {
        self.0
    }
}

impl<T: UnitType> PgUnitPerm<T> {
    #[verifier::type_invariant]
    pub closed spec fn wf(&self) -> bool {
        &&& self.info.npages() > 0 ==> self.info.is_unit()
        &&& self.info.npages() > 0 ==> T::wf_share_total(
            self.info.id().shares,
            self.info.id().total,
        )
    }

    pub closed spec fn pfn(&self) -> usize {
        self.info.unit_start()
    }

    #[verifier(inline)]
    spec fn page_info(&self) -> Option<PageInfo> {
        self.info.unit_head().page_info()
    }

    spec fn page_type(&self) -> PageType {
        let pageinfo = self.info.unit_head().page_info().unwrap();
        pageinfo.spec_type()
    }

    pub closed spec fn from_mr(&self, map: MemRegionMapping, pfn: usize, order: usize) -> bool {
        self.wf_pfn_order(map, pfn, order)
    }

    pub closed spec fn wf_pfn_order(
        &self,
        map: MemRegionMapping,
        pfn: usize,
        order: usize,
    ) -> bool {
        &&& self.mem.wf_pfn_order(map, pfn, order)
        &&& self.info.unit_start() == pfn
        &&& self.info.order() == order
        &&& self.info.base_ptr() === map.base_ptr()
        &&& !self.info@.is_empty()
    }

    proof fn empty(id: PInfoGroupId) -> (tracked ret: Self) {
        PgUnitPerm {
            mem: RawPerm::empty(id.ptr_data.provenance),
            info: PageInfoDb::tracked_empty(id),
            typ: arbitrary(),
        }
    }

    proof fn tracked_take(tracked &mut self) -> (tracked ret: (RawPerm, PageInfoDb))
        ensures
            ret == (old(self).mem, old(self).info),
            ret.1.npages() > 0 ==> ret.1.is_unit(),
            ret.1.npages() > 0 ==> T::wf_share_total(ret.1.id().shares, ret.1.id().total),
            ret.1.wf(),
    {
        use_type_invariant(&*self);
        let tracked mut tmp = PgUnitPerm::empty(self.info.id);
        tracked_swap(self, &mut tmp);
        use_type_invariant(&tmp.info);
        (tmp.mem, tmp.info)
    }
}

impl MemoryRegionPerms {
    spec fn npages(&self) -> usize {
        self.mr_map.pg_params().page_count
    }

    spec fn map(&self) -> LinearMap {
        self.mr_map@.map
    }

    spec fn base_ptr(&self) -> *const PageStorageType {
        self.mr_map.base_ptr()
    }

    spec fn wf_base_ptr(&self) -> bool {
        &&& self.mr_map@ == self.free.mr_map()@
        &&& self.info_ptr_exposed@ == self.mr_map@.provenance
        &&& self.info.base_ptr() == self.base_ptr()
    }

    spec fn page_info_ptr(&self, pfn: usize) -> *const PageStorageType {
        self.base_ptr().add(pfn)
    }

    #[verifier(inline)]
    spec fn get_info(&self, pfn: usize) -> Option<PageInfo> {
        self.info@[pfn].page_info()
    }

    #[verifier(inline)]
    spec fn get_free_info(&self, pfn: usize) -> Option<FreeInfo> {
        self.info@[pfn].page_info().unwrap().spec_get_free()
    }

    spec fn get_page_storage_type(&self, pfn: usize) -> Option<PageStorageType> {
        self.info@[pfn].page_storage()
    }

    /** Invariants for page info **/
    spec fn wf_info(&self) -> bool {
        let info = self.info;
        &&& info.is_readonly_allocator_shares()
        &&& self.npages() == info.npages()
        &&& info@.dom() =~= Set::new(|idx| 0 <= idx < self.npages())
        &&& self.wf_base_ptr()
    }

    spec fn wf(&self) -> bool {
        self.wf_info()
    }
}

} // verus!

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// This module defines specification functions for MemoryRegion implementations
//
// How the proof works:
// - Upon entry to the SVSM (Secure Virtual Machine Monitor) kernel, we ensure there exists a set of unique
//   memory permissions that are predefined and trusted.
// - Memory permissions are unforgeable, ensuring their integrity during execution.
// - The memory region tracks the memory page permissions and their page info permissions.
// - The PageInfo's permission will be shared as read-only permissions if the page is allocated.
//   observes the same PageInfo.
// - LinearMap is correct and is used for all memory managed.
//
use crate::address::group_addr_proofs;
use crate::mm::address_space::LinearMap;
use crate::types::lemma_page_size;
use verify_external::convert::FromSpec;
use verify_external::hw_spec::SpecMemMapTr;
use verify_proof::bits::*;
use verify_proof::frac_ptr::FracTypedPerm;
use vstd::arithmetic::mul::*;
use vstd::modes::tracked_swap;
use vstd::raw_ptr::IsExposed;

verus! {

mod alloc_spec { include!("alloc_inner.verus.rs");  }

use alloc_spec::*;

broadcast group set_len_group {
    verify_proof::set::lemma_len_filter,
    verify_proof::set::lemma_len_subset,
}

broadcast group alloc_broadcast_group {
    LinearMap::lemma_get_paddr,
    lemma_bit_usize_shl_values,
    lemma_page_size,
    set_len_group,
    //lemma_bit_u64_and_bound,
    alloc_spec::lemma_compound_neighbor,
}

broadcast use alloc_broadcast_group;

include!("alloc_info.verus.rs");

include!("alloc_free.verus.rs");

include!("alloc_perms.verus.rs");

//include!("alloc_mr.verus.rs");
include!("alloc_types.verus.rs");

impl View for MemoryRegion {
    type V = MemoryRegionPerms;

    closed spec fn view(&self) -> MemoryRegionPerms {
        self.perms@
    }
}

impl MemoryRegion {
    spec fn wf_next_pages(&self) -> bool {
        &&& self.wf_perms()
        &&& self.wf_params()
        &&& self.next_page@ =~= self@.free.next_pages()
        &&& forall|o| 0 <= o < MAX_ORDER ==> #[trigger] self.next_page[o] < MAX_PAGE_COUNT
        &&& self@.free.wf_strict()
    }

    spec fn wf_perms(&self) -> bool {
        let info = self@.info;
        &&& self@.wf()
        &&& forall|order|
            0 <= order < MAX_ORDER ==> info.nr_page(order) == (
            #[trigger] self.nr_pages[order as int])
        &&& self@.free.nr_free() =~= self.free_pages@
        &&& info.dom() =~= Set::new(|idx| 0 <= idx < self.page_count)
        &&& self.page_count == self@.npages()
    }

    spec fn wf_params(&self) -> bool {
        &&& self.page_count <= MAX_PAGE_COUNT
        &&& self.start_virt@ % PAGE_SIZE == 0
        &&& self@.mr_map.wf()
        &&& self@.info_ptr_exposed@ == self@.mr_map@.provenance
        &&& self.map() == self@.mr_map@.map
        &&& self.map().wf()
    }
}

impl MemoryRegion {
    spec fn map(&self) -> LinearMap {
        LinearMap {
            virt_start: self.start_virt,
            phys_start: self.start_phys@ as int,
            size: (self.page_count * PAGE_SIZE) as nat,
        }
    }

    spec fn with_same_mapping(&self, new: &Self) -> bool {
        self@.mr_map === new@.mr_map
    }
}

impl MemoryRegion {
    spec fn writable_page_info(&self, pfn: usize, perm: FracTypedPerm<PageStorageType>) -> bool {
        &&& perm.valid()
        &&& perm.writable()
        &&& perm.ptr() == self@.page_info_ptr(pfn)
        &&& self.wf_params()
    }

    spec fn writable_page_infos(
        &self,
        pfn: usize,
        npage: usize,
        perms: Map<usize, PInfoPerm>,
    ) -> bool {
        &&& forall|i| pfn <= i < pfn + npage ==> #[trigger] perms.contains_key(i)
        &&& forall|i|
            #![trigger perms[i]]
            pfn <= i < pfn + npage ==> {
                &&& self.writable_page_info(i, (#[trigger] perms[i]))
            }
    }

    spec fn ens_write_page_info(
        &self,
        new: Self,
        pfn: usize,
        pi: PageInfo,
        old_perm: FracTypedPerm<PageStorageType>,
        perm: FracTypedPerm<PageStorageType>,
    ) -> bool {
        &&& *self == new
        &&& old_perm.ens_write_page_info(&perm, pfn, pi)
    }

    spec fn req_mark_compound_page(
        &self,
        pfn: usize,
        order: usize,
        perms: Map<usize, PInfoPerm>,
    ) -> bool {
        let size = (1usize << order);
        &&& self.writable_page_infos((pfn + 1) as usize, (size - 1) as usize, perms)
        &&& self.inbound_pfn_order(pfn, order)
        &&& self.wf_params()
    }

    spec fn ens_mark_compound_page(
        &self,
        new: Self,
        pfn: usize,
        order: usize,
        perms: Map<usize, PInfoPerm>,
        new_perms: Map<usize, PInfoPerm>,
    ) -> bool {
        self.ens_mark_compound_page_loop(new, pfn, 1usize << order, order, perms, new_perms)
    }

    spec fn ens_mark_compound_page_loop(
        &self,
        new: Self,
        pfn: usize,
        size: usize,
        order: usize,
        perms: Map<usize, PInfoPerm>,
        new_perms: Map<usize, PInfoPerm>,
    ) -> bool {
        let pi = PageInfo::Compound(CompoundInfo { order });
        &&& *self == new
        &&& new_perms.dom() =~= perms.dom()
        &&& forall|i: usize|
            #![trigger new_perms[i]]
            perms.contains_key(i) ==> if pfn < i < pfn + size {
                perms[i].ens_write_page_info(&new_perms[i], i, pi)
            } else {
                new_perms[i] == perms[i]
            }
    }

    spec fn req_init_compound_page(
        &self,
        pfn: usize,
        order: usize,
        next_pfn: usize,
        perms: Map<usize, PInfoPerm>,
    ) -> bool {
        &&& next_pfn < MAX_PAGE_COUNT
        &&& self.inbound_pfn_order(pfn, order)
        &&& self.writable_page_infos(pfn, 1usize << order, perms)
        &&& self.wf_params()
    }

    spec fn ens_init_compound_page(
        &self,
        new: Self,
        pfn: usize,
        order: usize,
        next_pfn: usize,
        perms: Map<usize, PInfoPerm>,
        new_perms: Map<usize, PInfoPerm>,
    ) -> bool {
        let size = 1usize << order;
        let pi = PageInfo::Free(FreeInfo { next_page: next_pfn, order });
        &&& *self == new
        &&& new_perms.dom() =~= perms.dom()
        &&& forall|i: usize|
            #![trigger new_perms[i]]
            pfn <= i < pfn + size ==> perms[i].ens_write_page_info(
                &new_perms[i],
                i,
                if i == pfn {
                    pi
                } else {
                    PageInfo::Compound(CompoundInfo { order })
                },
            )
    }

    spec fn req_merge_pages(
        &self,
        pfn1: usize,
        pfn2: usize,
        order: usize,
        p1: PgUnitPerm<DeallocUnit>,
        p2: PgUnitPerm<DeallocUnit>,
    ) -> bool {
        let pfn = vstd::math::min(pfn1 as int, pfn2 as int);
        &&& self.wf_next_pages()
        &&& self.valid_pfn_order(pfn as usize, (order + 1) as usize)
        &&& 0 <= order < MAX_ORDER - 1
        &&& p1.wf_pfn_order(self@.mr_map, pfn1, order)
        &&& p2.wf_pfn_order(self@.mr_map, pfn2, order)
        &&& (pfn1 == pfn2 + (1usize << order)) || (pfn1 == pfn2 - (1usize << order))
    }

    spec fn ens_merge_pages_ok(
        &self,
        new: &Self,
        pfn1: usize,
        pfn2: usize,
        order: usize,
        ret: usize,
        perm: PgUnitPerm<DeallocUnit>,
    ) -> bool {
        let pfn = vstd::math::min(pfn1 as int, pfn2 as int) as usize;
        let new_order = (order + 1) as usize;
        &&& new.wf_next_pages()
        &&& ret == pfn
        &&& self.with_same_mapping(new)
        &&& perm.wf_pfn_order(self@.mr_map, pfn, new_order)
    }

    spec fn ens_merge_pages(
        &self,
        new: &Self,
        pfn1: usize,
        pfn2: usize,
        order: usize,
        ret: Result<usize, AllocError>,
        perm: PgUnitPerm<DeallocUnit>,
    ) -> bool {
        &&& ret.is_ok()
        &&& self.ens_merge_pages_ok(new, pfn1, pfn2, order, ret.unwrap(), perm)
    }

    spec fn req_split_page(&self, pfn: usize, order: usize, perm: PgUnitPerm<DeallocUnit>) -> bool {
        let new_size = (1usize << (order - 1) as usize);
        &&& self.wf_next_pages()
        &&& perm.wf_pfn_order(self@.mr_map, pfn, order)
        &&& perm.page_type() == PageType::Free
        &&& self.valid_pfn_order(pfn, order)
        &&& order >= 1
    }

    spec fn ens_split_page_ok(&self, new: &Self, pfn: usize, order: usize) -> bool {
        let rhs_pfn = (pfn + (1usize << order) / 2) as usize;
        let new_order = order - 1;
        let order = order as int;
        &&& new.wf_next_pages()
        &&& new.next_page[order - 1] != 0
        &&& self.with_same_mapping(new)
    }

    spec fn spec_get_pfn(&self, vaddr: VirtAddr) -> Option<usize> {
        self.map().get_pfn(vaddr)
    }

    spec fn spec_try_get_virt(&self, pfn: int) -> Option<VirtAddr> {
        self.map().try_get_virt(pfn as usize)
    }

    /// virt_offset == physical_offset
    spec fn ens_get_pfn(&self, vaddr: VirtAddr, ret: Result<usize, AllocError>) -> bool {
        &&& ret.is_ok() == self.spec_get_pfn(vaddr).is_some()
        &&& ret.is_ok() ==> {
            &&& ret.unwrap() == self.spec_get_pfn(vaddr).unwrap()
            &&& ret.unwrap() < self.page_count
            &&& vaddr@ % 0x1000 == 0 ==> self.spec_try_get_virt(ret.unwrap() as int) == Some(vaddr)
        }
    }

    spec fn ens_get_next_page(
        &self,
        new: &Self,
        order: usize,
        ret: Result<usize, AllocError>,
        perm: PgUnitPerm<DeallocUnit>,
    ) -> bool {
        let order = order as int;
        &&& new.wf_next_pages()
        &&& ret.is_err() == ((self.next_page[order] == 0))
        &&& ret.is_err() ==> self === new
        &&& ret.is_ok() ==> {
            &&& perm.wf_pfn_order(new@.mr_map, ret.unwrap(), order as usize)
            &&& perm.page_type() == PageType::Free
            &&& ret.unwrap() == self.next_page[order]
            &&& new.valid_pfn_order(ret.unwrap(), order as usize)
            &&& new.next_page@ =~= self.next_page@.update(order, new.next_page[order])
            &&& new.free_pages@ =~= self.free_pages@.update(order, new.free_pages@[order])
            &&& new.free_pages@[order] == self.free_pages[order] - 1
            &&& self.with_same_mapping(new)
        }
    }

    spec fn req_read_any_info(&self) -> bool {
        &&& self.page_count == self@.npages()
        &&& self.wf_params()
        &&& self@.wf()
    }

    spec fn ens_read_page_info(self, pfn: usize, ret: PageInfo) -> bool {
        let pi = self@.get_info(pfn);
        &&& pi === Some(ret)
        &&& pfn < self.page_count
    }

    spec fn spec_alloc_fails(&self, order: int) -> bool {
        forall|i| #![trigger self.next_page[i]] order <= i < MAX_ORDER ==> self.next_page[i] == 0
    }

    spec fn pg_params(&self) -> PageCountParam<MAX_ORDER> {
        PageCountParam { page_count: self.page_count }
    }

    spec fn inbound_pfn_order(&self, pfn: usize, order: usize) -> bool {
        &&& pfn + (1usize << order) <= self.pg_params().page_count
        &&& order < MAX_ORDER
        &&& pfn < MAX_PAGE_COUNT
    }

    spec fn valid_pfn_order(&self, pfn: usize, order: usize) -> bool {
        &&& self.pg_params().valid_pfn_order(pfn, order)
        &&& 0 < pfn < MAX_PAGE_COUNT
    }

    spec fn ens_refill_page_list(&self, new: Self, ret: bool, order: usize) -> bool {
        // No available if no slot >= order
        let valid_order = (0 <= order < MAX_ORDER);
        &&& (valid_order && !self.spec_alloc_fails(order as int)) == ret
        &&& ret ==> valid_order
        &&& ret ==> new.next_page[order as int] != 0
        &&& self.with_same_mapping(&new)
        &&& new.wf_next_pages()
    }

    spec fn ens_compound_neighbor(
        &self,
        pfn: usize,
        order: usize,
        ret: Result<usize, AllocError>,
    ) -> bool {
        let ret_pfn = ret.unwrap();
        ret.is_ok() ==> {
            &&& ret_pfn < self.page_count
            &&& order < (MAX_ORDER - 1)
            &&& ens_find_neighbor(pfn, order, ret_pfn)
        }
    }

    spec fn req_allocate_pfn(&self, pfn: usize, order: usize) -> bool {
        &&& order < MAX_ORDER
        &&& pfn < self.page_count
        &&& self.wf_next_pages()
    }

    spec fn ens_allocate_pfn(
        &self,
        new: &Self,
        pfn: usize,
        order: usize,
        perm: PgUnitPerm<DeallocUnit>,
    ) -> bool {
        &&& perm.wf_pfn_order(new@.mr_map, pfn, order)
        &&& new.wf_next_pages()
        &&& new.valid_pfn_order(pfn, order)
        &&& self.with_same_mapping(new)
    }

    spec fn req_try_to_merge_page(
        &self,
        pfn: usize,
        order: usize,
        perm: PgUnitPerm<DeallocUnit>,
    ) -> bool {
        &&& self.wf_next_pages()
        &&& self.valid_pfn_order(pfn, order)
        &&& perm.wf_pfn_order(self@.mr_map, pfn, order)
    }

    spec fn ens_try_to_merge_page_ok(
        &self,
        new: &Self,
        pfn: usize,
        order: usize,
        ret: Result<usize, AllocError>,
        perm: PgUnitPerm<DeallocUnit>,
    ) -> bool {
        let new_pfn = ret.unwrap();
        let order = order as int;
        let new_order = (order + 1) as usize;
        &&& new_pfn == pfn || new_pfn == pfn - (1usize << order)
        &&& new.wf_next_pages()
        &&& perm.wf_pfn_order(new@.mr_map, new_pfn, new_order)
        &&& new.valid_pfn_order(new_pfn, new_order)
        &&& self.with_same_mapping(new)
    }

    spec fn ens_try_to_merge_page(
        &self,
        new: &Self,
        pfn: usize,
        order: usize,
        ret: Result<usize, AllocError>,
        old_perm: PgUnitPerm<DeallocUnit>,
        perm: PgUnitPerm<DeallocUnit>,
    ) -> bool {
        &&& ret.is_ok() ==> self.ens_try_to_merge_page_ok(new, pfn, order, ret, perm)
        &&& ret.is_err() ==> (self == new) && perm == old_perm
        &&& self.with_same_mapping(new)
    }

    spec fn ens_free_page_order(&self, new: &Self, pfn: usize, order: usize) -> bool {
        &&& new.wf_next_pages()
        &&& self.with_same_mapping(
            new,
        )
        //&&& new@.contains_range(pfn, order)

    }

    spec fn req_free_page(&self, vaddr: VirtAddr, perm: AllocatedPagesPerm) -> bool {
        &&& self.wf_next_pages()
    }

    spec fn ens_free_page(&self, new: &Self, vaddr: VirtAddr, perm: AllocatedPagesPerm) -> bool {
        self@.mr_map@ == new@.mr_map@
    }

    spec fn req_free_page_raw(
        &self,
        pfn: usize,
        order: usize,
        perm: PgUnitPerm<DeallocUnit>,
    ) -> bool {
        &&& self.wf_next_pages()
        &&& self.valid_pfn_order(pfn, order)
        &&& perm.wf_pfn_order(self@.mr_map, pfn, order)
    }

    spec fn ens_free_page_raw(&self, new: &Self, pfn: usize, order: usize) -> bool {
        let end = pfn + (1usize << order);
        &&& new.wf_next_pages()
        &&& self.with_same_mapping(new)
    }

    spec fn req_allocate_pages_info(&self, order: usize, pg: PageInfo) -> bool {
        &&& self.wf_next_pages()
        &&& order < MAX_ORDER
        &&& pg.spec_order() == order
        &&& pg.spec_type().spec_is_deallocatable()
        &&& !matches!(pg, PageInfo::Compound(_))
    }

    spec fn ens_allocate_pages_info(
        &self,
        new: &Self,
        order: usize,
        pg: PageInfo,
        ret: Result<VirtAddr, AllocError>,
        perm_with_dealloc: Option<UnitDeallocPerm>,
    ) -> bool {
        let pfn = self.spec_get_pfn(ret.unwrap()).unwrap();
        let UnitDeallocPerm(perm) = perm_with_dealloc.unwrap();
        &&& self.with_same_mapping(new)
        &&& new.wf_next_pages()
        &&& ret.is_ok() ==> {
            &&& perm.page_info() == Some(pg)
            &&& perm.wf_pfn_order(new@.mr_map, pfn, order)
        }
    }

    spec fn ens_phys_to_virt(&self, paddr: PhysAddr, ret: Option<VirtAddr>) -> bool {
        let identity_map = self.map().is_identity_map();
        let valid_identity_map = identity_map && (self.start_phys@ == self.start_virt.offset());
        &&& !identity_map ==> (ret.is_some() == self.map().to_vaddr(paddr@ as int).is_some())
        &&& (!identity_map && ret.is_some()) ==> (ret.unwrap() == self.map().to_vaddr(
            paddr@ as int,
        ).unwrap())
        &&& valid_identity_map ==> (ret == Some(VirtAddr::from_spec(paddr@)))
    }
}

} // verus!

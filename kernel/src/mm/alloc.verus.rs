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
        &&& self.start_virt@ + (self.page_count * PAGE_SIZE) as int
            <= crate::address::VADDR_LOWER_MASK || self.start_virt@
            >= crate::address::VADDR_UPPER_MASK
        &&& self@.mr_map.wf()
        &&& self@.info_ptr_exposed@ == self@.mr_map@.provenance
        &&& self.map() == self@.mr_map@.map
        &&& self.map().wf()
    }

    proof fn lemma_page_info_ptr(&self, pfn: usize)
        requires
            #[trigger] self.wf_params(),
            pfn < self.page_count,
        ensures
            self.start_virt@ + #[trigger] (pfn * size_of::<PageStorageType>()) <= usize::MAX,
    {
        let unit = size_of::<PageStorageType>() as int;
        vstd::arithmetic::mul::lemma_mul_is_commutative(pfn as int, unit);
        vstd::arithmetic::mul::lemma_mul_is_commutative(pfn as int, PAGE_SIZE as int);
        vstd::arithmetic::mul::lemma_mul_inequality(unit, PAGE_SIZE as int, pfn as int);
        vstd::arithmetic::mul::lemma_mul_inequality(
            pfn as int,
            self.page_count as int,
            PAGE_SIZE as int,
        );
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

    spec fn req_next_free_pfn(
        self,
        pfn: usize,
        order: usize,
        perm: &PgUnitPerm<DeallocUnit>,
    ) -> bool {
        &&& self.req_read_any_info()
        &&& perm.page_type() == PageType::Free
        &&& perm.wf_pfn_order(self@.mr_map, pfn, order)
        &&& order < MAX_ORDER
        &&& pfn < self.page_count
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
/*********************************************************************************
 * Defines inline proofs to simplify annotations inside executable functions.
 * Those proof blocks are close to implementations and are not performance critical.
 * Thus, instead of define a new proof function, we define inline proofs.
 * TODO(verus): support real inline proof functions instead of using macros.
 */
#[cfg(verus_keep_ghost_body)]
macro_rules! grant_info_write {
    ($mr: ident, $perm: ident => $mem: ident, $reserved: ident, $id: ident) => {
        proof_decl! {
            let tracked mut $perm = $perm;
            let tracked ($mem, mut info) = $perm.tracked_take();
            $mr.perms.borrow_mut().info.tracked_unshare_for_write(&mut info);
            let tracked mut $reserved = info.tracked_expose();
            let ghost $id = info.id();
        }
    };
}

#[cfg(verus_keep_ghost_body)]
macro_rules! revoke_info_write {
    ($mr: ident, $pfn: ident, $order: ident, $mem: ident, $reserved: ident, $id: ident => $p: ident) => {
        proof_decl!{
            let tracked info = $mr.perms.borrow_mut().info.tracked_insert_unit($order, $pfn, $id, $reserved);
            let tracked mut $p = PgUnitPerm {mem: $mem, info, typ: arbitrary()};
        }
    }
}

#[cfg(verus_keep_ghost_body)]
macro_rules! lemma_free_page_pre {
    ($mr: ident, $perm: ident, $pfn: ident => $mem: ident, $reserved: ident, $head_info: ident, $id: ident) => {
        proof_decl! {
            grant_info_write!($mr, $perm => $mem, $reserved, $id);
            let tracked mut $head_info = $reserved.tracked_remove($pfn);
        }
    };
}

#[cfg(verus_keep_ghost_body)]
macro_rules! lemma_free_page_post {
    ($mr: ident, $pfn: ident, $order: ident, $mem: ident, $reserved: ident, $head_info: ident, $id: ident) => {
        proof_decl! {
            $reserved.tracked_insert($pfn, $head_info);
            revoke_info_write!($mr, $pfn, $order, $mem, $reserved, $id => pfn_perm);
            $mr.perms.borrow_mut().free.tracked_push($order, $pfn, pfn_perm);
        }
    };
}

#[cfg(verus_keep_ghost_body)]
macro_rules! lemma_split_pre {
    ($mr: ident, $perm: ident, $pfn1: ident, $pfn2: ident, $order: ident, $new_order: ident => $mem: ident, $mem2: ident, $reserved: ident, $reserved2: ident, $info: ident, $id: ident) => {
        proof_decl!{
            // To prove that nr_pages[new_order] < usize::MAX - 2.
            $mr.perms.borrow().info.tracked_nr_page_pair($new_order, $order);

            // Grant write access to the page info.
            use_type_invariant(&$perm.info);
            grant_info_write!($mr, $perm => $mem, $reserved2, $id);

            let tracked mut $reserved = $reserved2.tracked_remove_keys(Set::new(|i: usize| $pfn1 <= i < $pfn2));

            // Prove the next page is valid.
            $mr.perms.borrow().free.tracked_next($new_order);

            // Split the memory permission to two.
            let tracked ($mem, $mem2) = $mr.perms.borrow().mr_map.tracked_split_pages($mem, $pfn1, $order);
        }
    }
}

#[cfg(verus_keep_ghost_body)]
macro_rules! lemma_split_post {
    ($mr: ident, $pfn1: ident, $pfn2: ident, $new_order: ident, $mem: ident, $mem2: ident, $reserved: ident, $reserved2: ident, $id: ident, $p1: ident) => {
        proof_decl! {
            // Insert the readonly share of info perm for the right pages into
            // the tracked info perm to avoid future write outside.
            revoke_info_write!($mr, $pfn2, $new_order, $mem2, $reserved2, $id => p2);

            // Add the new free perms into the free list.
            use_type_invariant(&p2.info);
            $mr.perms.borrow_mut().free.tracked_push($new_order, $pfn2, p2);
            use_type_invariant(&$p1.info);
            $mr.perms.borrow_mut().free.tracked_push($new_order, $pfn1, $p1);
        }
    };
}

#[cfg(verus_keep_ghost_body)]
macro_rules! lemma_merge_pre {
    ($mr: ident, $perm: ident, $p2: ident, $pfn1: ident, $pfn2: ident, $pfn: ident, $order: ident, $new_order: ident => $mem: ident, $reserved: ident, $head_info: ident, $id: ident) => {
        proof_decl! {
            // Proves that nr_page[new_order] <= usize:MAX - 1.
            $mr.perms.borrow().info.tracked_nr_page_pair($order, $new_order);

            let tracked (mut $mem, mut info) = $perm.tracked_take();

            // Grant write access to the pfn1 page info.
            // prove nr_page[order] >= 1.
            $mr.perms.borrow_mut().info.tracked_unshare_for_write(&mut info);

            let tracked mut $p2 = $p2;
            let tracked (mut mem2, mut info2) = $p2.tracked_take();

            // Grant write access to the pfn1 page info.
            // prove that nr_page[order] >= 2.
            $mr.perms.borrow_mut().info.tracked_unshare_for_write(&mut info2);

            // Merge mem2 permissions into mem to cover the merged pages.
            $mr.perms.borrow().mr_map.tracked_merge_pages(&mut $mem, mem2, $pfn1, $pfn2, $order);

            // Split info perms into two groups:
            // one for the allocinfo and another for compound pages.
            let ghost $id = info.id();
            let tracked mut $reserved = info.tracked_expose();
            let tracked reserved2 = info2.tracked_expose();
            $reserved.tracked_union_prefer_right(reserved2);
            let tracked mut $head_info = $reserved.tracked_remove($pfn);
        }
    };
}

#[cfg(verus_keep_ghost_body)]
macro_rules! lemma_merge_post {
    ($mr: ident, $perm: ident, $pfn: ident, $order: ident, $new_order: ident, $mem: ident, $reserved: ident, $head_info: ident, $id: ident) => {
        proof_decl! {
            // Insert the readonly share of info perm for the merged memory
            // back into the tracked info perm to avoid future write outside.
            $reserved.tracked_insert($pfn, $head_info);
            revoke_info_write!($mr, $pfn, $new_order, $mem, $reserved, $id => tmp_perm);
            *$perm = tmp_perm;

            // Prove the nr_page counter is correct.
            assert(2 * (1usize << $order) == (1usize << $new_order));
            assert($mr@.info.nr_page($order) == old($mr)@.info.nr_page($order) - 2);
            assert($mr@.info.nr_page($new_order) == old($mr)@.info.nr_page($new_order) + 1);
        }
    };
}

#[cfg(verus_keep_ghost_body)]
macro_rules! lemma_alloc_pfn_loop_pre {
    ($mr: ident, $perm: ident, $old_pfn: ident, $current_pfn: ident, $order: ident, $idx_: ident =>
        $prev_mem: ident,  $prev_id: ident, $prev_reserved: ident, $prev_head_info:ident,
        $mem: ident, $id: ident, $reserved: ident, $head_info: ident) => {
        proof_decl!{
            // prove the next_pfn is disjont with current_pfn.
            $mr.perms.borrow_mut().free.tracked_disjoint_pfn($order, $idx_ + 1, $order, $idx_);

            // Get prev mem and info perms and grant write to info perm.
            let tracked mut prev_perm = $mr.perms.borrow_mut().free.tracked_remove($order, $idx_ + 1);
            lemma_free_page_pre!($mr, prev_perm, $old_pfn => $prev_mem, $prev_reserved, $prev_head_info, $prev_id);

            // Get current mem and info perms and grant write to info perm.
            let tracked mut current_perm = $mr.perms.borrow_mut().free.tracked_remove($order, $idx_);
            lemma_free_page_pre!($mr, current_perm, $current_pfn => $mem, $reserved, $head_info, $id);
        }
    }
}

#[cfg(verus_keep_ghost_body)]
macro_rules! lemma_alloc_pfn_loop_post {
    ($mr: ident, $perm: ident, $old_pfn: ident, $current_pfn: ident, $order: ident, $idx_: ident, $prev_mem: ident, $prev_info_id: ident,
        $prev_reserved: ident, $prev_head_info: ident, $mem: ident, $info_id: ident, $reserved: ident,
        $head_info: ident) => {
        proof_decl!{
            // Insert the readonly share of info perm for prev free pages
            $prev_reserved.tracked_insert($old_pfn, $prev_head_info);

            let tracked prev_info = $mr.perms.borrow_mut().info.tracked_insert_unit($order, $old_pfn, $prev_info_id, $prev_reserved);

            // Insert the prev_mem back to free list.
            let tracked mut prev_perm = PgUnitPerm {mem: $prev_mem, info: prev_info, typ: arbitrary()};
            $mr.perms.borrow_mut().free.tracked_insert($order, $idx_, $old_pfn, prev_perm);

            // Insert the readonly share of info perm for the allocated
            // pages to avoid future change from inside and outside of MR.
            $reserved.tracked_insert($current_pfn, $head_info);

            revoke_info_write!($mr, $current_pfn, $order, $mem, $reserved, $info_id => tmp_perm);
            *$perm = tmp_perm;
            // Prove free list is still strictly wellformed.
            old($mr)@.free.lemma_wf_restrict_remove(&$mr.perms.borrow().free, $order, $idx_);
        }
    }
}

#[cfg(verus_keep_ghost_body)]
macro_rules! lemma_free_page {
    ($mr: ident, $inperm: ident, $pfn: ident, $res: ident => $perm: ident) => {
        proof_decl! {
            // Prove the passed pages are valid.
            use_type_invariant(&$inperm);
            let tracked AllocatedPagesPerm{mut $perm, mr_map} = $inperm;

            // Prove the passed pages shares the same mapping and page info,
            // tracked inside the MemoryRegion.
            $mr.perms.borrow().mr_map.is_same(&mr_map);
            $mr.perms.borrow().info.tracked_is_same_info(&$perm, $pfn);

            // Prove the pfn is valid.
            assert($mr.valid_pfn_order($pfn, $res.spec_order())) by {
                mr_map.pg_params().lemma_reserved_pfn_count();
            }
        }
    };
}

#[cfg(verus_keep_ghost_body)]
macro_rules! lemma_get_pfn {
    ($mr: ident, $vaddr: ident) => {
        proof! {
            use_type_invariant($vaddr);
            reveal(<LinearMap as SpecMemMapTr>::to_paddr);
            if $mr@.map().virt_start.offset() <= $vaddr.offset() < $mr@.map().virt_start.offset() + $mr@.map().size {
                $mr@.map().lemma_get_pfn_get_virt($vaddr);
            }
        }
    }
}

#[cfg(verus_keep_ghost_body)]
macro_rules! lemma_alloc_pages_info_pre {
    ($self: ident, $pfn: ident, $perm: ident => $mem: ident, $info: ident, $reserved: ident, $info_head: ident) => {
        proof_decl! {
            // Grant write access to the page info.
            let tracked ($mem, mut $info) = $perm.tracked_take();
            $self.perms.borrow_mut().info.tracked_unshare_for_write(&mut $info);
            let tracked mut $reserved = $info.tracked_expose();
            let tracked mut $info_head = $reserved.tracked_remove($pfn);
        }
    };
}

#[cfg(verus_keep_ghost_body)]
macro_rules! lemma_alloc_pages_info_post {
    ($self: ident, $order: ident, $pfn: ident, $mem: ident, $info: ident, $reserved: ident, $info_head: ident, $ret_perm: ident) => {
        proof!{
            // Insert the readonly share of info perm into the tracked info perm
            $reserved.tracked_insert($pfn, $info_head);
            let tracked info = $self.perms.borrow_mut().info.tracked_insert_unit($order, $pfn, $info.id(), $reserved);

            // Return the memory permission with a readonly share of info.
            let tracked perm = PgUnitPerm {$mem, info, typ: arbitrary()};
            *$ret_perm = Some(UnitDeallocPerm(perm));

            // Prove the relationship between vaddr and pfn.
            // assert(pfn == self.spec_get_pfn(vaddr).unwrap()) by {
            reveal(<LinearMap as SpecMemMapTr>::to_paddr);
            // };
        }
    }
}

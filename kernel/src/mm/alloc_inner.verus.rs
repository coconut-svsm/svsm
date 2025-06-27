// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// Spec and proofs that does not need private types in alloc.rs
use crate::mm::alloc::VirtAddr;
use crate::mm::LinearMap;
use crate::types::{lemma_page_size, PAGE_SIZE};
use crate::utils::util::spec_align_up;

use crate::mm::alloc::MAX_ORDER;
use verify_external::hw_spec::SpecVAddrImpl;
use verify_proof::bits::*;
use verify_proof::frac_ptr::*;
use verify_proof::nonlinear::*;
use vstd::arithmetic::div_mod::*;
use vstd::arithmetic::mul::lemma_mul_is_distributive_add_other_way;
use vstd::math::min;
use vstd::modes::tracked_swap;
use vstd::prelude::*;
use vstd::raw_ptr::*;
verus! {

pub type RawPerm = PointsToRaw;

pub spec const MAX_PAGE_COUNT: u64 = 1u64 << (u64::BITS - 12) as u64;

pub spec const MAX_PGINFO_SHARES: nat = 2;

pub spec const ALLOCATOR_PGINFO_SHARES: nat = 1;

pub spec const DEALLOC_PGINFO_SHARES: nat = 1;

pub uninterp spec fn allocator_provenance() -> Provenance;

pub proof fn tracked_empty_seq_of_seq<T>(n: nat) -> (tracked ret: Seq<Seq<T>>)
    requires
        n >= 0,
    ensures
        ret.len() == n,
        ret == Seq::new(n, |i| Seq::<T>::empty()),
    decreases n,
{
    if n == 0 {
        assert(Seq::empty() =~= Seq::new(n, |i| Seq::<T>::empty()));
        Seq::tracked_empty()
    } else {
        let tracked mut ret = tracked_empty_seq_of_seq((n - 1) as nat);
        ret.tracked_push(Seq::tracked_empty());
        assert(ret =~= Seq::new(n, |i| Seq::<T>::empty()));
        ret
    }
}

pub open spec fn ens_find_neighbor(pfn: usize, order: usize, ret_pfn: usize) -> bool {
    let lower_neighbor = pfn - (1usize << order);
    let upper_neighbor = pfn + (1usize << order);
    &&& ret_pfn == lower_neighbor || ret_pfn == upper_neighbor
    &&& ret_pfn == lower_neighbor ==> ret_pfn % (1usize << (order + 1) as usize) == 0
    &&& ret_pfn == upper_neighbor ==> pfn % (1usize << (order + 1) as usize) == 0
    &&& ret_pfn % (1usize << order) == 0
}

#[verifier::spinoff_prover]
#[verifier::rlimit(4)]
pub broadcast proof fn lemma_compound_neighbor(pfn: usize, order: usize, ret_pfn: usize)
    requires
        pfn % (1usize << order) == 0,
        pfn + (1usize << order) <= usize::MAX,
        ret_pfn == pfn ^ (1usize << order),
        0 <= order < 63,
    ensures
        (ret_pfn == pfn - (1usize << order)) ==> ret_pfn % (1usize << (order + 1)) == 0,
        #[trigger] ens_find_neighbor(pfn, order, ret_pfn),
{
    broadcast use lemma_bit_usize_shl_values;

    assert(pfn % (1usize << order) == 0);
    let n = 1usize << (order + 1);
    assert(1usize << (order + 1) == 2 * (1usize << order));
    lemma_bit_usize_and_mask_is_mod(pfn, ((1usize << order) - 1) as usize);
    lemma_bit_usize_and_mask_is_mod(pfn, ((1usize << (order + 1) as usize) - 1) as usize);
    lemma_bit_usize_xor_neighbor(pfn, order);
    lemma_modulus_add_sub_m(pfn as int, (1usize << order) as int);
    if ret_pfn == pfn - (1usize << order) {
        let x = pfn;
        let m = 1usize << order;
        if x as int % (2 * m) == 0 {
            assert(x & (2 * m - 1) as usize == 0);
            assert(x & (n - 1) as usize == 0);
            assert(x ^ m == sub(x, m));
        }
        assert(x as int % (2 * m) != 0);
        assert(((x - m) % (2 * m) == 0 && (x >= m || x <= -m)))
    }
}

pub open spec fn order_disjoint(
    start1: usize,
    order1: usize,
    start2: usize,
    order2: usize,
) -> bool {
    let end1 = start1 + (1usize << order1);
    let end2 = start2 + (1usize << order2);
    (end1 <= start2 || end2 <= start1)
}

pub proof fn lemma_order_disjoint_len(s: Seq<usize>, o: usize, max_count: usize)
    requires
        o < 64,
        // s has a upper bound
        forall|i| #![trigger s[i]] 0 <= i < s.len() ==> s[i] < max_count,
        // s is order-disjoint
        forall|i, j|
            #![trigger s[i], s[j]]
            0 <= i < s.len() && 0 <= j < s.len() && i != j ==> order_disjoint(s[i], o, s[j], o),
    ensures
        s.len() * (1usize << o) <= max_count + (1usize << o) - 1,
        s.len() <= max_count,
    decreases s.len(),
{
    broadcast use lemma_bit_usize_shl_values;

    let gap = (1usize << o);
    let int_s = s.map_values(|x| x as int);
    assert(int_s.len() == s.len());
    if s.len() > 1 {
        int_s.max_ensures();
        let idx = choose|i| 0 <= i < int_s.len() && int_s[i] == int_s.max();
        assert(int_s[idx] == int_s.max());
        assert(s.remove(idx).len() < s.len());
        assert forall|i| #![trigger s[i]] 0 <= i < s.len() && i != idx implies s[i] < max_count
            - gap by {
            assert(s[idx] <= max_count);
            assert(int_s[i] <= int_s[idx]);
            assert(s[i] <= s[idx]);
            assert(order_disjoint(s[i], o, s[idx], o));
        }
        let s2 = s.remove(idx);
        if idx > 0 {
            assert(order_disjoint(s[idx], o, s[idx - 1], o));
        } else {
            assert(order_disjoint(s[idx], o, s[idx + 1], o));
        }
        assert(max_count >= gap);
        lemma_order_disjoint_len(s2, o, (max_count - gap) as usize);
        assert(s2.len() <= max_count - gap);
        assert(s2.len() * gap <= max_count - 1);
        assert(s.len() == s2.len() + 1);
        assert(s.len() * gap == s2.len() * gap + 1 * gap) by {
            lemma_mul_is_distributive_add_other_way(gap as int, s2.len() as int, 1);
        }
    } else if s.len() == 1 {
        assert(s[0] < max_count);
        assert(max_count > 0);
        assert(s.len() <= max_count);
        assert(1 * gap == gap);
        assert(s.len() * gap <= max_count + gap - 1);
    } else {
        assert(0 * gap == 0);
    }
}

#[allow(missing_debug_implementations)]
pub ghost struct PageCountParam<const N: usize> {
    pub page_count: usize,
}

impl<const N: usize> PageCountParam<N> {
    #[verifier(opaque)]
    pub open spec fn reserved_pfn_count(&self) -> nat {
        (spec_align_up(self.page_count * 8 as int, PAGE_SIZE as int) / PAGE_SIZE as int) as nat
    }

    pub open spec fn valid_pfn_order(&self, pfn: usize, order: usize) -> bool {
        let n = 1usize << order;
        &&& self.reserved_pfn_count() <= pfn < self.page_count
        &&& pfn + n <= self.page_count
        &&& n > 0
        &&& pfn % n == 0
        &&& order < N
    }

    pub proof fn lemma_reserved_pfn_count(&self)
        ensures
            self.reserved_pfn_count() == self.page_count / 512 || self.reserved_pfn_count() == 1 + (
            self.page_count / 512),
            self.page_count > 0 ==> self.reserved_pfn_count() > 0,
    {
        broadcast use lemma_page_size;

        reveal(PageCountParam::reserved_pfn_count);

        let x = self.page_count * 8 as int;
        assert(PAGE_SIZE == 0x1000);
        let count = spec_align_up(x, PAGE_SIZE as int);
        verify_proof::nonlinear::lemma_align_up_properties(x, PAGE_SIZE as int, count);
        assert(self.page_count * 8 / 0x1000 == self.page_count / 512);
    }

    #[verifier::spinoff_prover]
    proof fn lemma_valid_pfn_order_split(&self, pfn: usize, order: usize)
        requires
            self.valid_pfn_order(pfn, order),
            0 < order < N <= 64,
        ensures
            self.valid_pfn_order(pfn, (order - 1) as usize),
            self.valid_pfn_order(
                (pfn + (1usize << (order - 1) as usize)) as usize,
                (order - 1) as usize,
            ),
    {
        broadcast use lemma_bit_usize_shl_values;

        let n = 1usize << order;
        let lower_n = 1usize << (order - 1) as usize;
        assert(1usize << order == 2 * (1usize << (order - 1) as usize)) by (bit_vector)
            requires
                0 < order < 64,
        ;
        if self.valid_pfn_order(pfn, order) && order > 0 {
            verify_proof::nonlinear::lemma_modulus_product_divisibility(
                pfn as int,
                lower_n as int,
                2,
            );
        }
        lemma_add_mod_noop(pfn as int, lower_n as int, lower_n as int);
        lemma_mod_self_0(lower_n as int);
        lemma_small_mod(0, lower_n as nat);
        assert((pfn + lower_n) % lower_n as int == 0);
    }
}

pub trait MemPermWithVAddrOrder<VAddr: SpecVAddrImpl> {
    spec fn wf_vaddr_order(&self, map: MemRegionMapping, vaddr: VAddr, order: usize) -> bool;
}

pub trait MemPermWithPfnOrder {
    spec fn wf_pfn_order(&self, map: MemRegionMapping, pfn: usize, order: usize) -> bool;
}

impl<VAddr: SpecVAddrImpl> MemPermWithVAddrOrder<VAddr> for RawPerm {
    open spec fn wf_vaddr_order(&self, map: MemRegionMapping, vaddr: VAddr, order: usize) -> bool {
        let size = ((1usize << order) * PAGE_SIZE) as nat;
        &&& self.dom() =~= vaddr.region_to_dom(size)
        &&& self.provenance() === map@.provenance
    }
}

impl MemPermWithPfnOrder for RawPerm {
    open spec fn wf_pfn_order(&self, map: MemRegionMapping, pfn: usize, order: usize) -> bool {
        let vaddr = map@.map.try_get_virt(pfn);
        &&& vaddr.is_some()
        &&& pfn + (1usize << order) <= map@.map.size / PAGE_SIZE as nat
        &&& self.wf_vaddr_order(map, vaddr.unwrap(), order)
    }
}

// A ghost global layout for global allocator
// Add more global variables here as needed
// It could be a real global variable or a global invariant.
// We put FracPerm to ensure that the content will not be modified by accident.
// For example, allocator must update this ghost variable if it needs to
// change the base_ptr of the allocator.
//
// Since the allocated memory will have GlobalInv and so the allocator cannot
// obtain full ownership if the allocator does not free all memory before updating
// the base_ptr.
#[allow(missing_debug_implementations)]
pub ghost struct MemRegionMappingView {
    pub map: LinearMap,
    pub provenance: Provenance,
}

#[allow(missing_debug_implementations)]
pub tracked struct MemRegionMapping(FracTypedPerm<Tracked<MemRegionMappingView>>);

impl MemRegionMapping {
    pub uninterp spec fn const_ptr() -> *const Tracked<MemRegionMappingView>;

    #[verifier::type_invariant]
    pub closed spec fn wf(&self) -> bool {
        &&& self.0.ptr() == Self::const_ptr()
        &&& self.0.valid()
        &&& self@.map.wf()
    }

    pub closed spec fn view(&self) -> MemRegionMappingView {
        self.0.value()@
    }

    pub closed spec fn shares(&self) -> nat {
        self.0.shares()
    }

    pub open spec fn pg_params(&self) -> PageCountParam<MAX_ORDER> {
        PageCountParam { page_count: (self@.map.size / PAGE_SIZE as nat) as usize }
    }

    pub open spec fn base_ptr<T>(&self) -> *const T {
        vstd::raw_ptr::ptr_from_data(
            vstd::raw_ptr::PtrData {
                addr: self@.map.virt_start@,
                provenance: self@.provenance,
                metadata: vstd::raw_ptr::Metadata::Thin,
            },
        )
    }

    pub proof fn is_same(tracked &self, tracked other: &Self)
        ensures
            self@ == other@,
    {
        use_type_invariant(&*self);
        use_type_invariant(other);
        self.0.is_same(&other.0);
    }

    #[verifier::spinoff_prover]
    pub proof fn tracked_merge_pages(
        tracked &self,
        tracked perm1: &mut RawPerm,
        tracked perm2: RawPerm,
        p1: usize,
        p2: usize,
        order: usize,
    )
        requires
            0 <= order < 64,
            p1 == p2 + (1usize << order) || p2 == p1 + (1usize << order),
            perm2.wf_pfn_order(*self, p2, order),
            old(perm1).wf_pfn_order(*self, p1, order),
        ensures
            perm1.wf_pfn_order(*self, min(p1 as int, p2 as int) as usize, (order + 1) as usize),
    {
        use_type_invariant(self);
        broadcast use lemma_bit_usize_shl_values;

        let map = self@.map;
        let vaddr1 = map.lemma_get_virt(p1);
        let vaddr2 = map.lemma_get_virt(p2);
        let size = ((1usize << order) * PAGE_SIZE) as nat;
        if p1 < p2 {
            vaddr1.lemma_region_to_dom_merge(size, vaddr2, size);
        } else {
            vaddr2.lemma_region_to_dom_merge(size, vaddr1, size);
        }
        let tracked mut owned_perm1 = RawPerm::empty(perm1.provenance());
        tracked_swap(&mut owned_perm1, perm1);
        *perm1 = owned_perm1.join(perm2);
    }

    #[verifier::spinoff_prover]
    pub proof fn tracked_split_pages(
        tracked &self,
        tracked p: RawPerm,
        pfn: usize,
        order: usize,
    ) -> (tracked perms: (RawPerm, RawPerm))
        requires
            1 <= order < 64,
            p.wf_pfn_order(*self, pfn, order),
        ensures
            perms.0.wf_pfn_order(*self, pfn, (order - 1) as usize),
            perms.1.wf_pfn_order(
                *self,
                (pfn + (1usize << (order - 1))) as usize,
                (order - 1) as usize,
            ),
            self.pg_params().valid_pfn_order(pfn, order) ==> (self.pg_params().valid_pfn_order(
                pfn,
                (order - 1) as usize,
            ) && self.pg_params().valid_pfn_order(
                (pfn + (1usize << (order - 1))) as usize,
                (order - 1) as usize,
            )),
    {
        use_type_invariant(self);
        broadcast use lemma_bit_usize_shl_values;

        let map = self@.map;
        reveal(<VirtAddr as SpecVAddrImpl>::region_to_dom);
        let p1 = pfn;
        let p2 = (pfn + (1usize << (order - 1))) as usize;
        let vaddr1 = map.lemma_get_virt(p1);
        assert(p2 + (1usize << (order - 1)) == pfn + (1usize << order));
        let vaddr2 = map.lemma_get_virt(p2);
        let size = (1usize << (order - 1)) * PAGE_SIZE;
        if self.pg_params().valid_pfn_order(pfn, order) {
            self.pg_params().lemma_valid_pfn_order_split(p1, order);
        }
        p.split(vaddr1.region_to_dom(size as nat))
    }

    pub proof fn raw_perm_order_disjoint(
        &self,
        p1: usize,
        o1: usize,
        p2: usize,
        o2: usize,
        tracked perm1: &mut RawPerm,
        tracked perm2: &RawPerm,
    )
        requires
            self.wf(),
            0 <= o1 < 64,
            0 <= o2 < 64,
            old(perm1).wf_pfn_order(*self, p1, o1),
            perm2.wf_pfn_order(*self, p2, o2),
        ensures
            order_disjoint(p1, o1, p2, o2),
            *old(perm1) == *perm1,
    {
        broadcast use lemma_bit_usize_shl_values;

        let vaddr1 = self@.map.lemma_get_virt(p1);
        let vaddr2 = self@.map.lemma_get_virt(p2);
        let size1 = ((1usize << o1) * PAGE_SIZE) as nat;
        let size2 = ((1usize << o2) * PAGE_SIZE) as nat;
        vaddr1.lemma_vaddr_region_len(size1);
        vaddr2.lemma_vaddr_region_len(size2);
        raw_perm_is_disjoint(perm1, perm2);
        reveal(<VirtAddr as SpecVAddrImpl>::region_to_dom);
        assert(perm1.dom().contains(vaddr1@ as int));
        assert(perm2.dom().contains(vaddr2@ as int));
    }
}

} // verus!

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// Proofs for tracking the page info in reserved memory regions.
// To ensure the global allocator and the locally allocated heap memory
// have consistent page info, we use `FracPtr` to share the page info
// and guarantee that the page info is immutable once shared.
// PageInfoDb is the main data structure to track the page info with the same
// shared status.
use verify_proof::frac_ptr::tracked_map_merge_right_shares;
use verify_proof::frac_ptr::tracked_map_shares;
use verify_proof::set::{lemma_set_usize_range, set_usize_range};
use vstd::raw_ptr::PtrData;

verus! {

type PInfoPerm = FracTypedPerm<PageStorageType>;

#[allow(missing_debug_implementations)]
pub ghost struct PInfoGroupId {
    pub ptr_data: PtrData,
    pub shares: nat,
    pub total: nat,
}

impl PInfoGroupId {
    spec fn update_shares(&self, shares: nat) -> PInfoGroupId {
        PInfoGroupId { ptr_data: self.ptr_data, shares, total: self.total }
    }

    spec fn base_ptr(&self) -> *const PageStorageType {
        vstd::raw_ptr::ptr_from_data(self.ptr_data)
    }

    #[verifier(inline)]
    spec fn ptr(&self, idx: usize) -> *const PageStorageType {
        self.base_ptr().add(idx)
    }
}

trait ValidPageInfo {
    spec fn is_valid_pginfo(&self) -> bool;

    spec fn page_info(&self) -> Option<PageInfo>;

    spec fn page_storage(&self) -> Option<PageStorageType>;

    spec fn order(&self) -> usize;

    spec fn size(&self) -> usize;

    spec fn is_head(&self) -> bool;

    spec fn is_free(&self) -> bool;

    spec fn ens_write_page_info(&self, new: &Self, pfn: usize, pi: PageInfo) -> bool;
}

impl ValidPageInfo for FracTypedPerm<PageStorageType> {
    spec fn is_valid_pginfo(&self) -> bool {
        &&& self.page_info().is_some()
        &&& self.page_info().unwrap().spec_order() < MAX_ORDER
        &&& self.valid()
    }

    spec fn ens_write_page_info(&self, perm: &Self, pfn: usize, pi: PageInfo) -> bool {
        let old_perm = *self;
        &&& perm@ == old_perm@.update_value(perm.opt_value())
        &&& perm.is_valid_pginfo()
        &&& perm.page_info() == Some(pi)
    }

    spec fn page_info(&self) -> Option<PageInfo> {
        spec_page_info(self.opt_value())
    }

    spec fn page_storage(&self) -> Option<PageStorageType> {
        spec_page_storage_type(self.opt_value())
    }

    spec fn order(&self) -> usize {
        self.page_info().unwrap().spec_order()
    }

    #[verifier(inline)]
    spec fn size(&self) -> usize {
        1usize << self.order()
    }

    spec fn is_head(&self) -> bool {
        !matches!(self.page_info(), Some(PageInfo::Compound(_)))
    }

    spec fn is_free(&self) -> bool {
        matches!(self.page_info(), Some(PageInfo::Free(_)))
    }
}

// The `PageInfoDb` is a map of page info with the same shared status.
// It is used to track the page info stored in reserved memory regions.
// Those permissions should be grouped as (1usize<<order) continuous physical
// pages with consistent page type and order information (see
// new_unit_requires).
tracked struct PageInfoDb {
    ghost unit_start: usize,  // only for unit
    ghost id: PInfoGroupId,
    reserved: Map<usize, FracTypedPerm<PageStorageType>>,
}

impl PageInfoDb {
    /*** Basic spec functions ***/
    pub closed spec fn view(&self) -> Map<usize, FracTypedPerm<PageStorageType>> {
        self.reserved
    }

    pub closed spec fn id(&self) -> PInfoGroupId {
        self.id
    }

    pub closed spec fn unit_start(&self) -> usize {
        self.unit_start
    }

    /*** Useful spec functions ***/
    #[verifier(inline)]
    spec fn order(&self) -> usize {
        self@[self.unit_start].order()
    }

    #[verifier(inline)]
    spec fn dom(&self) -> Set<usize> {
        self@.dom()
    }

    spec fn npages(&self) -> nat {
        self.dom().len()
    }

    #[verifier(inline)]
    spec fn base_ptr(&self) -> *const PageStorageType {
        self.id().base_ptr()
    }

    #[verifier(inline)]
    spec fn ptr(&self, idx: usize) -> *const PageStorageType {
        self.id().ptr(idx)
    }

    #[verifier::inline]
    spec fn share_total(&self) -> (nat, nat) {
        (self.id().shares, self.id().total)
    }

    #[verifier(inline)]
    spec fn end(&self) -> int {
        self.unit_start + (1usize << self@[self.unit_start()].order())
    }

    #[verifier(inline)]
    spec fn page_info(&self, idx: usize) -> Option<PageInfo> {
        self@[idx].page_info()
    }

    #[verifier(inline)]
    spec fn is_head(&self, idx: usize) -> bool {
        self@[idx].is_head()
    }

    spec fn _is_unit(
        reserved: Map<usize, FracTypedPerm<PageStorageType>>,
        unit_start: usize,
    ) -> bool {
        let item = reserved[unit_start];
        let order = item.order();
        let npages = reserved.dom().len();
        let end = unit_start + (1usize << order);
        &&& end <= usize::MAX + 1
        &&& !reserved.dom().is_empty()
        &&& reserved.dom() =~= Set::new(|k| unit_start <= k < end)
        &&& item.is_head()
    }

    #[verifier(inline)]
    spec fn is_unit(&self) -> bool {
        &&& Self::_is_unit(self@, self.unit_start)
    }

    #[verifier(inline)]
    spec fn unit_head(&self) -> FracTypedPerm<PageStorageType>
        recommends
            self.is_unit(),
    {
        self@[self.unit_start]
    }

    #[verifier(inline)]
    spec fn dom_at(&self, idx: usize) -> Set<usize> {
        set_usize_range(idx, idx + self@[idx].size())
    }

    spec fn writable(&self) -> bool {
        self.id().shares == self.id().total > DEALLOC_PGINFO_SHARES
    }

    spec fn is_readonly_allocator_shares(&self) -> bool {
        AllocatorUnit::wf_share_total(self.id().shares, self.id().total)
    }

    spec fn marked_compound(
        reserved: Map<usize, FracTypedPerm<PageStorageType>>,
        head_idx: usize,
        order: usize,
    ) -> bool {
        let n = 1usize << order;
        &&& order < MAX_ORDER
        &&& forall|i|
            #![trigger reserved[i]]
            head_idx < i < head_idx + n ==> reserved[i].page_info() == Some(
                PageInfo::Compound(CompoundInfo { order }),
            )
    }

    spec fn wf_basic_at(
        item: FracTypedPerm<PageStorageType>,
        idx: usize,
        id: PInfoGroupId,
    ) -> bool {
        &&& item.is_valid_pginfo()
        &&& item.shares() == id.shares
        &&& item.total() == id.total
        &&& item.ptr() == id.ptr(idx)
    }

    #[verifier(inline)]
    spec fn wf_basic(&self, idx: usize) -> bool {
        Self::wf_basic_at(self@[idx], idx, self.id())
    }

    spec fn wf_follows(&self, idx: usize) -> bool {
        let next = idx + self@[idx].size();
        &&& self@[idx].is_head() ==> self.dom_at(idx).subset_of(self@.dom())
        &&& !self@[idx].is_head() ==> idx > 0 && self@.dom().contains((idx - 1) as usize)
        &&& (self@[idx].is_head() && next <= usize::MAX && self@.dom().contains(next as usize))
            ==> self@[next as usize].is_head()
    }

    /// A memory "unit" is a block of contiguous pages. This function ensures:
    /// - All pages within the unit are continuous and well-formed.
    /// - All pages within the unit have the same sharing state.
    /// - The unit is properly aligned.
    /// - If the unit contains compound pages, they follow the head page
    ///   correctly and consistently.
    spec fn new_unit_requires(
        reserved: Map<usize, FracTypedPerm<PageStorageType>>,
        id: PInfoGroupId,
        unit_start: usize,
        order: usize,
    ) -> bool {
        let item = reserved[unit_start];
        let info = item.page_info().unwrap();
        let end = (1usize << order) + unit_start;
        &&& item.order() == order
        &&& item.shares() == id.shares
        &&& item.total() == id.total
        &&& Self::_is_unit(reserved, unit_start)
        &&& forall|idx: usize|
            #![trigger reserved[idx]]
            unit_start <= idx < end ==> Self::wf_basic_at(reserved[idx], idx, id)
        &&& match info {
            PageInfo::Reserved(_) => true,
            PageInfo::Compound(ci) => { false },
            PageInfo::Slab(_) | PageInfo::File(_) => true,
            PageInfo::Allocated(ai) => { Self::marked_compound(reserved, unit_start, order) },
            PageInfo::Free(fi) => { Self::marked_compound(reserved, unit_start, order) },
        }
    }

    spec fn wf_unit(&self) -> bool {
        &&& Self::new_unit_requires(self@, self.id(), self.unit_start, self.order())
    }

    spec fn remove(&self, idx: usize) -> PageInfoDb {
        PageInfoDb {
            unit_start: self.unit_start,
            id: self.id,
            reserved: self@.remove_keys(self.dom_at(idx)),
        }
    }

    /// Extract a unit from the `PageInfoDb` at the given index.
    #[verifier(opaque)]
    spec fn restrict(&self, idx: usize) -> PageInfoDb {
        if self@[idx].is_head() {
            PageInfoDb {
                unit_start: idx,
                id: self.id(),
                reserved: self@.restrict(self.dom_at(idx)),
            }
        } else {
            PageInfoDb::empty(self.id)
        }
    }

    /// The invariant of the `PageInfoDb`
    #[verifier::type_invariant]
    spec fn wf(&self) -> bool {
        &&& forall|idx: usize|
            #![trigger self@[idx]]
            self@.dom().contains(idx) && self@[idx].is_head() ==> {
                &&& idx + self@[idx].size() <= usize::MAX + 1
            }
        &&& !self.is_unit() ==> forall|idx: usize|
            #![trigger self@[idx]]
            self@.dom().contains(idx) ==> {
                &&& self.wf_follows(idx)
                &&& self@[idx].is_head() ==> self.restrict(idx).wf_unit()
                &&& self.wf_basic(idx)
            }
        &&& self.is_unit() ==> self.wf_unit()
    }

    spec fn empty(id: PInfoGroupId) -> PageInfoDb {
        PageInfoDb { unit_start: 0, id, reserved: Map::empty() }
    }

    spec fn _info_dom(&self, order: usize) -> Set<usize> {
        self@.dom().filter(|i| self@[i].order() == order && self@[i].is_head())
    }

    /// The number of pages with the given order in the `PageInfoDb`.
    #[verifier(opaque)]
    spec fn nr_page(&self, order: usize) -> nat {
        self._info_dom(order).len()
    }

    spec fn _info_head_dom(&self, order: usize) -> Set<usize> {
        self@.dom().filter(|i| self@[i].order() == order && self@[i].is_head())
    }

    proof fn tracked_nr_page_pair(tracked &self, order: usize, order2: usize)
        requires
            order < order2 < 64,
        ensures
            self.nr_page(order) + self.nr_page(order2) * 2 <= self.npages(),
    {
        use_type_invariant(self);
        self.lemma_nr_page_pair(order, order2);
    }

    proof fn lemma_nr_page_pair(&self, order: usize, order2: usize)
        requires
            self.wf(),
            order < order2 < 64,
        ensures
            self.nr_page(order) + self.nr_page(order2) * 2 <= self.dom().len(),
    {
        reveal(PageInfoDb::nr_page);
        let s1 = self._info_dom(order);
        let s2 = self._info_dom(order2);
        assert(order2 >= 1);
        assert((1usize << order2) > 1);
        let r = |i: usize|
            if i < usize::MAX {
                (i + 1) as usize
            } else {
                0usize
            };
        let s3 = s2.map(r);
        assert forall|x1: usize, x2: usize| #[trigger] r(x1) == #[trigger] r(x2) implies x1
            == x2 by {}
        vstd::set_lib::lemma_map_size(s2, s3, r);
        assert forall|i| #[trigger] s3.contains(i) implies !s1.contains(i) && !s2.contains(i)
            && self.dom().contains(i) by {
            let head_i = (i - 1) as usize;
            assert(s2.contains(head_i));
            self.lemma_restrict(head_i);
            reveal(PageInfoDb::restrict);
            let e2 = self@[head_i];
            let e3 = self@[i];
            assert(self.is_head(head_i));
            assert(!self.is_head(i));
        }
        assert(s1.disjoint(s2));
        vstd::set_lib::lemma_set_disjoint_lens(s1, s2);
        vstd::set_lib::lemma_set_disjoint_lens(s1 + s2, s3);
        let s = s1 + s2 + s3;
        assert(s.subset_of(self@.dom()));
    }

    proof fn lemma_nr_page_npages(&self, order: usize)
        requires
            self.wf(),
        ensures
            self.nr_page(order) <= self.npages(),
    {
        reveal(PageInfoDb::nr_page);
        assert(self._info_dom(order).subset_of(self@.dom()));
    }

    spec fn const_nr_page(npages: nat, order: usize) -> nat {
        if order < MAX_ORDER && (1usize << order) == npages {
            1
        } else {
            0
        }
    }

    proof fn tracked_unit_nr_pages(tracked &self)
        requires
            self.is_unit(),
        ensures
            forall|order| #[trigger]
                self.nr_page(order) == Self::const_nr_page(self.npages(), order),
            self.npages() == 1usize << (self@[self.unit_start()].order()),
    {
        use_type_invariant(self);
        self.proof_unit_nr_page();
    }

    proof fn proof_unit_nr_page(&self)
        requires
            self.wf(),
            self.is_unit(),
        ensures
            forall|order| #[trigger]
                self.nr_page(order) == Self::const_nr_page(self.npages(), order),
            self.npages() == 1usize << (self@[self.unit_start()].order()),
    {
        reveal(PageInfoDb::nr_page);

        assert(1usize << self@[self.unit_start()].order() == self.npages()) by {
            lemma_set_usize_range(
                self.unit_start,
                self.unit_start + (1usize << self@[self.unit_start()].order()),
            );
        }
        assert forall|order| #[trigger]
            self.nr_page(order) == Self::const_nr_page(self.npages(), order) by {
            if (order < MAX_ORDER && (1usize << order) == self.npages()) {
                assert(order == self@[self.unit_start()].order());
            }
            self.lemma_unit_nr_page(order);
        }
    }

    proof fn lemma_unit_nr_page(&self, order: usize)
        requires
            self.wf(),
            self.is_unit(),
        ensures
            self.nr_page(order) == Self::const_nr_page(self.npages(), order),
            self.npages() == 1usize << (self@[self.unit_start()].order()),
    {
        reveal(PageInfoDb::nr_page);
        if order == self@[self.unit_start()].order() {
            assert(self._info_dom(order) =~= set![self.unit_start]);
            //assert(self._info_dom(order) =~= self@.dom());
        } else {
            assert(self._info_dom(order).is_empty());
        }
        lemma_set_usize_range(self.unit_start, self.unit_start + (1usize << self.order()));
    }

    proof fn lemma_restrict(&self, idx: usize)
        requires
            self.wf(),
            self.is_head(idx),
            self@.dom().contains(idx),
        ensures
            self.restrict(idx).wf(),
            self.restrict(idx).is_unit(),
            self.restrict(idx)@.dom() =~= self.dom_at(idx),
            forall|i|
                #![trigger self@[i]]
                #![trigger self.restrict(idx)@[i]]
                idx <= i < idx + self@[idx].size() ==> self.restrict(idx)@[i] == self@[i],
    {
        reveal(PageInfoDb::restrict);
        if self.is_unit() {
            assert(idx == self.unit_start);
            assert(self.restrict(idx)@ =~= self@);
            assert(self.restrict(idx).wf());
        } else {
            assert(self.restrict(idx).is_unit());
            assert(self.restrict(idx).wf_unit());
        }
    }

    spec fn new(
        unit_start: usize,
        id: PInfoGroupId,
        reserved: Map<usize, FracTypedPerm<PageStorageType>>,
    ) -> Self {
        PageInfoDb { unit_start, id, reserved }
    }

    spec fn ens_split_inner(&self, left: Self, right: Self) -> bool {
        &&& left.dom().disjoint(right.dom())
        &&& left@ =~= self@.restrict(left.dom())
        &&& right@ =~= self@.restrict(right.dom())
        &&& left.dom() + right.dom() =~= self.dom()
        &&& left.id() == self.id()
        &&& right.id() == self.id()
    }

    spec fn ens_split(&self, left: Self, right: Self) -> bool {
        &&& left.dom().disjoint(right.dom())
        &&& left@ == self@.restrict(left.dom())
        &&& right@ == self@.restrict(right.dom())
        &&& left.dom() + right.dom() == self.dom()
        &&& left.id() == self.id()
        &&& right.id() == self.id()
    }

    spec fn ens_add_nr_pages(&self, left: Self, right: Self) -> bool {
        &&& self.npages() == left.npages() + right.npages()
        &&& forall|o: usize| #[trigger] self.nr_page(o) == left.nr_page(o) + right.nr_page(o)
    }

    spec fn ens_add_unit_nr_pages(&self, left: Self, order: usize) -> bool {
        &&& self.npages() == left.npages() + (1usize << order)
        &&& forall|o: usize| order != o ==> #[trigger] self.nr_page(o) == left.nr_page(o)
        &&& self.nr_page(order) == left.nr_page(order) + 1
    }

    /** Constructors **/
    proof fn tracked_empty(id: PInfoGroupId) -> (tracked ret: PageInfoDb)
        ensures
            ret == PageInfoDb::empty(id),
    {
        let tracked reserved = Map::tracked_empty();
        PageInfoDb { unit_start: 0, id, reserved }
    }

    proof fn proof_split_nr_page(&self, left: Self, right: Self)
        requires
            self.wf(),
            self.ens_split_inner(left, right),
        ensures
            self.ens_add_nr_pages(left, right),
    {
        self.lemma_split_nr_page(left, right, 0);
        assert forall|order: usize| #[trigger]
            self.nr_page(order) == left.nr_page(order) + right.nr_page(order) by {
            self.lemma_split_nr_page(left, right, order);
        }
    }

    proof fn lemma_split_nr_page(&self, left: Self, right: Self, order: usize)
        requires
            self.wf(),
            self.ens_split_inner(left, right),
        ensures
            self.nr_page(order) == left.nr_page(order) + right.nr_page(order),
            self.npages() == left.npages() + right.npages(),
    {
        reveal(PageInfoDb::nr_page);
        let s1 = left._info_dom(order);
        let s2 = right._info_dom(order);
        let s = self._info_dom(order);
        vstd::set_lib::lemma_set_disjoint_lens(left.dom(), right.dom());
        vstd::set_lib::lemma_set_disjoint_lens(s1, s2);
        assert(s1 + s2 =~= s);
    }

    proof fn lemma_remove(&self, i: usize)
        requires
            self.wf(),
            self.dom().contains(i),
            self.is_head(i),
        ensures
            self.remove(i).npages() == self.npages() - self@[i].size(),
            forall|j|
                self.is_head(j) && i != j && self.dom().contains(j) ==> #[trigger] self.remove(
                    i,
                ).restrict(j) == self.restrict(j),
    {
        let left = self.remove(i);
        assert forall|j|
            self.is_head(j) && i != j && self.dom().contains(j) implies #[trigger] left.restrict(j)
            == self.restrict(j) by {
            self.lemma_remove_restrict(i, j);
        }
        let s = self.dom_at(i);
        assert(left.dom() + s =~= self@.dom());
        vstd::set_lib::lemma_set_disjoint_lens(left.dom(), s);
        lemma_set_usize_range(i, i + self@[i].size());
    }

    spec fn merge(&self, other: Self) -> Self {
        PageInfoDb {
            unit_start: self.unit_start,
            id: self.id,
            reserved: self@.union_prefer_right(other@),
        }
    }

    #[verifier(spinoff_prover)]
    proof fn lemma_merge_wf(&self, other: Self)
        requires
            self.wf(),
            other.wf(),
            other.is_unit(),
            self.id() == other.id(),
            self.dom().disjoint(other.dom()),
        ensures
            self.merge(other).wf(),
    {
        reveal(PageInfoDb::restrict);
        let new = self.merge(other);

        if !new.is_unit() {
            assert forall|idx: usize| #![trigger new@[idx]] new@.dom().contains(idx) implies {
                &&& new.wf_follows(idx)
            } by {
                let next = idx + new@[idx].size();
                let item = new@[next as usize];
                assert(other@[other.unit_start].is_head());
                if (new@[idx].is_head() && next <= usize::MAX && new@.dom().contains(
                    next as usize,
                )) {
                    if other.unit_start <= next < other.end() {
                        if (!item.is_head()) {
                            assert(new@[next as usize] == other@[next as usize]);
                            assert(next > other.unit_start);
                            assert(self.dom().contains((next - 1) as usize));
                        }
                    } else if other.unit_start <= idx < other.end() {
                        assert(item.is_head());
                    }
                }
            }
            assert forall|idx: usize|
                #![trigger new@[idx]]
                new@.dom().contains(idx) && new@[idx].is_head() implies {
                new.restrict(idx).wf_unit()
            } by {
                if self.dom().contains(idx) {
                    self.lemma_restrict(idx);
                    assert(self.restrict(idx).wf());
                    assert(self.restrict(idx)@ =~= new.restrict(idx)@);
                } else {
                    assert(other.dom().contains(idx));
                    other.lemma_restrict(idx);
                    assert(other.restrict(idx).wf());
                    assert(other.restrict(idx)@ =~= new.restrict(idx)@);
                }
            }
        } else {
            if new.unit_start() != other.unit_start() {
                assert(other.dom().subset_of(new.dom()));
                assert(other@[other.unit_start()].is_head());
                assert(new@[other.unit_start()].is_head());
            }
            assert(new@ =~= other@);
        }
    }

    #[verifier(spinoff_prover)]
    proof fn lemma_remove_wf(&self, i: usize)
        requires
            self.wf(),
            self.dom().contains(i),
            self.is_head(i),
        ensures
            self.remove(i).wf(),
    {
        reveal(PageInfoDb::restrict);
        self.lemma_restrict(i);
        lemma_set_usize_range(i, i + self@[i].size());
        broadcast use lemma_set_usize_range;

        self.lemma_remove(i);
    }

    #[verifier(spinoff_prover)]
    proof fn lemma_remove_restrict(&self, i: usize, j: usize)
        requires
            self.wf(),
            self.dom().contains(i),
            self.dom().contains(j),
            self.is_head(i),
            self.is_head(j),
            i != j,
        ensures
            self.remove(i).restrict(j) == self.restrict(j),
    {
        reveal(PageInfoDb::restrict);
        self.lemma_head_no_overlap(i, j);
        assert(self.remove(i).restrict(j)@ =~= self.restrict(j)@);
    }

    broadcast proof fn lemma_head_no_overlap(&self, i: usize, j: usize)
        requires
            self.wf(),
            self.is_head(i),
            self.is_head(j),
            i != j,
            self.dom().contains(i),
            self.dom().contains(j),
        ensures
            #![trigger self@[i], self@[j]]
            i + self@[i].size() <= j || i >= j + self@[j].size(),
    {
        reveal(PageInfoDb::restrict);
        self.lemma_restrict(i);
        self.lemma_restrict(j);
    }

    proof fn lemma_wf_recursive(&self)
        requires
            self.wf(),
        ensures
            forall|idx| #![trigger self@[idx]] self.dom().contains(idx) ==> self.restrict(idx).wf(),
    {
        reveal(PageInfoDb::restrict);
        assert forall|idx| #![trigger self@[idx]] self.dom().contains(idx) implies self.restrict(
            idx,
        ).wf() by {
            if self.is_head(idx) {
                self.lemma_restrict(idx);
            }
        }
    }

    proof fn tracked_new_unit(
        order: usize,
        unit_start: usize,
        id: PInfoGroupId,
        tracked reserved: Map<usize, FracTypedPerm<PageStorageType>>,
    ) -> (tracked ret: Self)
        requires
            order < MAX_ORDER,
            unit_start + (1usize << order) <= usize::MAX + 1,
            reserved.dom() =~= Set::new(|k| unit_start <= k < unit_start + (1usize << order)),
            reserved[unit_start].is_head(),
            reserved[unit_start].order() == order,
            PageInfoDb::new_unit_requires(reserved, id, unit_start, order),
        ensures
            ret.is_unit(),
            ret == PageInfoDb::new(unit_start, id, reserved),
            ret@ == reserved,
            ret.npages() == (1usize << order),
            forall|order| #[trigger] ret.nr_page(order) == Self::const_nr_page(ret.npages(), order),
    {
        reveal(PageInfoDb::restrict);
        lemma_set_usize_range(unit_start, unit_start + (1usize << order));
        let tracked ret = PageInfoDb { unit_start, id, reserved };
        ret.proof_unit_nr_page();
        ret
    }

    proof fn tracked_remove_unit(tracked &mut self, idx: usize) -> (tracked unit: PageInfoDb)
        requires
            old(self).dom().contains(idx),
            old(self).is_head(idx),
        ensures
            old(self).ens_split(*self, unit),
            self@ == old(self)@.remove_keys(unit@.dom()),
            self.id() == old(self).id(),
            self.npages() == old(self).npages() - old(self)@[idx].size(),
            unit.is_unit(),
            unit.unit_start() == idx,
            old(self).ens_add_nr_pages(*self, unit),
    {
        use_type_invariant(&*self);
        reveal(PageInfoDb::restrict);
        self.lemma_restrict(idx);
        self.lemma_remove(idx);
        self.lemma_remove_wf(idx);
        let order = self@[idx].order();
        let s = self.dom_at(idx);
        let tracked ret = self.reserved.tracked_remove_keys(s);
        assert(ret.dom() == s);
        assert(order == ret[idx].order());
        let tracked ret = PageInfoDb::tracked_new_unit(order, idx, self.id(), ret);
        assert(old(self).ens_split_inner(*self, ret));
        old(self).proof_split_nr_page(*self, ret);
        ret
    }

    spec fn ens_unshare_for_write(&self, new: Self, unit: &PageInfoDb) -> bool {
        &&& new@ == self@.remove_keys(unit@.dom())
        &&& new.id() == self.id()
        &&& self.ens_add_unit_nr_pages(new, unit.order())
    }

    proof fn tracked_unshare_for_write(tracked &mut self, tracked unit: &mut PageInfoDb)
        requires
            old(self).dom().contains(old(unit).unit_start()),
            old(unit).is_unit(),
            old(unit).id().ptr_data == old(self).id().ptr_data,
        ensures
            unit.is_unit(),
            unit.npages() == old(unit).npages(),
            unit.unit_start() == old(unit).unit_start(),
            unit.id() == old(unit).id().update_shares(
                old(unit).id().shares + old(self).id().shares,
            ),
            unit.unit_head()@ == old(unit).unit_head()@.update_shares(unit.id().shares),
            forall|order: usize| #[trigger] old(unit).nr_page(order) == unit.nr_page(order),
            self@ == old(self)@.remove_keys(unit@.dom()),
            self.id() == old(self).id(),
            old(self).ens_add_unit_nr_pages(*self, unit.order()),
    {
        let idx = unit.unit_start();
        use_type_invariant(&*self);
        use_type_invariant(&*unit);

        assert(self@[idx].ptr() == unit@[idx].ptr());
        self.reserved.tracked_borrow(idx).is_same(unit.reserved.tracked_borrow(idx));

        assert(self@[idx].valid());
        assert(unit@[idx].valid());
        unit.tracked_unit_nr_pages();
        let order = unit@[idx].order();
        let tracked unit2 = self.tracked_remove_unit(idx);
        unit2.tracked_unit_nr_pages();
        let tracked mut tmp = PageInfoDb::tracked_empty(arbitrary());
        tracked_swap(unit, &mut tmp);
        let tracked PageInfoDb { unit_start, mut reserved, mut id } = tmp;
        tracked_map_merge_right_shares(&mut reserved, unit2.reserved);
        id.shares = id.shares + unit2.id().shares;
        *unit = PageInfoDb::tracked_new_unit(order, unit_start, id, reserved);
    }

    /// Insert a new unit with the same share into the `PageInfoDb` and
    /// returns remaining shares.
    proof fn tracked_insert_unit(
        tracked &mut self,
        order: usize,
        unit_start: usize,
        id: PInfoGroupId,
        tracked reserved: Map<usize, FracTypedPerm<PageStorageType>>,
    ) -> (tracked unit: PageInfoDb)
        requires
            order < MAX_ORDER,
            unit_start + (1usize << order) <= usize::MAX + 1,
            reserved.dom() =~= Set::new(|k| unit_start <= k < unit_start + (1usize << order)),
            reserved[unit_start].is_head(),
            reserved[unit_start].order() == order,
            PageInfoDb::new_unit_requires(reserved, id, unit_start, order),
            old(self).dom().disjoint(reserved.dom()),
            old(self).id() == id.update_shares(old(self).id().shares),
            0 < old(self).id().shares < id.shares,
        ensures
            unit.is_unit(),
            unit.id() == id.update_shares((id.shares - old(self).id().shares) as nat),
            unit.unit_head()@ == reserved[unit_start]@.update_shares(unit.id().shares),
            unit.unit_start() == unit_start,
            unit.npages() == (1usize << order),
            self.id() == old(self).id(),
            self@.dom() == old(self)@.dom() + reserved.dom(),
            self@ =~= old(self)@.union_prefer_right(self@.restrict(reserved.dom())),
            self.ens_add_unit_nr_pages(*old(self), order),
    {
        let tracked mut info = PageInfoDb::tracked_new_unit(order, unit_start, id, reserved);
        self.tracked_insert_shares(&mut info);
        info
    }

    #[verifier(spinoff_prover)]
    proof fn tracked_insert_shares(tracked &mut self, tracked unit: &mut PageInfoDb)
        requires
            old(unit).is_unit(),
            0 < old(self).id().shares < old(unit).id().shares,
            old(self).dom().disjoint(old(unit).dom()),
            old(self).id() == old(unit).id().update_shares(old(self).id().shares),
        ensures
            unit.is_unit(),
            unit.unit_head()@ == old(unit).unit_head()@.update_shares(unit.id().shares),
            unit.id() == old(unit).id().update_shares(
                (old(unit).id().shares - old(self).id().shares) as nat,
            ),
            unit.unit_start() == old(unit).unit_start(),
            self.id() == old(self).id(),
            self@.dom() == old(self)@.dom() + old(unit)@.dom(),
            self@ =~= old(self)@.union_prefer_right(self@.restrict(unit@.dom())),
            forall|order: usize| #[trigger] old(unit).nr_page(order) == unit.nr_page(order),
            self.ens_add_unit_nr_pages(*old(self), unit.order()),
    {
        use_type_invariant(&*unit);
        unit.tracked_unit_nr_pages();
        let tracked new_unit = unit.tracked_split_shares(self.id().shares);
        assert(old(unit).dom() == new_unit.dom());
        use_type_invariant(&*self);
        use_type_invariant(&new_unit);
        self.lemma_merge_wf(new_unit);
        new_unit.tracked_unit_nr_pages();
        unit.tracked_unit_nr_pages();
        self.reserved.tracked_union_prefer_right(new_unit.reserved);
        self.proof_split_nr_page(*old(self), new_unit);
        assert(self@.dom() =~= old(self)@.dom() + old(unit)@.dom());
    }

    proof fn tracked_split_shares(tracked &mut self, shares: nat) -> (tracked unit: PageInfoDb)
        requires
            old(self).is_unit(),
            0 < shares < old(self).id().shares,
        ensures
            self.is_unit(),
            self.unit_head()@ == old(self).unit_head()@.update_shares(self.id().shares),
            unit.unit_head()@ == old(self).unit_head()@.update_shares(shares),
            self.unit_start() == old(self).unit_start() == unit.unit_start(),
            old(self).npages() == self.npages() == unit.npages(),
            self.id() == old(self).id().update_shares((old(self).id().shares - shares) as nat),
            unit.is_unit(),
            unit.id() == old(self).id().update_shares(shares),
            forall|order: usize| #[trigger]
                old(self).nr_page(order) == self.nr_page(order) == unit.nr_page(order),
    {
        use_type_invariant(&*self);
        self.proof_unit_nr_page();
        let idx = self.unit_start();
        let order = self@[idx].order();
        let tracked mut tmp = PageInfoDb::tracked_empty(arbitrary());
        tracked_swap(self, &mut tmp);
        let tracked PageInfoDb { unit_start, mut reserved, mut id } = tmp;
        let tracked new_reserved = tracked_map_shares(&mut reserved, shares);
        let mut ret_id = id;
        ret_id.shares = shares;
        id.shares = (id.shares - shares) as nat;
        *self = PageInfoDb::tracked_new_unit(order, unit_start, id, reserved);
        use_type_invariant(&*self);
        self.proof_unit_nr_page();
        PageInfoDb::tracked_new_unit(order, unit_start, ret_id, new_reserved)
    }

    proof fn tracked_is_same_info<T: UnitType>(
        tracked &self,
        tracked other: &PgUnitPerm<T>,
        pfn: usize,
    )
        requires
            self.dom().contains(pfn),
            !other.info@.is_empty(),
            other.info.unit_start() <= pfn < other.info.end(),
            self.base_ptr() == other.info.base_ptr(),
        ensures
            self@[pfn].points_to() == other.info@[pfn].points_to(),
    {
        use_type_invariant(self);
        use_type_invariant(other);
        use_type_invariant(&other.info);
        self.reserved.tracked_borrow(pfn).is_same(other.info.reserved.tracked_borrow(pfn));
    }

    proof fn tracked_borrow(tracked &self, idx: usize) -> (tracked item: &FracTypedPerm<
        PageStorageType,
    >)
        requires
            self.dom().contains(idx),
        ensures
            item == self@[idx],
            item.is_valid_pginfo(),
    {
        use_type_invariant(self);
        reveal(PageInfoDb::wf_basic_at);
        self.reserved.tracked_borrow(idx)
    }

    proof fn tracked_expose(tracked self) -> (tracked ret: Map<
        usize,
        FracTypedPerm<PageStorageType>,
    >)
        ensures
            ret == self.reserved,
            self.wf(),
    {
        use_type_invariant(&self);
        let tracked PageInfoDb { id, reserved, .. } = self;
        reserved
    }
}

} // verus!

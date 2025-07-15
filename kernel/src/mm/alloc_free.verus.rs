// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// Proofs for the free pages.
// The allocator should have memory permissions for all free pages.
// The free_page counter should be consistant with the actual free pages defined by nr_free.
verus! {

/// Each free memory page block should include PgUnitPerm to define
/// 1. the full permission to access the free memory page block. The free memory
/// access permission (`avail`) is defined in a structure to reflect the list of
/// free list structure used in MemoryRegion. Each free list is a sequence of
/// free pages with the same order.
/// 2. Remaining shares of page info for the free page.
///
/// The mr_map defines one share of memory mapping permission to indicate that
/// the allocator should remain at least one share of memory mapping permission.
tracked struct MRFreePerms {
    tracked avail: Seq<Seq<PgUnitPerm<DeallocUnit>>>,
    ghost mr_map: MemRegionMapping,
}

impl MRFreePerms {
    /// The list of number of free page block for each order.
    spec fn nr_free(&self) -> Seq<usize> {
        self.avail.map_values(|perms: Seq<PgUnitPerm<DeallocUnit>>| perms.len() as usize)
    }

    /// The list of free pages for each order.
    /// ret[order][i] is the pfn of the i-th free page in the order-th free list.
    #[verifier(inline)]
    spec fn next_lists(&self) -> Seq<Seq<usize>> {
        Seq::new(self.avail.len(), |i| Seq::new(self.avail[i].len(), |k| self.avail[i][k].pfn()))
    }

    /// The next free page for the given order.
    spec fn next_page(&self, order: usize) -> usize {
        let perms = self.avail[order as int];
        if perms.len() > 0 {
            perms.last().pfn()
        } else {
            0
        }
    }

    /// The next free page for each order.
    spec fn next_pages(&self) -> Seq<usize> {
        self.avail.map_values(
            |perms: Seq<PgUnitPerm<DeallocUnit>>|
                if perms.len() > 0 {
                    perms.last().pfn()
                } else {
                    0
                },
        )
    }

    spec fn mr_map(&self) -> MemRegionMapping {
        self.mr_map
    }

    spec fn pg_params(&self) -> PageCountParam<MAX_ORDER> {
        self.mr_map.pg_params()
    }

    #[verifier(inline)]
    spec fn valid_pfn_order(&self, pfn: usize, order: usize) -> bool {
        &&& self.pg_params().valid_pfn_order(pfn, order)
        &&& pfn > 0
    }

    /// Create a new MRFreePerms with an empty free list.
    proof fn tracked_empty(mr_map: MemRegionMapping) -> (tracked ret: Self)
        requires
            mr_map.wf(),
        ensures
            ret.nr_free() == Seq::new(MAX_ORDER as nat, |order| 0usize),
            ret.avail === Seq::new(MAX_ORDER as nat, |order| Seq::empty()),
            ret.mr_map() == mr_map,
    {
        let tracked ret = MRFreePerms { avail: tracked_empty_seq_of_seq(MAX_ORDER as nat), mr_map };
        assert(ret.nr_free() =~= Seq::new(MAX_ORDER as nat, |order| 0usize));
        ret
    }

    spec fn wf_next(&self, order: usize, i: int) -> bool {
        &&& self.ens_perm_next(order, i, self.avail[order as int][i])
    }

    #[verifier(opaque)]
    spec fn wf_strict(&self) -> bool {
        let avail = self.avail;
        forall|o: int, i: int|
            #![trigger avail[o][i]]
            0 <= o < MAX_ORDER && 0 <= i < avail[o].len() ==> self.wf_next(o as usize, i)
    }

    /// Prove that the permission is valid for the given order and index.
    /// The PFN and order must be valid within the memory region.
    /// The permission should be a valid to cover page block.
    /// The PFN must be larger than 0 and the PageInfo must indicate the PageType is Free.
    #[verifier(inline)]
    spec fn ens_perm_valid(&self, order: usize, i: int, perm: PgUnitPerm<DeallocUnit>) -> bool {
        let pfn = perm.info.unit_start();
        &&& perm == self.avail[order as int][i]
        &&& self.pg_params().valid_pfn_order(pfn, order)
        &&& perm.wf_pfn_order(self.mr_map, pfn, order)
        &&& perm.page_type() == PageType::Free
        &&& pfn > 0
    }

    #[verifier(inline)]
    spec fn ens_perm_next(&self, order: usize, i: int, perm: PgUnitPerm<DeallocUnit>) -> bool {
        let next_perm = self.avail[order as int][i - 1];
        &&& match perm.page_info() {
            Some(PageInfo::Free(FreeInfo { order, next_page })) => {
                &&& (next_page == 0 <==> i == 0)
                &&& next_page > 0 ==> {
                    &&& next_page == next_perm.pfn()
                }
            },
            _ => { false },
        }
    }

    #[verifier(inline)]
    spec fn ens_perm_strict(&self, order: usize, i: int, perm: PgUnitPerm<DeallocUnit>) -> bool {
        &&& self.ens_perm_valid(order, i, perm)
        &&& self.ens_perm_next(order, i, perm)
    }

    #[verifier(opaque)]
    spec fn wf_at(&self, order: usize, i: int) -> bool {
        let perm = self.avail[order as int][i];
        self.ens_perm_valid(order, i, perm)
    }

    #[verifier::type_invariant]
    spec fn wf(&self) -> bool {
        &&& self.mr_map.wf()
        &&& self.avail.len() == MAX_ORDER
        &&& forall|o: int, i: int|
            #![trigger self.avail[o][i]]
            0 <= o < MAX_ORDER && 0 <= i < self.avail[o].len() ==> self.wf_at(o as usize, i)
    }

    proof fn tracked_perm_disjoint_rec1(
        tracked &self,
        pfn: usize,
        order: usize,
        tracked perm: &mut RawPerm,
        o: usize,
        len: nat,
    )
        requires
            old(perm).wf_pfn_order(self.mr_map, pfn, order),
            0 <= len <= self.avail[o as int].len(),
            0 <= o < MAX_ORDER,
            0 <= order < MAX_ORDER,
        ensures
            *perm == *old(perm),
            forall|i: int|
                #![trigger self.avail[o as int][i]]
                0 <= i < len ==> order_disjoint(self.avail[o as int][i].pfn(), o, pfn, order),
        decreases len,
    {
        reveal(MRFreePerms::wf_at);
        if len > 0 {
            self.tracked_perm_disjoint_rec1(pfn, order, perm, o, (len - 1) as nat);
            use_type_invariant(&*self);
            let pfn2 = self.avail[o as int][len - 1].pfn();
            let tracked perm2 = self.avail.tracked_borrow(o as int).tracked_borrow(len - 1);
            self.mr_map.raw_perm_order_disjoint(pfn, order, pfn2, o, perm, &perm2.mem);
        }
    }

    proof fn tracked_perm_disjoint_rec2(
        tracked &self,
        pfn: usize,
        order: usize,
        tracked perm: &mut RawPerm,
        max_order: usize,
    )
        requires
            old(perm).wf_pfn_order(self.mr_map(), pfn, order),
            0 <= order < MAX_ORDER,
            0 <= max_order <= MAX_ORDER,
        ensures
            *perm == *old(perm),
            forall|o: usize, i: int|
                #![trigger self.avail[o as int][i].pfn()]
                0 <= o < max_order && 0 <= i < self.avail[o as int].len() ==> order_disjoint(
                    self.avail[o as int][i].pfn(),
                    o,
                    pfn,
                    order,
                ),
        decreases max_order,
    {
        if max_order > 0 {
            self.tracked_perm_disjoint_rec2(pfn, order, perm, (max_order - 1) as usize);
            let o = (max_order - 1) as usize;
            self.tracked_perm_disjoint_rec1(pfn, order, perm, o, self.avail[o as int].len());
        }
    }

    // If providing a mutable tracked perm, the tracked free perms must be disjoint with it.
    proof fn tracked_perm_disjoint(
        tracked &self,
        tracked perm: &mut RawPerm,
        pfn: usize,
        order: usize,
    )
        requires
            old(perm).wf_pfn_order(self.mr_map(), pfn, order),
            0 <= order < MAX_ORDER,
        ensures
            *perm == *old(perm),
            forall|o: usize, i: int|
                #![trigger self.avail[o as int][i].pfn()]
                0 <= o < MAX_ORDER && 0 <= i < self.avail[o as int].len() ==> order_disjoint(
                    self.avail[o as int][i].pfn(),
                    o,
                    pfn,
                    order,
                ),
    {
        self.tracked_perm_disjoint_rec2(pfn, order, perm, MAX_ORDER);
    }

    // Any pair of free pages in the free lists are disjoint.
    proof fn tracked_disjoint_pfn(tracked &mut self, o1: usize, i: int, o2: usize, j: int)
        requires
            (o1, i) != (o2, j),
            0 <= o1 < MAX_ORDER,
            0 <= o2 < MAX_ORDER,
            0 <= i < old(self).avail[o1 as int].len() as int,
            0 <= j < old(self).avail[o2 as int].len() as int,
        ensures
            *self == *old(self),
            order_disjoint(self.avail[o1 as int][i].pfn(), o1, self.avail[o2 as int][j].pfn(), o2),
    {
        reveal(MRFreePerms::wf_at);
        use_type_invariant(&*self);
        let pfn1 = self.avail[o1 as int][i].pfn();
        let pfn2 = self.avail[o2 as int][j].pfn();
        let tracked mut tmp = MRFreePerms::tracked_empty(old(self).mr_map);
        tracked_swap(&mut tmp, self);
        let tracked MRFreePerms { mut avail, mr_map } = tmp;

        let tracked mut a = avail.tracked_remove(o1 as int);
        let olda = a;
        let tracked mut p1 = a.tracked_remove(i);
        let tracked p2 = if o1 < o2 {
            avail.tracked_borrow(o2 - 1).tracked_borrow(j)
        } else if o1 > o2 {
            avail.tracked_borrow(o2 as int).tracked_borrow(j)
        } else {
            if i < j {
                a.tracked_borrow(j - 1)
            } else {
                a.tracked_borrow(j)
            }
        };
        use_type_invariant(&p1);
        self.mr_map.raw_perm_order_disjoint(pfn1, o1, pfn2, o2, &mut p1.mem, &p2.mem);
        a.tracked_insert(i, p1);
        avail.tracked_insert(o1 as int, a);
        assert(a =~= olda);
        assert(avail =~= old(self).avail);
        *self = MRFreePerms { avail, mr_map };
    }

    proof fn tracked_next_no_dup_len(tracked &mut self, o: usize)
        requires
            0 <= o < MAX_ORDER,
        ensures
            *self == *old(self),
            self.next_lists()[o as int].no_duplicates(),
            self.avail[o as int].len() <= self.pg_params().page_count,
            self.avail[o as int].len() * (1usize << o) <= self.pg_params().page_count + (1usize
                << o) - 1,
    {
        reveal(MRFreePerms::wf_at);
        use_type_invariant(&*self);

        let next_seq = self.next_lists()[o as int];
        assert(next_seq.len() == self.avail[o as int].len());
        self.tracked_next_is_disjoint_rec(o, 0, next_seq.len() as int);
        lemma_order_disjoint_len(next_seq, o, self.pg_params().page_count);
    }

    proof fn tracked_next_is_disjoint_rec(tracked &mut self, o: usize, start: int, end: int)
        requires
            0 <= o < MAX_ORDER,
            0 <= start <= end <= old(self).avail[o as int].len(),
        ensures
            *self == *old(self),
            forall|i, j|
                #![trigger self.avail[o as int][i], self.avail[o as int][j]]
                start <= i < end && start <= j < end && i != j ==> order_disjoint(
                    self.avail[o as int][i].pfn(),
                    o,
                    self.avail[o as int][j].pfn(),
                    o,
                ),
        decreases end - start,
    {
        if start + 1 < end {
            self.tracked_next_is_disjoint_rec(o, start + 1, end);
            self.tracked_next_is_disjoint_rec(o, start, end - 1);
            self.tracked_disjoint_pfn(o, start, o, end - 1);
            assert forall|i, j|
                #![trigger self.avail[o as int][i], self.avail[o as int][j]]
                start <= i < end && start <= j < end && i != j ==> order_disjoint(
                    self.avail[o as int][i].pfn(),
                    o,
                    self.avail[o as int][j].pfn(),
                    o,
                ) by {}
        }
    }

    /// Prove the side effect of inserting a new free page block into the free list.
    #[verifier::spinoff_prover]
    proof fn tracked_insert(
        tracked &mut self,
        order: usize,
        idx: int,
        pfn: usize,
        tracked perm: PgUnitPerm<DeallocUnit>,
    )
        requires
            0 <= order < MAX_ORDER,
            0 <= idx <= old(self).avail[order as int].len() as int,
            old(self).valid_pfn_order(pfn, order),
            perm.wf_pfn_order(old(self).mr_map, pfn, order),
            perm.page_type() == PageType::Free,
        ensures
            self.avail == old(self).avail.update(
                order as int,
                old(self).avail[order as int].insert(idx, perm),
            ),
            self.avail[order as int] == old(self).avail[order as int].insert(idx, perm),
            self.mr_map() == old(self).mr_map(),
            self.pg_params() == old(self).pg_params(),
            self.nr_free() == old(self).nr_free().update(
                order as int,
                (old(self).nr_free()[order as int] + 1) as usize,
            ),
            old(self).nr_free()[order as int] <= old(self).pg_params().page_count - 1,
            old(self).nr_free()[order as int] * (1usize << order) <= old(
                self,
            ).pg_params().page_count - 1,
    {
        reveal(MRFreePerms::wf_at);
        use_type_invariant(&*self);
        let tracked mut tmp = MRFreePerms::tracked_empty(old(self).mr_map());
        tracked_swap(&mut tmp, self);
        let tracked MRFreePerms { mut avail, mr_map } = tmp;
        let tracked mut a = avail.tracked_remove(order as int);
        a.tracked_insert(idx, perm);
        avail.tracked_insert(order as int, a);

        *self = MRFreePerms { avail, mr_map: mr_map };
        assert(self.avail =~= old(self).avail.update(
            order as int,
            old(self).avail[order as int].insert(idx, perm),
        ));
        assert(old(self).nr_free()[order as int] == old(self).avail[order as int].len() as usize);
        self.tracked_next_no_dup_len(order);
        let gap = 1usize << order;
        lemma_mul_is_distributive_add_other_way(
            gap as int,
            old(self).nr_free()[order as int] as int,
            1,
        );

        assert(self.avail[order as int].len() as usize == (old(self).nr_free()[order as int]
            + 1) as usize);
        assert forall|o: usize| 0 <= o < MAX_ORDER implies #[trigger] self.nr_free()[o as int]
            == if o != order {
            old(self).nr_free()[o as int]
        } else {
            (old(self).nr_free()[order as int] + 1) as usize
        } by {}
        assert(self.nr_free() =~= old(self).nr_free().update(
            order as int,
            (old(self).nr_free()[order as int] + 1) as usize,
        ));
    }

    #[verifier::spinoff_prover]
    proof fn tracked_push(
        tracked &mut self,
        order: usize,
        pfn: usize,
        tracked perm: PgUnitPerm<DeallocUnit>,
    )
        requires
            0 <= order < MAX_ORDER,
            old(self).valid_pfn_order(pfn, order),
            perm.wf_pfn_order(old(self).mr_map, pfn, order),
            perm.page_type() == PageType::Free,
            old(self).wf_strict(),
            perm.page_info() == Some(
                PageInfo::Free(FreeInfo { order, next_page: old(self).next_page(order) }),
            ),
        ensures
            self.avail == old(self).avail.update(
                order as int,
                old(self).avail[order as int].push(perm),
            ),
            self.mr_map() == old(self).mr_map(),
            self.pg_params() == old(self).pg_params(),
            self.nr_free() == old(self).nr_free().update(
                order as int,
                (old(self).nr_free()[order as int] + 1) as usize,
            ),
            old(self).nr_free()[order as int] <= old(self).pg_params().page_count - 1,
            old(self).nr_free()[order as int] * (1usize << order) <= old(
                self,
            ).pg_params().page_count - 1,
            self.wf_strict(),
    {
        reveal(MRFreePerms::wf_strict);
        reveal(MRFreePerms::wf_at);
        use_type_invariant(&*self);
        self.tracked_insert(order, self.avail[order as int].len() as int, pfn, perm);
        assert(old(self).avail[order as int].push(perm) =~= old(self).avail[order as int].insert(
            old(self).avail[order as int].len() as int,
            perm,
        ));
        assert(self.avail[order as int].last() == perm);

    }

    #[verifier::spinoff_prover]
    proof fn tracked_pop(tracked &mut self, order: usize) -> (tracked perm: PgUnitPerm<DeallocUnit>)
        requires
            0 <= order < MAX_ORDER,
            old(self).next_page(order) > 0,
            old(self).wf_strict(),
        ensures
            self.wf_strict(),
            self.avail == old(self).avail.update(order as int, self.avail[order as int]),
            self.avail[order as int] == old(self).avail[order as int].take(
                old(self).avail[order as int].len() - 1,
            ),
            old(self).ens_perm_strict(order, old(self).avail[order as int].len() - 1, perm),
            self.mr_map() == old(self).mr_map(),
            self.nr_free() == old(self).nr_free().update(
                order as int,
                (old(self).nr_free()[order as int] - 1) as usize,
            ),
            old(self).nr_free()[order as int] > 0,
    {
        self.tracked_remove(order, self.avail[order as int].len() - 1)
    }

    /// Prove the property of i-th free page block at a specific order
    #[verifier::spinoff_prover]
    proof fn tracked_borrow(tracked &self, order: usize, i: int) -> (tracked perm: &PgUnitPerm<
        DeallocUnit,
    >)
        requires
            0 <= order < MAX_ORDER,
            0 <= i < self.avail[order as int].len(),
        ensures
            self.wf_strict() ==> self.ens_perm_strict(order, i, *perm),
            self.ens_perm_valid(order, i, *perm),
    {
        reveal(MRFreePerms::wf_at);
        use_type_invariant(self);
        reveal(MRFreePerms::wf_strict);
        let tracked p = self.avail.tracked_borrow(order as int).tracked_borrow(i);
        use_type_invariant(&p);
        p
    }

    /// Prove the property of the next free page at a specific order
    proof fn tracked_next(tracked &self, order: usize)
        requires
            self.wf_strict(),
        ensures
            (order < MAX_ORDER && self.next_page(order) != 0) ==> self.pg_params().valid_pfn_order(
                self.next_page(order),
                order as usize,
            ),
    {
        use_type_invariant(self);
        if order < MAX_ORDER && self.next_page(order) != 0 {
            self.tracked_borrow(order, self.avail[order as int].len() - 1);
        }
    }

    /// Prove the side effect of removing a free page block from the free list.
    #[verifier::spinoff_prover]
    proof fn tracked_remove(tracked &mut self, order: usize, idx: int) -> (tracked perm: PgUnitPerm<
        DeallocUnit,
    >)
        requires
            0 <= order < MAX_ORDER,
            0 <= idx < old(self).avail[order as int].len(),
        ensures
            self.avail == old(self).avail.update(order as int, self.avail[order as int]),
            self.avail[order as int] == old(self).avail[order as int].remove(idx),
            old(self).ens_perm_valid(order, idx, perm),
            self.mr_map() == old(self).mr_map(),
            self.nr_free() == old(self).nr_free().update(
                order as int,
                (old(self).nr_free()[order as int] - 1) as usize,
            ),
            old(self).nr_free()[order as int] > 0,
            old(self).wf_strict() ==> old(self).ens_perm_strict(order, idx, perm),
            old(self).wf_strict() ==> (idx == self.avail[order as int].len() ==> self.wf_strict()),
    {
        reveal(MRFreePerms::wf_at);
        use_type_invariant(&*self);
        let p = self.avail[order as int][idx];
        let tracked mut tmp = MRFreePerms::tracked_empty(old(self).mr_map());
        tracked_swap(&mut tmp, self);
        tmp.tracked_next_no_dup_len(order);
        assert(old(self).nr_free()[order as int] == old(self).avail[order as int].len());

        let tracked MRFreePerms { mut avail, mr_map } = tmp;
        let len = avail[order as int].len();
        let tracked mut a = avail.tracked_remove(order as int);
        let olda = a;
        let tracked perm = a.tracked_remove(idx);
        avail.tracked_insert(order as int, a);
        *self = MRFreePerms { avail, mr_map: mr_map };
        assert(self.avail =~= old(self).avail.update(
            order as int,
            old(self).avail[order as int].remove(idx),
        ));
        assert(self.nr_free() =~= old(self).nr_free().update(
            order as int,
            (old(self).nr_free()[order as int] - 1) as usize,
        ));
        use_type_invariant(&*self);
        if old(self).wf_strict() {
            assert(old(self).ens_perm_strict(order, idx, perm)) by {
                reveal(MRFreePerms::wf_strict);
            }
            assert((idx == self.avail[order as int].len() ==> self.wf_strict())) by {
                reveal(MRFreePerms::wf_strict);
            }
        }
        perm
    }

    #[verifier::spinoff_prover]
    #[verifier::rlimit(2)]
    proof fn lemma_wf_restrict_remove(&self, tracked new: &Self, order: usize, idx: int)
        requires
            self.wf_strict(),
            self.wf(),
            new.avail =~= self.avail.update(order as int, new.avail[order as int]),
            order < MAX_ORDER,
            0 <= idx < self.avail[order as int].len(),
            idx < self.avail[order as int].len() ==> new.avail[order as int]
                =~= self.avail[order as int].remove(idx).update(idx, new.avail[order as int][idx]),
            idx == self.avail[order as int].len() - 1 ==> new.avail[order as int]
                =~= self.avail[order as int].remove(idx),
            new.avail[order as int][idx].pfn() == self.avail[order as int][idx + 1].pfn(),
            new.ens_perm_strict(order, idx, new.avail[order as int][idx]),
        ensures
            new.wf_strict(),
    {
        use_type_invariant(new);
        reveal(MRFreePerms::wf_strict);
        reveal(MRFreePerms::wf_at);
        assert(idx > 0 ==> self.avail[order as int][idx - 1].pfn() == new.avail[order as int][idx
            - 1].pfn());
        assert forall|o: usize, i: int|
            #![trigger new.avail[o as int][i]]
            0 <= o < MAX_ORDER && 0 <= i < new.avail[o as int].len() implies new.wf_next(o, i) by {
            let old_a = self.avail[o as int][i];
            let old_prev_a = self.avail[o as int][i - 1];
            let old_prev_a = self.avail[o as int][i + 1];
        }
    }
}

} // verus!

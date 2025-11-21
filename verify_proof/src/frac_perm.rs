// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// A fully verified frac-based ownership to share tracked ghost permissions.
// This is motivated by PCM lib from vstd.
// The state-machine proofs are motivated from the proof for Rc in vstd.
use crate::sum::{lemma_sum_insert, lemma_sum_remove, sum, CountTrait};
use verus_state_machines_macros::*;
use vstd::modes::tracked_swap;
use vstd::multiset::*;
use vstd::prelude::*;

verus! {

impl<T> CountTrait for (T, nat) {
    open spec fn count(&self) -> nat {
        self.1
    }
}

} // verus!
tokenized_state_machine!(frac_inner<Perm> {
    fields {
        #[sharding(storage_option)]
        pub storage: Option<Perm>,

        #[sharding(multiset)]
        pub reader: Multiset<(Option<Perm>, nat)>, // read token and number of shares

        #[sharding(constant)]
        pub total: nat, // maximum number of shares, must be sum of readers
    }

    #[invariant]
    pub fn frac_positive(&self) -> bool {
        forall |s| #[trigger] self.reader.count(s) > 0 ==> s.1 > 0
    }

    #[invariant]
    pub fn frac_agrees_total(&self) -> bool {
        sum(self.reader) == self.total
    }

    #[invariant]
    pub fn reader_agrees_storage(&self) -> bool {
        forall |v| #[trigger] self.reader.count(v) > 0 ==> self.storage == v.0
    }

    #[invariant]
    pub fn reader_agrees_total(&self) -> bool {
        forall |v| #[trigger] self.reader.count(v) > 0 ==> v.1 <= self.total
    }

    init!{
        initialize_once(total: nat) {
            require total > 0;
            init storage = Option::None;
            init reader = Multiset::empty().insert((Option::None, total));
            init total = total;
        }
    }

    #[inductive(initialize_once)]
    fn initialize_once_inductive(post: Self, total: nat) {
        let frac = Multiset::empty().insert((Option::<Perm>::None, total));
        lemma_sum_remove(frac, (Option::None, total));
    }

    property! {
        is_same(p1: (Option<Perm>, nat), p2: (Option<Perm>, nat)) {
            have reader >= {p1};
            have reader >= {p2};
            birds_eye let r1 = pre.reader.contains(p1);
            birds_eye let r2 = pre.reader.contains(p2);
            assert p1.0 == p2.0;
        }
    }

    property! {
        shares_agree_totals(p: (Option<Perm>, nat)) {
            have reader >= {p};
            birds_eye let r1 = pre.reader.contains(p);
            assert p.1 <= pre.total;
        }
    }

    property! {
        reader_guard(x: Option<Perm>, shares: nat) {
            require x.is_some();
            have reader >= {(x, shares)};
            guard storage >= Some(x.unwrap());
        }
    }

    transition! {
        do_share(x: Option<Perm>, shares: nat, new_shares: nat) {
            remove reader -= {(x, shares)};
            require(0 < new_shares < shares);
            add reader += {(x, new_shares)};
            add reader += {(x, (shares - new_shares) as nat)};
        }
    }


    #[inductive(do_share)]
    fn do_share_inductive(pre: Self, post: Self, x: Option<Perm>, shares: nat, new_shares: nat) {
        let reader1 = pre.reader.remove((x, shares));
        let reader2 = reader1.insert((x, new_shares));
        lemma_sum_remove(pre.reader, (x, shares));
        lemma_sum_insert(reader1, (x, new_shares));
        lemma_sum_insert(reader2, (x, (shares - new_shares) as nat));
    }

    transition! {
        take(x: Option<Perm>) {
            remove reader -= {(x, pre.total)};
            require x.is_some();
            add reader += {(None, pre.total)};
            withdraw storage -= Some(x.unwrap());
        }
    }

    #[inductive(take)]
    fn take_inductive(pre: Self, post: Self, x: Option<Perm>) {
        lemma_sum_remove(pre.reader, (x, pre.total));
        let reader1 = pre.reader.remove((x, pre.total));
        assert(reader1.len() == 0) by {
            let e = reader1.choose();
            if (reader1.contains(e)) {
                lemma_sum_remove(reader1, e);
            }
        }
        lemma_sum_insert(reader1, (None, pre.total));
    }

    transition!{
        update(x: Option<Perm>) {
            remove reader -= {(None, pre.total)};
            require x.is_some();
            add reader += {(x, pre.total)};
            deposit storage += Some(x.unwrap());
        }
    }

    #[inductive(update)]
    fn update_inductive(pre: Self, post: Self, x: Option<Perm>) {
        let oldx = None;
        assert(sum(pre.reader) == pre.total);
        lemma_sum_remove(pre.reader, (oldx, pre.total));
        assert(pre.storage.is_none());
        let reader1 = pre.reader.remove((oldx, pre.total));
        assert(sum(reader1) == 0);
        if (reader1.len() != 0) {
            let e = reader1.choose();
            vstd::multiset::axiom_choose_count(reader1);
            lemma_sum_remove(reader1, e);
        }
        lemma_sum_insert(reader1, (x, pre.total));
    }


    transition!{
        merge(x: Option<Perm>, shares1: nat, shares2: nat) {
            let new_shares = (shares1 + shares2) as nat;
            remove reader -= {(x, shares1)};
            remove reader -= {(x, shares2)};
            add reader += {(x, new_shares)};
        }
    }

    #[inductive(merge)]
    fn merge_inductive(pre: Self, post: Self, x: Option<Perm>, shares1: nat, shares2: nat) {
        let new_shares = (shares1 + shares2) as nat;
        let reader1 = pre.reader.remove((x, shares1));
        let reader2 = reader1.remove((x, shares2));
        lemma_sum_remove(pre.reader, (x, shares1));
        lemma_sum_remove(reader1, (x, shares2));
        lemma_sum_insert(reader2, (x, (shares1 + shares2) as nat));
    }
});

verus! {

/// A `tracked ghost` container that you can put a ghost object in.
/// A `Shared<T>` is duplicable and lets you get a `&T` out.
/// Refer to FracTypedPerm.
pub(crate) tracked struct FracPerm<T> {
    tracked inst: frac_inner::Instance<T>,
    tracked reader: frac_inner::reader<T>,
}

impl<T> FracPerm<T> {
    #[verifier::type_invariant]
    pub closed spec fn wf(self) -> bool {
        &&& self.reader.instance_id() == self.inst.id()
        &&& self.inst.total() > 0
    }

    pub closed spec fn view(self) -> Option<T> {
        self.reader.element().0
    }

    pub closed spec fn id(self) -> InstanceId {
        self.inst.id()
    }

    pub closed spec fn shares(&self) -> nat {
        self.reader.element().1
    }

    pub closed spec fn total(&self) -> nat {
        self.inst.total()
    }

    pub open spec fn valid(&self) -> bool {
        self@.is_some()
    }

    pub proof fn new(total: nat, tracked v: T) -> (tracked s: Self)
        requires
            total > 0,
        ensures
            s.valid(),
            s@ == Some(v),
    {
        let tracked (Tracked(inst), Tracked(mut readers)) = frac_inner::Instance::initialize_once(
            total,
            None,
        );
        let tracked reader = readers.remove((None, total));
        let tracked reader = inst.update(Some(v), v, reader);
        FracPerm { inst, reader }
    }

    pub proof fn empty(total: nat) -> (tracked s: Self)
        requires
            total > 0,
        ensures
            !s.valid(),
    {
        let tracked (Tracked(inst), Tracked(mut readers)) = frac_inner::Instance::initialize_once(
            total,
            None,
        );
        let tracked reader = readers.remove((None, total));
        FracPerm { inst, reader }
    }

    pub proof fn borrow(tracked &self) -> (tracked t: &T)
        requires
            self.valid(),
        ensures
            Some(*t) == self@,
    {
        use_type_invariant(&*self);
        self.inst.reader_guard(self.view(), self.shares(), &self.reader)
    }

    pub proof fn is_same(tracked &self, tracked other: &Self)
        requires
            self.id() == other.id(),
        ensures
            self@ == other@,
    {
        use_type_invariant(self);
        use_type_invariant(other);
        self.inst.is_same(
            (self@, self.shares()),
            (other@, other.shares()),
            &self.reader,
            &other.reader,
        );
    }

    pub proof fn shares_agree_totals(tracked &self)
        ensures
            self.shares() <= self.total(),
    {
        use_type_invariant(self);
        self.inst.shares_agree_totals((self@, self.shares()), &self.reader);
    }

    pub proof fn share(tracked &mut self, n: nat) -> (tracked ret: Self)
        requires
            0 < n < old(self).shares(),
        ensures
            ret@ == old(self)@,
            self@ == old(self)@,
            self.id() == old(self).id(),
            self.total() == old(self).total(),
            ret.id() == old(self).id(),
            ret.shares() + self.shares() == old(self).shares(),
            ret.shares() == n,
            ret.total() == old(self).total(),
    {
        use_type_invariant(&*self);
        let tracked mut perm = FracPerm::empty(self.total());
        tracked_swap(self, &mut perm);
        let tracked (Tracked(r1), Tracked(r2)) = perm.inst.do_share(
            perm.view(),
            perm.shares(),
            n,
            perm.reader,
        );
        *self = FracPerm { inst: perm.inst, reader: r2 };
        FracPerm { inst: perm.inst, reader: r1 }
    }

    pub proof fn merge(tracked &mut self, tracked other: Self)
        requires
            old(self)@ == other@,
            old(self).valid(),
            other.valid(),
            old(self).id() == other.id(),
        ensures
            self@ == old(self)@,
            self.shares() == old(self).shares() + other.shares(),
            self.total() == old(self).total(),
            self.id() == old(self).id(),
            self.valid(),
    {
        use_type_invariant(&*self);
        use_type_invariant(&other);
        let tracked mut perm = FracPerm::empty(self.total());
        tracked_swap(self, &mut perm);
        let shares = perm.shares();
        let tracked FracPerm { inst, reader } = perm;
        let tracked (new_reader) = inst.merge(other@, shares, other.shares(), reader, other.reader);
        *self = FracPerm { inst: inst, reader: new_reader }
    }

    pub proof fn udpate(tracked &mut self, tracked v: T)
        requires
            !old(self).valid(),
            old(self).shares() == old(self).total(),
        ensures
            self.valid(),
            self@ == Some(v),
            self.id() == old(self).id(),
            self.shares() == old(self).shares(),
            self.total() == old(self).total(),
    {
        use_type_invariant(&*self);
        let tracked mut perm = FracPerm::empty(self.total());
        tracked_swap(self, &mut perm);
        let tracked FracPerm { inst, reader } = perm;
        let tracked reader = inst.update(Some(v), v, reader);
        *self = FracPerm { inst, reader };
    }

    pub proof fn extract(tracked self) -> (tracked ret: (T, Self))
        requires
            self.valid(),
            self.shares() == self.total(),
        ensures
            Some(ret.0) == self@,
            ret.1.id() == self.id(),
            !ret.1.valid(),
            ret.1.shares() == ret.1.total(),
            self.total() == ret.1.total(),
    {
        use_type_invariant(&self);
        let tracked FracPerm { mut inst, mut reader } = self;
        let tracked (Tracked(ret), Tracked(reader)) = inst.take(reader.element().0, reader);

        (ret, FracPerm { inst, reader })
    }

    pub proof fn take(tracked &mut self) -> (tracked ret: T)
        requires
            old(self).valid(),
            old(self).shares() == old(self).total(),
        ensures
            Some(ret) == old(self)@,
            self.id() == old(self).id(),
            !self.valid(),
            self.shares() == old(self).total(),
            self.total() == old(self).total(),
    {
        use_type_invariant(&*self);
        let tracked mut perm = FracPerm::empty(self.total());
        tracked_swap(self, &mut perm);
        let tracked (ret, mut new) = perm.extract();
        tracked_swap(self, &mut new);
        ret
    }
}

impl<T> FracPerm<vstd::raw_ptr::PointsTo<T>> {
    pub open spec fn addr(&self) -> int
        recommends
            self.valid(),
    {
        self@.unwrap().ptr()@.addr as int
    }
}

} // verus!

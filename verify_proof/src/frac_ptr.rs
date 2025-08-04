// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// A fully verified ghost and non-forgeable frac-based pointer permission to
// share tracked memory permissions.
use state_machines_macros::*;

use vstd::prelude::*;
use vstd::raw_ptr::{MemContents, PointsTo, PointsToData, PointsToRaw};
use vstd::tokens::InstanceId;

use crate::frac_perm::FracPerm;

verus! {

use vstd::multiset::Multiset;

tokenized_state_machine!(addr_unique {
    fields {
        #[sharding(map)]
        pub addr_to: Map<int, Option<InstanceId>>,
        #[sharding(map)]
        pub to_addr: Map<InstanceId, Option<int>>,

        #[sharding(multiset)]
        pub ptr_readers: Multiset<(int, InstanceId)>,
    }

    #[invariant]
    pub fn ptr_readers_agrees(&self) -> bool {
        forall |addr, id| #[trigger]self.ptr_readers.contains((addr, id)) ==>
            self.addr_to[addr] === Some(id) && self.to_addr[id] === Some(addr)
    }

    #[invariant]
    pub fn dom_cover_all(&self) -> bool {
        self.addr_to.dom() =~= Set::full() &&
        self.to_addr.dom() =~= Set::full()
    }

    #[invariant]
    pub fn unique_id(&self) -> bool {
        forall |addr: int| (#[trigger]self.addr_to[addr]).is_some() ==>
            self.to_addr[self.addr_to[addr].unwrap()] == Some(addr)
    }

    transition! {
        check_ids(addr: int, id1: InstanceId, id2: InstanceId) {
            have ptr_readers >= {(addr, id1)};
            have ptr_readers >= {(addr, id2)};
            birds_eye let c1 = pre.ptr_readers.contains(((addr, id1)));
            birds_eye let c2 = pre.ptr_readers.contains(((addr, id2)));
            birds_eye let id = pre.addr_to[addr];
            assert Some(id2) == id;
            assert Some(id1) == id;
        }
    }

    #[inductive(check_ids)]
    fn check_ids_inductive(pre: Self, post: Self, addr: int, id1: InstanceId, id2: InstanceId) {
        assert(pre.ptr_readers.contains((addr, id1)));
        assert(pre.ptr_readers.contains((addr, id2)));
        assert(pre.addr_to[addr] == Some(id1));
        assert(pre.addr_to[addr] == Some(id2));
        assert(id1 == id2);
    }

    init!{
        empty() {
            init addr_to = Map::new(|addr| true, |addr|None);
            init to_addr = Map::new(|id| true, |addr|None);
            init ptr_readers = Multiset::empty();
        }
    }

    #[inductive(empty)]
    fn empty_inductive(post: Self) {
        assert(post.addr_to =~= Map::new(|addr| true, |addr|None));
    }

    transition!{
        update(addr: int, id: InstanceId) {
            remove addr_to -= [addr => None];
            remove to_addr -= [id => None];
            add addr_to += [ addr => Some(id) ];
            add to_addr += [ id => Some(addr) ];
        }
    }

    #[inductive(update)]
    fn update_inductive(pre: Self, post: Self, addr: int, id: InstanceId) {
        assert forall |addr: int| (#[trigger]post.addr_to[addr]).is_some()
        implies
            post.to_addr[post.addr_to[addr].unwrap()] == Some(addr)
        by {}
    }

    transition!{
        add_reader(addr: int, id: InstanceId) {
            have ptr_readers >= {(addr, id)};
            add ptr_readers += {(addr, id)};
        }
    }

    #[inductive(add_reader)]
    fn add_reader_inductive(pre: Self, post: Self, addr: int, id: InstanceId) {
        assert(pre.ptr_readers.contains((addr, id)));
        assert forall |addr, id| #[trigger]post.ptr_readers.contains((addr, id))
        implies
            post.addr_to[addr] === Some(id) && post.to_addr[id] === Some(addr)
        by {
            assert(pre.ptr_readers.contains((addr, id)));
        }
    }
}
);

// A single inst + addr_unique::addr_to, addr_unique::to_addr are created at entry.
pub struct UniqueByPtr {
    tracked inst: addr_unique::Instance,
    tracked id: addr_unique::ptr_readers,
    ghost addr_id_map: Option<(addr_unique::addr_to, addr_unique::to_addr)>,
}

impl UniqueByPtr {
    // inst is only created once at the begining and thus all share the same inst_id;
    pub uninterp spec fn spec_uniq_inst_id() -> InstanceId;

    #[verifier::type_invariant]
    pub closed spec fn wf(&self) -> bool {
        &&& self.inst.id() == UniqueByPtr::spec_uniq_inst_id()
        &&& self.id.instance_id() == UniqueByPtr::spec_uniq_inst_id()
        &&& if let Some((id_map, addr_map)) = self.addr_id_map {
            &&& id_map.instance_id() == UniqueByPtr::spec_uniq_inst_id()
            &&& addr_map.instance_id() == UniqueByPtr::spec_uniq_inst_id()
        } else {
            true
        }
    }

    pub proof fn tracked_clone(tracked &self) -> (tracked ret: Self)
        ensures
            ret@ == self@,
    {
        use_type_invariant(&*self);
        let (addr, id) = self.id.element();
        let tracked reader = self.inst.add_reader(addr, id, &self.id);
        UniqueByPtr { inst: self.inst, id: reader, addr_id_map: self.addr_id_map }
    }

    pub closed spec fn view(&self) -> (int, InstanceId) {
        self.id.element()
    }

    pub open spec fn id(&self) -> InstanceId {
        self@.1
    }
}

/// FracTypedPerm<T> is a ghost tracked permission type that tracks a fraction
/// of memory permission. It is used to share memory permissions between
/// different components and allowing concurrent read. In most cases, we rely on
/// Rust existing ownership system to track the memory permissions. This is only
/// used when we need to deal with raw pointers and unsafe codes. For example,
/// in memory allocator, we need to share the read access to some raw memory but
/// we do not really store PageInfo inside allocator, or share reference to
/// external. Instead, we can use this ghost type to define the ownership and
/// share the read access to the PageInfo without causing memory overhead.
///
/// In addition, we proved that the frac-based permissions pointing to the same
/// address are always from the same instance. Thus, we can safely merge the
/// local and global permissions if they point to the same address.
pub struct FracTypedPerm<T> {
    p: FracPerm<PointsTo<T>>,
    unique: UniqueByPtr,
}

pub struct FracTypedPermData<T> {
    pub shares: nat,
    pub total: nat,
    pub addr: int,
    pub id: InstanceId,
    pub points_to: Option<PointsToData<T>>,
}

impl<T> FracTypedPermData<T> {
    pub open spec fn update_points_to(self, p: Option<PointsToData<T>>) -> Self {
        FracTypedPermData {
            shares: self.shares,
            total: self.total,
            addr: self.addr,
            id: self.id,
            points_to: p,
        }
    }

    pub open spec fn update_value(self, opt_value: MemContents<T>) -> Self
        recommends
            self.points_to.is_some(),
    {
        FracTypedPermData {
            shares: self.shares,
            total: self.total,
            addr: self.addr,
            id: self.id,
            points_to: Some(PointsToData { ptr: self.points_to.unwrap().ptr, opt_value }),
        }
    }

    pub open spec fn update_shares(self, shares: nat) -> Self {
        FracTypedPermData {
            shares,
            total: self.total,
            addr: self.addr,
            id: self.id,
            points_to: self.points_to,
        }
    }

    pub open spec fn data_view(&self) -> Self {
        self.update_shares(0)
    }
}

impl<T> FracTypedPerm<T> {
    pub closed spec fn view(&self) -> FracTypedPermData<T> {
        FracTypedPermData {
            shares: self.p.shares(),
            total: self.p.total(),
            id: self.p.id(),
            addr: self.unique@.0,
            points_to: match self.p@ {
                Some(p) => Some(p@),
                None => None,
            },
        }
    }

    pub open spec fn shares(&self) -> nat {
        self@.shares
    }

    pub open spec fn total(&self) -> nat {
        self@.total
    }

    pub open spec fn points_to(&self) -> Option<PointsToData<T>> {
        self@.points_to
    }

    pub open spec fn addr(&self) -> int {
        self@.addr
    }

    pub open spec fn id(&self) -> InstanceId {
        self@.id
    }

    #[verifier::inline]
    pub open spec fn ptr(&self) -> *mut T {
        self@.points_to.unwrap().ptr
    }

    #[verifier::inline]
    pub open spec fn opt_value(&self) -> MemContents<T> {
        self@.points_to.unwrap().opt_value
    }

    #[verifier::inline]
    pub open spec fn is_init(&self) -> bool {
        self.opt_value().is_init()
    }

    #[verifier::inline]
    pub open spec fn is_uninit(&self) -> bool {
        self.opt_value().is_uninit()
    }

    #[verifier::inline]
    pub open spec fn value(&self) -> T {
        self.opt_value().value()
    }
}

impl<T> FracTypedPerm<T> {
    #[verifier::type_invariant]
    pub closed spec fn wf(&self) -> bool {
        &&& self@.id == self.unique.id()
        &&& self.valid() ==> ((self.ptr() as int) == self.addr())
    }

    pub open spec fn readable(&self) -> bool {
        self.is_init()
    }

    pub open spec fn writable(&self) -> bool {
        self.shares() == self.total()
    }

    pub open spec fn valid(&self) -> bool {
        &&& self@.points_to.is_some()
    }

    proof fn has_same_id(tracked &self, tracked other: &Self)
        requires
            self.valid(),
            other.valid(),
            self.addr() == other.addr(),
        ensures
            self@.id == other@.id,
    {
        use_type_invariant(&*self);
        use_type_invariant(&*other);
        use_type_invariant(&self.unique);
        use_type_invariant(&other.unique);
        self.unique.inst.check_ids(
            self.addr(),
            self.id(),
            other.id(),
            &self.unique.id,
            &other.unique.id,
        );
    }

    pub proof fn is_same(tracked &self, tracked other: &Self)
        requires
            self.valid(),
            other.valid(),
            self.ptr() == other.ptr(),
        ensures
            self@.points_to == other@.points_to,
            self@.id == other@.id,
    {
        use_type_invariant(&*self);
        use_type_invariant(&*other);
        self.has_same_id(&other);
        self.p.is_same(&other.p);
    }

    pub proof fn extract(tracked &mut self) -> (tracked ret: PointsTo<T>)
        requires
            old(self).valid(),
            old(self).writable(),
        ensures
            Some(ret@) == old(self).points_to(),
            ret.ptr() as int == self.addr(),
            !self.valid(),
            self@ == old(self)@.update_points_to(None),
    {
        use_type_invariant(&*self);
        self.p.take()
    }

    pub proof fn update(tracked &mut self, tracked val: PointsTo<T>)
        requires
            old(self).writable(),
            (val@.ptr as int) == old(self).addr(),
            !old(self).valid(),
        ensures
            self@ === old(self)@.update_points_to(Some(val@)),
    {
        use_type_invariant(&*self);
        use_type_invariant(&self.p);
        self.p.udpate(val)
    }

    pub proof fn borrow(tracked &self) -> (tracked ret: &PointsTo<T>)
        requires
            self.valid(),
        ensures
            Some(ret@) == self.points_to(),
    {
        use_type_invariant(&*self);
        self.p.borrow()
    }

    pub proof fn share(tracked &mut self, shares: nat) -> (tracked ret: Self)
        requires
            old(self).valid(),
            0 < shares < old(self).shares(),
        ensures
            self@ === old(self)@.update_shares((old(self).shares() - shares) as nat),
            ret@ === old(self)@.update_shares(shares),
    {
        use_type_invariant(&*self);
        use_type_invariant(&self.p);
        use_type_invariant(&self.unique);
        let id = self.unique.id();
        let tracked p = self.p.share(shares);
        assert(p.id() == id);
        let tracked unique = self.unique.tracked_clone();
        assert(unique.id() == id);
        use_type_invariant(&p);
        use_type_invariant(&unique);
        FracTypedPerm { p, unique }
    }

    pub proof fn merge(tracked &mut self, tracked other: Self)
        requires
            other.valid(),
            old(self).valid(),
            old(self).ptr() == other.ptr(),
        ensures
            self@ === old(self)@.update_shares(old(self).shares() + other.shares()),
            old(self).shares() + other.shares() <= old(self).total(),
    {
        use_type_invariant(&*self);
        use_type_invariant(&other);
        let tracked mut other = other;
        self.is_same(&other);
        self.p.is_same(&other.p);
        self.p.merge(other.p);
        use_type_invariant(&self.p);
        self.p.shares_agree_totals();
    }
}

pub proof fn raw_perm_is_disjoint(tracked p1: &mut PointsToRaw, p2: &PointsToRaw)
    requires
        old(p1).dom().len() > 0,
    ensures
        *old(p1) == *p1,
        p1.dom().disjoint(p2.dom()),
{
    admit();
}

pub proof fn tracked_map_shares<Idx, T>(
    tracked m: &mut Map<Idx, FracTypedPerm<T>>,
    shares: nat,
) -> (tracked ret: Map<Idx, FracTypedPerm<T>>)
    requires
        old(m).dom().finite(),
        shares > 0,
        forall|i|
            old(m).dom().contains(i) ==> shares < (#[trigger] old(m)[i]).shares() && old(
                m,
            )[i].valid(),
    ensures
        ret.dom() == m.dom(),
        m.dom() == old(m).dom(),
        forall|i: Idx|
            #![trigger m[i]]
            #![trigger old(m)[i]]
            m.contains_key(i) ==> m[i]@ == old(m)[i]@.update_shares(
                (old(m)[i].shares() - shares) as nat,
            ),
        forall|i: Idx|
            #![trigger ret[i]]
            #![trigger old(m)[i]]
            ret.contains_key(i) ==> ret[i]@ == old(m)[i]@.update_shares(shares),
{
    _tracked_map_shares(m, shares, m.dom())
}

pub proof fn _tracked_map_shares<Idx, T>(
    tracked m: &mut Map<Idx, FracTypedPerm<T>>,
    shares: nat,
    s: Set<Idx>,
) -> (tracked ret: Map<Idx, FracTypedPerm<T>>)
    requires
        shares > 0,
        forall|i| #[trigger] s.contains(i) ==> old(m).contains_key(i),
        forall|i| s.contains(i) ==> (#[trigger] old(m)[i]).valid(),
        forall|i| s.contains(i) ==> shares < (#[trigger] old(m)[i]).shares(),
        s.finite(),
    ensures
        forall|i: Idx|
            #![trigger m[i]]
            #![trigger old(m)[i]]
            s.contains(i) ==> m[i]@ == old(m)[i]@.update_shares(
                (old(m)[i].shares() - shares) as nat,
            ),
        *m =~= old(m).union_prefer_right(m.restrict(s)),
        m.dom() =~= old(m).dom(),
        ret.dom() =~= s,
        forall|i: Idx| s.contains(i) ==> (#[trigger] ret[i])@ == old(m)[i]@.update_shares(shares),
    decreases s.len(),
{
    if !s.is_empty() {
        let idx = s.choose();
        assert(s.contains(idx));
        assert(m.contains_key(idx));
        let tracked mut ret = _tracked_map_shares(m, shares, s.remove(idx));
        let old_m = *m;
        let tracked mut tmp = m.tracked_remove(idx);
        let tracked shared = tmp.share(shares);
        m.tracked_insert(idx, tmp);
        ret.tracked_insert(idx, shared);
        ret
    } else {
        assert(s =~= Set::empty());
        Map::tracked_empty()
    }
}

pub proof fn tracked_map_merge_right_shares<Idx, T>(
    tracked m: &mut Map<Idx, FracTypedPerm<T>>,
    tracked right: Map<Idx, FracTypedPerm<T>>,
)
    requires
        right.dom().subset_of(old(m).dom()),
        right.dom().finite(),
        forall|i|
            right.contains_key(i) ==> (#[trigger] old(m)[i]).valid() && old(m)[i].ptr()
                == right[i].ptr(),
        forall|i| right.contains_key(i) ==> (#[trigger] right[i]).valid(),
    ensures
        forall|i: Idx|
            #![trigger m[i]]
            #![trigger old(m)[i]]
            old(m).contains_key(i) && right.contains_key(i) ==> m[i]@ == old(m)[i]@.update_shares(
                (old(m)[i].shares() + right[i].shares()) as nat,
            ),
        m.dom() =~= old(m).dom(),
    decreases right.dom().len(),
{
    let s = right.dom();
    if !s.is_empty() {
        let idx = s.choose();
        assert(right.contains_key(idx));
        let tracked mut right = right;
        let tracked mut right_tmp = right.tracked_remove(idx);
        let tracked mut tmp = m.tracked_remove(idx);
        tmp.merge(right_tmp);
        tracked_map_merge_right_shares(m, right);
        m.tracked_insert(idx, tmp);
    }
}

} // verus!

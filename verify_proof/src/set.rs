// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
use vstd::prelude::*;

verus! {

pub open spec fn set_usize_range(start: usize, end: int) -> Set<usize> {
    Set::new(|i| start <= i < end)
}

pub broadcast proof fn lemma_set_usize_range(start: usize, end: int)
    requires
        start <= end,
        end <= usize::MAX + 1,
    ensures
        (#[trigger] set_usize_range(start, end)).finite(),
        set_usize_range(start, end).len() == end - start,
    decreases end - start,
{
    if end > start {
        let e2 = (end - 1) as usize;
        let s1 = set_usize_range(start, end);
        let s2 = set_usize_range(start, e2 as int);
        lemma_set_usize_range(start, e2 as int);
        assert(s1 =~= s2.insert(e2));
    } else {
        assert(set_usize_range(start, end) =~= Set::empty());
    }
}

pub broadcast proof fn lemma_set_usize_finite(s: Set<usize>)
    ensures
        #[trigger] s.finite(),
{
    let maxset = set_usize_range(0, usize::MAX + 1);
    lemma_set_usize_range(0, usize::MAX + 1);
    assert(s.subset_of(maxset));
}

pub broadcast proof fn lemma_len_filter<A>(s: Set<A>, f: spec_fn(A) -> bool)
    requires
        s.finite(),
    ensures
        (#[trigger] s.filter(f)).finite(),
        s.filter(f).len() <= s.len(),
{
    s.lemma_len_filter(f)
}

pub broadcast proof fn lemma_len_subset<A>(s1: Set<A>, s2: Set<A>)
    requires
        s2.finite(),
        #[trigger] s1.subset_of(s2),
    ensures
        s1.len() <= s2.len(),
        s1.finite(),
{
    vstd::set_lib::lemma_len_subset(s1, s2)
}

} // verus!

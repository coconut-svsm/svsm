// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
use vstd::prelude::*;
use vstd::set_lib::range_set_properties;

verus! {

/// The finite set of usizes in the half-open range [start, end).
///
/// `end` is an `int` so the range can be empty (`end == start`) or cover the
/// full `usize` space (`end == usize::MAX + 1`), neither of which a `usize`
/// upper bound can express. It is built from vstd's `Set::range`
/// (`[start, end)`) for the common case and `Set::range_inclusive` for the full
/// case, so finiteness, membership, and length all come from vstd's
/// `range_set_properties` broadcast. Membership is re-exported unconditionally
/// through [`lemma_set_usize_range_contains`] (and [`group_set_usize`]); the
/// length is given by [`lemma_set_usize_range`].
pub closed spec fn set_usize_range(start: usize, end: int) -> Set<usize> {
    if end <= start {
        Set::<usize>::range(start, start)
    } else if end <= usize::MAX {
        Set::<usize>::range(start, end as usize)
    } else {
        Set::<usize>::range_inclusive(start, usize::MAX)
    }
}

/// Unconditional membership of [`set_usize_range`].
pub broadcast proof fn lemma_set_usize_range_contains(start: usize, end: int, k: usize)
    ensures
        (#[trigger] set_usize_range(start, end).contains(k)) <==> start <= k < end,
{
    broadcast use vstd::set::group_set_lemmas;

    if end <= start {
        range_set_properties::<usize>(start, start);
    } else if end <= usize::MAX {
        assert((end as usize) as int == end);
        range_set_properties::<usize>(start, end as usize);
    } else {
        range_set_properties::<usize>(start, usize::MAX);
    }
}

/// Establishes the length of [`set_usize_range`].
pub broadcast proof fn lemma_set_usize_range(start: usize, end: int)
    requires
        start <= end,
        end <= usize::MAX + 1,
    ensures
        (#[trigger] set_usize_range(start, end)).len() == end - start,
{
    if end <= start {
    } else if end <= usize::MAX {
        range_set_properties::<usize>(start, end as usize);
    } else {
        // end == usize::MAX + 1: range_inclusive adds the top element, which is
        // not already in the half-open range, so the length is one larger.
        range_set_properties::<usize>(start, usize::MAX);
        assert(!Set::<usize>::range(start, usize::MAX).contains(usize::MAX));
    }
}

pub broadcast proof fn lemma_len_filter<A>(s: Set<A>, f: spec_fn(A) -> bool)
    ensures
        (#[trigger] s.filter(f)).len() <= s.len(),
{
    s.lemma_len_filter(f)
}

pub broadcast proof fn lemma_len_subset<A>(s1: Set<A>, s2: Set<A>)
    requires
        #[trigger] s1.subset_of(s2),
    ensures
        s1.len() <= s2.len(),
{
    vstd::set_lib::lemma_len_subset(s1, s2)
}

/// Broadcast group restoring the ergonomics of the (now finite) `Set` over
/// `usize` ranges: unconditional membership of [`set_usize_range`] plus the
/// filter/subset length lemmas.
pub broadcast group group_set_usize {
    lemma_set_usize_range_contains,
    lemma_len_filter,
    lemma_len_subset,
}

} // verus!

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
use vstd::multiset::Multiset;
use vstd::prelude::*;

verus! {

pub trait CountTrait {
    spec fn count(&self) -> nat;
}

pub open spec fn sum<T: CountTrait>(s: Multiset<T>) -> nat
    decreases s.len(),
{
    if s.len() > 0 {
        let e = s.choose();
        e.count() + sum(s.remove(e))
    } else {
        0
    }
}

pub proof fn lemma_sum_insert<T: CountTrait>(s: Multiset<T>, elem: T)
    ensures
        sum(s) + elem.count() == sum(s.insert(elem)),
{
    assert(s.insert(elem).remove(elem) =~= s);
    lemma_sum_remove(s.insert(elem), elem);
}

pub proof fn lemma_sum_remove<T: CountTrait>(s: Multiset<T>, elem: T)
    requires
        s.contains(elem),
    ensures
        sum(s.remove(elem)) + elem.count() == sum(s),
    decreases s.len(),
{
    let news = s.remove(elem);
    if s.len() > 1 {
        let e = s.choose();
        if e != elem {
            assert(sum(s.remove(e)) + e.count() == sum(s));
            lemma_sum_remove(s.remove(e), elem);
            lemma_sum_remove(s.remove(elem), e);
            assert(s.remove(elem).remove(e) =~= s.remove(e).remove(elem));
        } else {
            assert(sum(s.remove(elem)) + elem.count() == sum(s));
        }
    } else {
        Multiset::lemma_is_singleton(s);
        let e = s.choose();
        assert(s.contains(e));
        assert(news.len() == 0);
        assert(sum(news) == 0);
        assert(e == elem);
    }
}

} // verus!

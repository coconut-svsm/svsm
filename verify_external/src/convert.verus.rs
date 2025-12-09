// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
use vstd::prelude::*;
use vstd::std_specs::convert::{FromSpec, IntoSpec};
verus! {

#[verifier(inline)]
pub open spec fn exists_into<T, U>(v: T, r: spec_fn(v: U) -> bool) -> bool where T: Into<U> {
    exists|u: U| #[trigger] T::into.ensures((v,), u) && r(u)
}

#[verifier(inline)]
pub open spec fn forall_into<T, U>(v: T, r: spec_fn(v: U) -> bool) -> bool where T: Into<U> {
    forall|u: U| #[trigger] T::into.ensures((v,), u) ==> r(u)
}

#[verifier(inline)]
pub open spec fn exists_from<T, U>(v: T, r: spec_fn(v: U) -> bool) -> bool where U: From<T> {
    exists|u: U| #[trigger] U::from.ensures((v,), u) && r(u)
}

#[verifier(inline)]
pub open spec fn forall_from<T, U>(v: T, r: spec_fn(v: U) -> bool) -> bool where U: From<T> {
    forall|u: U| #[trigger] U::from.ensures((v,), u) ==> r(u)
}

} // verus!

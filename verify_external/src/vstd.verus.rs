// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
use vstd::prelude::*;
verus! {

#[verifier::external_fn_specification]
pub fn ex_map<T, U, F: FnOnce(T) -> U>(a: Option<T>, f: F) -> (ret: Option<U>)
    requires
        a.is_some() ==> call_requires(f, (a.unwrap(),)),
    ensures
        ret.is_some() == a.is_some(),
        ret.is_some() ==> call_ensures(f, (a.unwrap(),), ret.unwrap()),
{
    a.map(f)
}

} // verus!
macro_rules! num_specs {
    ($uN:ty) => {
        verus! {
        pub open spec fn saturating_add(x: $uN, y: $uN) -> $uN {
            if x + y > <$uN>::MAX {
                <$uN>::MAX
            } else {
                (x + y) as $uN
            }
        }

        #[verifier::external_fn_specification]
        #[verifier::when_used_as_spec(saturating_add)]
        pub fn ex_saturating_add(x: $uN, y: $uN) -> (res: $uN)
            ensures res == saturating_add(x, y)
        {
            x.saturating_add(y)
        }
        }
    };
}

num_specs! {usize}

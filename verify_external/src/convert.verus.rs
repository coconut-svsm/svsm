// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
use vstd::prelude::*;
verus! {

pub broadcast group convert_group {
    axiom_from_spec,
}

pub trait FromSpec<T>: Sized {
    spec fn from_spec(v: T) -> Self;
}

macro_rules! def_primitive_from{
    ($toty: ty, $($fromty: ty),*) => {
        $(verus!{
            impl FromSpec<$fromty> for $toty {
            open spec fn from_spec(v: $fromty) -> Self {
                v as $toty
            }
        }})*
    }
}

def_primitive_from!{u16, u8, u16}

def_primitive_from!{u32, u8, u16, u32}

def_primitive_from!{u64, u8, u16, u32, usize}

def_primitive_from!{usize, u8, u16, u32, usize}

pub open spec fn from_spec<T1, T2>(v: T1) -> T2;

#[verifier(inline)]
pub open spec fn default_into_spec<T, U: From<T>>(v: T) -> U {
    from_spec(v)
}

#[verifier(external_body)]
pub broadcast proof fn axiom_from_spec<T, U: FromSpec<T>>(v: T)
    ensures
        #[trigger] from_spec::<T, U>(v) === U::from_spec(v),
{
}

#[verifier::external_trait_specification]
pub trait ExInto<T>: Sized {
    type ExternalTraitSpecificationFor: core::convert::Into<T>;

    fn into(self) -> (ret: T)
        ensures
            from_spec(self) === ret,
    ;
}

#[verifier::external_trait_specification]
pub trait ExFrom<T>: Sized {
    type ExternalTraitSpecificationFor: core::convert::From<T>;

    fn from(v: T) -> (ret: Self)
        ensures
            from_spec(v) === ret,
    ;
}

#[verifier::external_fn_specification]
#[verifier::when_used_as_spec(default_into_spec)]
pub fn ex_into<T, U: From<T>>(a: T) -> (ret: U)
    ensures
        ret === from_spec(a),
{
    a.into()
}

} // verus!

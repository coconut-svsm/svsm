// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
use vstd::prelude::*;
verus! {

pub trait FromSpec<T>: Sized {
    spec fn from_spec(v: T) -> Self;
}

pub trait IntoSpec<T>: Sized {
    spec fn into_spec(self) -> T;
}

impl<T, U> IntoSpec<U> for T where U: FromSpec<T> {
    open spec fn into_spec(self) -> U {
        U::from_spec(self)
    }
}

pub trait FromIntoInteger: FromSpec<int> + IntoSpec<int> {

}

macro_rules! def_primitive_from{
    ($toty: ty; $($fromty: ty),*) => {verus!{
        $(
            impl FromSpec<$fromty> for $toty {
                open spec fn from_spec(v: $fromty) -> Self {
                    v as $toty
                }
            }
        )*
    }}
}

def_primitive_from!{u8; u8, int}

def_primitive_from!{u16; u8, u16, int}

def_primitive_from!{u32; u8, u16, u32, int}

def_primitive_from!{u64; u8, u16, u32, u64, usize, int}

def_primitive_from!{usize; u8, u16, u32, usize, int}

def_primitive_from!{u128; u8, u16, u32, u64, usize, u128, int}

def_primitive_from!{int; u8, u16, u32, u64, usize, u128, int, nat}

def_primitive_from!{nat; u8, u16, u32, u64, usize, u128, nat}

impl FromIntoInteger for u8 {

}

impl FromIntoInteger for u16 {

}

impl FromIntoInteger for u32 {

}

impl FromIntoInteger for u64 {

}

impl FromIntoInteger for usize {

}

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

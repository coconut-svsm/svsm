// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// Specifications related to util.rs that are used in proof_align_down and proof_align_up.
#[verus_verify]
pub trait AlignUpSpec:
    Add<Output = Self>
    + Sub<Output = Self>
    + BitAnd<Output = Self>
    + Not<Output = Self>
    + From<u8>
    + Copy
    + Sized
{
}

#[verus_verify]
impl<T> AlignUpSpec for T where
    T: Add<Output = Self>
        + Sub<Output = Self>
        + BitAnd<Output = Self>
        + Not<Output = Self>
        + From<u8>
        + Copy
        + Sized
{
}

#[verus_verify]
pub trait AlignDownSpec:
    Sub<Output = Self> + Not<Output = Self> + BitAnd<Output = Self> + From<u8> + Copy + Sized
{
}

#[verus_verify]
impl<T> AlignDownSpec for T where
    T: Sub<Output = Self> + Not<Output = Self> + BitAnd<Output = Self> + From<u8> + Copy + Sized
{
}

#[verus_verify]
pub trait IsAlignedSpec:
    Sub<Output = Self> + BitAnd<Output = Self> + PartialEq + From<u8> + Sized
{
}

#[verus_verify]
impl<T> IsAlignedSpec for T where
    T: Sub<Output = Self> + BitAnd<Output = Self> + PartialEq + From<u8> + Sized
{
}

verus! {

use verify_external::convert::*;
use verify_proof::bits::is_pow_of_2;
use vstd::std_specs::ops::*;

#[verifier(inline)]
pub open spec fn align_requires(align: u64) -> bool {
    is_pow_of_2(align)
}

pub open spec fn spec_align_up(val: int, align: int) -> int {
    let r = val % align;
    &&& if r == 0 {
        val
    } else {
        (val - r + align)
    }
}

pub open spec fn align_up_integer_ens<T>(val: T, align: T, ret: T) -> bool where
    T: AlignUpSpec + FromIntoInteger,
 {
    spec_align_up(val.into_spec(), align.into_spec()) == ret.into_spec()
}

pub open spec fn spec_align_down(val: int, align: int) -> int {
    val - val % align
}

#[verifier(inline)]
pub open spec fn align_down_integer_ens<T>(val: T, align: T, ret: T) -> bool where
    T: AlignDownSpec + FromIntoInteger,
 {
    T::from_spec(spec_align_down(val.into_spec(), align.into_spec())) == ret
}

pub open spec fn align_down_requires<T>(args: (T, T)) -> bool where T: AlignDownSpec {
    let (val, align) = args;
    &&& forall|one| #[trigger] call_ensures(T::from, (1u8,), one) ==> spec_sub_requires(align, one)
}

pub open spec fn align_down_ens<T>(args: (T, T), ret: T) -> bool where T: AlignDownSpec {
    let (val, align) = args;
    exists|one: T, mask: T, unmask: T|
        {
            &&& #[trigger] call_ensures(T::from, (1u8,), one)
            &&& call_ensures(T::sub, (align, one), mask)
            &&& #[trigger] call_ensures(T::not, (mask,), unmask)
            &&& call_ensures(T::bitand, (val, unmask), ret)
        }
}

pub open spec fn align_up_requires<T>(args: (T, T)) -> bool where T: AlignUpSpec {
    let (val, align) = args;
    &&& align_down_requires(args)
    &&& forall|one: T, mask: T|
        (call_ensures(T::from, (1u8,), one) && #[trigger] call_ensures(T::sub, (align, one), mask))
            ==> spec_add_requires(val, mask)
}

pub open spec fn align_up_ens<T>(args: (T, T), ret: T) -> bool where T: AlignUpSpec {
    let (val, align) = args;
    exists|one: T, mask: T, unmask: T, tmpval: T|
        {
            &&& #[trigger] call_ensures(T::from, (1u8,), one)
            &&& call_ensures(T::sub, (align, one), mask)
            &&& #[trigger] call_ensures(T::not, (mask,), unmask)
            &&& call_ensures(T::add, (val, mask), tmpval)
            &&& #[trigger] call_ensures(T::bitand, (tmpval, unmask), ret)
        }
}

pub open spec fn is_aligned_requires<T>(args: (T, T)) -> bool where T: IsAlignedSpec {
    let (val, align) = args;
    &&& forall|one| #[trigger] call_ensures(T::from, (1u8,), one) ==> spec_sub_requires(align, one)
    &&& forall|one: T, mask: T| #[trigger]
        call_ensures(T::from, (1u8,), one) && #[trigger] call_ensures(T::sub, (align, one), mask)
            ==> call_requires(T::bitand, (val, mask))
}

pub open spec fn is_aligned_ens<T>(args: (T, T), ret: bool) -> bool where T: IsAlignedSpec {
    let (val, align) = args;
    exists|zero: T, one: T, mask: T, b: T|
        {
            &&& #[trigger] call_ensures(T::from, (1u8,), one)
            &&& #[trigger] call_ensures(T::from, (0u8,), zero)
            &&& call_ensures(T::sub, (align, one), mask)
            &&& #[trigger] call_ensures(T::bitand, (val, mask), b)
            &&& #[trigger] call_ensures(T::eq, (&b, &zero), ret)
        }
}

pub open spec fn spec_is_aligned<T>(val: T, align: T) -> bool where
    T: IsAlignedSpec + FromIntoInteger,
 {
    val.into_spec() % align.into_spec() == 0
}

} // verus!
include!("util.proof.verus.rs");

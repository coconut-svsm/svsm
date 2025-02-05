// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// Specifications related to util.rs that are used in proof_align_down and proof_align_up.
verus! {

use verify_external::convert::*;
use verify_proof::bits::is_pow_of_2;
use vstd::std_specs::ops::*;
use vstd::std_specs::cmp::{SpecPartialEqOp, spec_partial_eq};

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

#[verifier(inline)]
pub open spec fn align_up_spec<T>(val: T, align: T) -> int where
    T: Add<Output = T> + Sub<Output = T> + BitAnd<Output = T> + Not<Output = T> + From<u8> + Copy,
 {
    spec_align_up(from_spec(val), from_spec(align))
}

pub open spec fn spec_align_down(val: int, align: int) -> int {
    val - val % align
}

#[verifier(inline)]
pub open spec fn align_down_spec<T>(val: T, align: T) -> int where
    T: Sub<Output = T> + Not<Output = T> + BitAnd<Output = T> + From<u8> + Copy,
 {
    spec_align_down(from_spec(val), from_spec(align))
}

pub open spec fn align_down_requires<T>(args: (T, T)) -> bool where
    T: Sub<Output = T> + BitAnd<Output = T>,
 {
    let (val, align) = args;
    let one = from_spec::<_, T>(1u8);
    &&& spec_sub_requires(align, one)
    &&& forall|v1: T, v2: T| #[trigger] spec_bitand_requires(v1, v2)
}

#[verifier(inline)]
pub open spec fn _align_down_ens<T>(val: T, align: T, ret: T, mask: T, unmask: T) -> bool {
    &&& spec_sub_ensures(align, from_spec::<_, T>(1u8), mask)
    &&& #[trigger] spec_not_ensures(mask, unmask)
    &&& spec_bitand_ensures(val, unmask, ret)
}

pub open spec fn align_down_ens<T>(args: (T, T), ret: T) -> bool {
    let (val, align) = args;
    exists|mask: T, unmask: T| _align_down_ens(val, align, ret, mask, unmask)
}

pub open spec fn align_up_requires<T>(args: (T, T)) -> bool where
    T: Sub<Output = T> + BitAnd<Output = T> + Add<Output = T>,
 {
    let (val, align) = args;
    let one = from_spec::<_, T>(1u8);
    &&& align_down_requires(args)
    &&& forall|mask: T| #[trigger]
        spec_sub_ensures(align, one, mask) ==> spec_add_requires(val, mask)
}

#[verifier(inline)]
pub open spec fn align_up_ens_inner<T>(
    val: T,
    align: T,
    ret: T,
    mask: T,
    unmask: T,
    tmpval: T,
) -> bool {
    &&& spec_sub_ensures(align, from_spec::<_, T>(1u8), mask)
    &&& #[trigger] spec_not_ensures(mask, unmask)
    &&& spec_add_ensures(val, mask, tmpval)
    &&& #[trigger] spec_bitand_ensures(tmpval, unmask, ret)
}

pub open spec fn align_up_ens<T>(args: (T, T), ret: T) -> bool {
    let (val, align) = args;
    exists|mask: T, unmask: T, tmpval: T| align_up_ens_inner(val, align, ret, mask, unmask, tmpval)
}

pub open spec fn impl_align_up_choose<T>(args: (T, T), ret: T) -> (T, T, T) {
    let (val, align) = args;
    choose|mask: T, unmask: T, tmpval: T| align_up_ens_inner(val, align, ret, mask, unmask, tmpval)
}

pub open spec fn is_aligned_requires<T>(args: (T, T)) -> bool where
    T: Sub<Output = T> + BitAnd<Output = T> + PartialEq,
 {
    let (val, align) = args;
    let one = from_spec::<_, T>(1u8);
    &&& spec_sub_requires(align, one)
    &&& forall|mask: T| #[trigger]
        spec_sub_ensures(align, one, mask) ==> spec_bitand_requires(val, mask)
    &&& forall|v1: T, v2: T| #[trigger] T::eq.requires((&v1, &v2))
}

#[verifier(inline)]
pub open spec fn is_aligned_ens_inner<T>(val: T, align: T, ret: bool, mask: T, b: T) -> bool where
    T: Sub<Output = T> + BitAnd<Output = T> + PartialEq + From<u8>,
 {
    &&& spec_sub_ensures(align, from_spec::<_, T>(1u8), mask)
    &&& #[trigger] spec_bitand_ensures(val, mask, b)
    &&& ret == spec_partial_eq(&b, &from_spec::<_, T>(0u8))
}

pub open spec fn is_aligned_ens<T>(args: (T, T), ret: bool) -> bool where
    T: Sub<Output = T> + BitAnd<Output = T> + PartialEq + From<u8>,
 {
    let (val, align) = args;
    exists|mask: T, b: T|
        #![trigger spec_bitand_ensures(val, mask, b)]
        { is_aligned_ens_inner(val, align, ret, mask, b) }
}

pub open spec fn spec_is_aligned<T>(addr: T, align: T) -> bool where
    T: Sub<Output = T> + BitAnd<Output = T> + PartialEq + From<u8>,
 {
    from_spec::<_, u64>(addr) % from_spec::<_, u64>(align) == 0
}

} // verus!
include!("util.proof.verus.rs");

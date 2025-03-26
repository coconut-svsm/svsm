// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// Proofs related to util.rs
verus! {

/// A meaningful align_down should be verified to equal to align_up_spec
/// align_down_ens ==> from_spec(ret) === align_down_spec
pub broadcast proof fn proof_align_down<T: IntegerAligned>(val: T, align: T) where
    u64: FromSpec<T>,
    int: FromSpec<T>,

    requires
        from_spec::<T, u64>(align) > 0,
        is_pow_of_2(from_spec(align)),
        #[trigger] align_down_requires((val, align)),
    ensures
        forall|ret| #[trigger]
            align_down_ens((val, align), ret) ==> from_spec(ret) === align_down_spec(val, align),
{
    assert forall|ret: T| #[trigger] align_down_ens((val, align), ret) implies from_spec(ret)
        === align_down_spec(val, align) by { T::lemma_align_down(val, align, ret) }
}

/// A meaningful align_up should be verified to equal to align_up_spec
/// align_up_ens ==> from_spec(ret) === align_up_spec
pub broadcast proof fn proof_align_up<T: IntegerAligned>(val: T, align: T) where
    u64: FromSpec<T>,
    int: FromSpec<T>,

    requires
        from_spec::<T, u64>(align) > 0,
        is_pow_of_2(from_spec(align)),
        align_up_requires((val, align)),
    ensures
        #![trigger align_up_requires((val, align))]
        forall|ret| #[trigger]
            align_up_ens((val, align), ret) ==> from_spec(ret) === align_up_spec(val, align),
{
    assert forall|ret: T| #[trigger] align_up_ens((val, align), ret) implies from_spec(ret)
        === align_up_spec(val, align) by {
        T::lemma_align_up(val, align, ret);
    }
}

broadcast group group_align_proofs {
    verify_proof::bits::lemma_bit_u64_not_is_sub,
    verify_proof::bits::lemma_bit_u64_shl_values,
    verify_proof::bits::lemma_bit_u64_and_mask,
    verify_proof::bits::lemma_bit_u64_and_mask_is_mod,
    verify_proof::bits::lemma_bit_u32_not_is_sub,
    verify_proof::bits::lemma_bit_u32_shl_values,
    verify_proof::bits::lemma_bit_u32_and_mask,
    verify_proof::bits::lemma_bit_u32_and_mask_is_mod,
    verify_proof::bits::lemma_bit_usize_not_is_sub,
    verify_proof::bits::lemma_bit_usize_shl_values,
    verify_proof::bits::lemma_bit_usize_and_mask,
    verify_proof::bits::lemma_bit_usize_and_mask_is_mod,
}

// put expensive proofs into another module.
mod util_align_up {
    use vstd::prelude::*;
    use vstd::arithmetic::div_mod::{
        lemma_add_mod_noop,
        lemma_mod_self_0,
        lemma_mod_twice,
        lemma_small_mod,
        lemma_sub_mod_noop,
    };
    use super::*;

    #[verifier::rlimit(4)]
    pub proof fn lemma_align_up(x: u64, align: u64) -> (ret: u64)
        requires
            is_pow_of_2(align as u64),
            x + align - 1 <= u64::MAX,
        ensures
            ret == add(x, sub(align, 1)) & !sub(align, 1),
            ret == spec_align_up(x as int, align as int),
    {
        broadcast use group_align_proofs;

        let mask = (align - 1) as u64;
        let y = (x + mask) as u64;
        verify_proof::bits::lemma_bit_u64_and_mask(y, !mask);
        verify_proof::bits::lemma_bit_u64_and_mask_is_mod(y, mask);
        let ret = add(x, sub(align, 1)) & !sub(align, 1);

        assert(y & !mask == sub(y, y & mask));
        let align = align as int;
        let x = x as int;
        let r = ((x + align) - 1) % align;
        if x % align == 0 {
            lemma_mod_self_0(align);
            lemma_add_mod_noop(x, align - 1, align);
            lemma_small_mod((align - 1) as nat, align as nat);
            lemma_mod_twice(x, align);
            assert(r == align - 1);
        } else {
            lemma_mod_self_0(align);
            lemma_sub_mod_noop(x + align, 1, align);
            lemma_sub_mod_noop(x % align, 1, align);
            lemma_add_mod_noop(x, align, align);
            lemma_mod_twice(x, align);
            lemma_small_mod(1, align as nat);
            assert(r == (x % align - 1) % align);
            lemma_small_mod((x % align - 1) as nat, align as nat);
            assert(r == (x % align - 1) as int);
        }
        ret
    }

    pub proof fn lemma_align_up_u32(x: u32, align: u32) -> (ret: u32)
        requires
            is_pow_of_2(align as u64),
            x + align - 1 <= u32::MAX,
        ensures
            ret == add(x, sub(align, 1)) & !sub(align, 1),
            ret == spec_align_up(x as int, align as int),
    {
        assert(align > 0) by {
            broadcast use verify_proof::bits::lemma_bit_u64_shl_values;

        }
        let mask = sub(align, 1);
        let r = add(x, sub(align, 1));
        let ret = add(x, sub(align, 1)) & !sub(align, 1);
        verify_proof::bits::lemma_bit_u32_and_mask(r, mask);
        verify_proof::bits::lemma_bit_u32_and_mask(r, !mask);
        verify_proof::bits::lemma_bit_u64_and_mask(r as u64, mask as u64);
        verify_proof::bits::lemma_bit_u64_and_mask(r as u64, !sub(align as u64, 1));
        lemma_align_up(x as u64, align as u64);
        ret
    }

}

pub use util_align_up::*;

mod util_align_down {
    use super::*;

    pub proof fn lemma_align_down(x: u64, align: u64)
        requires
            align_requires(align),
        ensures
            (x & !((align - 1) as u64)) == spec_align_down(x as int, align as int),
    {
        broadcast use group_align_proofs;

        let mask: u64 = sub(align, 1);
        assert(x == (x & !mask) + (x & mask));
    }

    pub proof fn lemma_align_down_u32(x: u32, align: u32)
        requires
            align_requires(align as u64),
        ensures
            (x & !((align - 1) as u32)) == spec_align_down(x as int, align as int),
    {
        assert(align > 0) by {
            broadcast use verify_proof::bits::lemma_bit_u64_shl_values;

        }
        let mask = sub(align, 1);
        verify_proof::bits::lemma_bit_u32_and_mask(x, mask);
        verify_proof::bits::lemma_bit_u32_and_mask(x, !mask);
        verify_proof::bits::lemma_bit_u64_and_mask(x as u64, mask as u64);
        verify_proof::bits::lemma_bit_u64_and_mask(x as u64, !sub(align as u64, 1));
        lemma_align_down(x as u64, align as u64);
    }

}

pub use util_align_down::*;

pub trait IntegerAligned: Add<Output = Self> + Sub<Output = Self> + BitAnd<Output = Self> + Not<
    Output = Self,
> + From<u8> + Copy + FromSpec<u8> + SpecSubOp<Self> + SpecAddOp<Self> + SpecBitAndOp<
    Self,
> + SpecNotOp + SpecPartialEqOp<Self> + core::cmp::PartialEq where
    u64: FromSpec<Self>,
    int: FromSpec<Self>,
 {
    proof fn lemma_is_aligned(val: Self, align: Self, ret: bool)
        requires
            from_spec::<Self, u64>(align) > 0,
            is_pow_of_2(from_spec::<_, u64>(align) as u64),
            is_aligned_requires((val, align)),
            is_aligned_ens((val, align), ret),
        ensures
            ret == spec_is_aligned(val, align),
    ;

    proof fn lemma_align_down(val: Self, align: Self, ret: Self)
        requires
            from_spec::<Self, u64>(align) > 0,
            is_pow_of_2(from_spec(align)),
            align_down_requires((val, align)),
            align_down_ens((val, align), ret),
        ensures
            from_spec::<_, int>(ret) == align_down_spec(val, align),
    ;

    proof fn lemma_align_up(val: Self, align: Self, ret: Self)
        requires
            from_spec::<Self, u64>(align) > 0,
            is_pow_of_2(from_spec(align)),
            align_up_ens((val, align), ret),
            align_up_requires((val, align)),
        ensures
            from_spec::<_, int>(ret) == align_up_spec(val, align),
    ;
}

mod util_integer_align {
    use super::*;

    broadcast use vstd::group_vstd_default, verify_external::external_axiom;

    impl IntegerAligned for u64 {
        proof fn lemma_is_aligned(val: u64, align: u64, ret: bool) {
            broadcast use group_align_proofs;

            assert(ret == (val & sub(align, 1) == 0));
        }

        proof fn lemma_align_down(val: Self, align: Self, ret: Self) {
            util_align_down::lemma_align_down(val, align);
        }

        proof fn lemma_align_up(val: Self, align: Self, ret: Self) {
            util_align_up::lemma_align_up(val, align);
        }
    }

    impl IntegerAligned for usize {
        proof fn lemma_is_aligned(val: usize, align: usize, ret: bool) {
            u64::lemma_is_aligned(val as u64, align as u64, ret)
        }

        proof fn lemma_align_down(val: Self, align: Self, ret: Self) {
            u64::lemma_align_down(val as u64, align as u64, ret as u64)
        }

        proof fn lemma_align_up(val: Self, align: Self, ret: Self) {
            u64::lemma_align_up(val as u64, align as u64, ret as u64)
        }
    }

    impl IntegerAligned for u32 {
        proof fn lemma_is_aligned(val: u32, align: u32, ret: bool) {
            broadcast use group_align_proofs;

            assert(ret == (val & (align - 1) as u32 == 0));
        }

        proof fn lemma_align_down(val: Self, align: Self, ret: Self) {
            util_align_down::lemma_align_down_u32(val, align);
        }

        proof fn lemma_align_up(val: Self, align: Self, ret: Self) {
            util_align_up::lemma_align_up_u32(val, align);
        }
    }

}

} // verus!

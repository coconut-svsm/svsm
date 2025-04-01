// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
use vstd::arithmetic::power2::pow2;
use vstd::bits::low_bits_mask;
use vstd::prelude::*;

#[macro_export]
macro_rules! POW2_VALUE {
    (0) => {
        0x1u64
    };
    (1) => {
        0x2u64
    };
    (2) => {
        0x4u64
    };
    (3) => {
        0x8u64
    };
    (4) => {
        0x10u64
    };
    (5) => {
        0x20u64
    };
    (6) => {
        0x40u64
    };
    (7) => {
        0x80u64
    };
    (8) => {
        0x100u64
    };
    (9) => {
        0x200u64
    };
    (10) => {
        0x400u64
    };
    (11) => {
        0x800u64
    };
    (12) => {
        0x1000u64
    };
    (13) => {
        0x2000u64
    };
    (14) => {
        0x4000u64
    };
    (15) => {
        0x8000u64
    };
    (16) => {
        0x10000u64
    };
    (17) => {
        0x20000u64
    };
    (18) => {
        0x40000u64
    };
    (19) => {
        0x80000u64
    };
    (20) => {
        0x100000u64
    };
    (21) => {
        0x200000u64
    };
    (22) => {
        0x400000u64
    };
    (23) => {
        0x800000u64
    };
    (24) => {
        0x1000000u64
    };
    (25) => {
        0x2000000u64
    };
    (26) => {
        0x4000000u64
    };
    (27) => {
        0x8000000u64
    };
    (28) => {
        0x10000000u64
    };
    (29) => {
        0x20000000u64
    };
    (30) => {
        0x40000000u64
    };
    (31) => {
        0x80000000u64
    };
    (32) => {
        0x100000000u64
    };
    (33) => {
        0x200000000u64
    };
    (34) => {
        0x400000000u64
    };
    (35) => {
        0x800000000u64
    };
    (36) => {
        0x1000000000u64
    };
    (37) => {
        0x2000000000u64
    };
    (38) => {
        0x4000000000u64
    };
    (39) => {
        0x8000000000u64
    };
    (40) => {
        0x10000000000u64
    };
    (41) => {
        0x20000000000u64
    };
    (42) => {
        0x40000000000u64
    };
    (43) => {
        0x80000000000u64
    };
    (44) => {
        0x100000000000u64
    };
    (45) => {
        0x200000000000u64
    };
    (46) => {
        0x400000000000u64
    };
    (47) => {
        0x800000000000u64
    };
    (48) => {
        0x1000000000000u64
    };
    (49) => {
        0x2000000000000u64
    };
    (50) => {
        0x4000000000000u64
    };
    (51) => {
        0x8000000000000u64
    };
    (52) => {
        0x10000000000000u64
    };
    (53) => {
        0x20000000000000u64
    };
    (54) => {
        0x40000000000000u64
    };
    (55) => {
        0x80000000000000u64
    };
    (56) => {
        0x100000000000000u64
    };
    (57) => {
        0x200000000000000u64
    };
    (58) => {
        0x400000000000000u64
    };
    (59) => {
        0x800000000000000u64
    };
    (60) => {
        0x1000000000000000u64
    };
    (61) => {
        0x2000000000000000u64
    };
    (62) => {
        0x4000000000000000u64
    };
    (63) => {
        0x8000000000000000u64
    };
    ($_:expr) => {
        0u64
    };
}

verus! {

#[verifier(inline)]
pub open spec fn bit_value(n: u64) -> u64
    recommends
        n < 64,
{
    seq_macro::seq! { N in 0..64 {
    #(if n == N {
        POW2_VALUE!(N)
    } else)*
    {
        0
    }
}
}
}

} // verus!
verus! {

pub open spec fn is_pow_of_2(val: u64) -> bool {
    seq_macro::seq! {N in 0..64 {#(
            val == 1u64 << N ||
        )* false
    }}
}

#[verifier(inline)]
pub open spec fn pow2_to_bits(val: u64) -> u64 {
    choose|ret: u64| (1u64 << ret) == val && 0 <= ret < 64
}

} // verus!
#[rustfmt::skip]
macro_rules! bit_shl_values {
    ($typ:ty, $styp:ty, $one: expr, $pname: ident) => {
        seq_macro::seq! {N in 0..64 {verus! {
        #[doc = "Proof that shifting 1 by N has a bound."]
        pub broadcast proof fn $pname()
        ensures
        #(
            #![trigger ($one << N)]
        )*
        #(
            N < $styp::BITS ==> ($one << N) == POW2_VALUE!(N),
        )*
        {
            #(assert($one << N == POW2_VALUE!(N)) by(compute_only);)*
        }
        }
}}
    };
}

macro_rules! bit_not_properties {
    ($typ:ty, $styp:ty, $sname: ident, $autopname: ident) => {
        verus! {
        #[doc = "Proof that !a is equal to max - a, and !!a == a"]
        pub broadcast proof fn $autopname(a: $typ)
            ensures
                #[trigger]!a == sub($styp::MAX as $typ, a),
                !(!a) == a,
        {
            assert(!(!a) == a) by(bit_vector);
            assert((!a) == $styp::MAX - a) by(bit_vector);
        }
        }
    };
}

macro_rules! bit_set_clear_mask {
    ($typ:ty, $styp:ty, $pname_or_mask: ident, $pname_and_mask: ident) => {
        verus! {
        #[doc = "Proof that a mask m is set with or operation."]
        #[verifier(bit_vector)]
        pub broadcast proof fn $pname_or_mask(a: $typ, m: $typ)
            ensures
                (#[trigger](a | m)) & m == m,
                (a | m) & (!m) == a & (!m),
                a | m >= a,
                a | m >= m,
                a == (a|m) - m + (a|!m) - !m
        {}

        #[doc = "Proof that a mask m is cleared with and operation."]
        #[verifier(bit_vector)]
        pub broadcast proof fn $pname_and_mask(a: $typ, m: $typ)
            ensures
                (#[trigger](a & m)) & !m == 0,
                (a & m) & m == a & m,
                a & m <= m,
                a & m <= a,
                a == (a & m) + (a & !m),
        {}
        }
    };
}

verus! {

pub broadcast proof fn lemma_bit_u64_and_mask_is_mod(x: u64, mask: u64)
    requires
        mask < u64::MAX,
        is_pow_of_2((mask + 1) as u64),
    ensures
        #[trigger] (x & mask) == x as int % (mask + 1),
{
    broadcast use lemma_bit_u64_shl_values;
    broadcast use vstd::bits::lemma_u64_pow2_no_overflow;

    let align = mask + 1;
    let bit = pow2_to_bits(align as u64) as nat;
    assert(1u64 << bit == pow2(bit)) by {
        broadcast use vstd::bits::lemma_u64_shl_is_mul;

    }
    assert(mask == low_bits_mask(bit));
    assert(x & (low_bits_mask(bit) as u64) == x as nat % (pow2(bit))) by {
        broadcast use vstd::bits::lemma_u64_low_bits_mask_is_mod;

    }
}

} // verus!
macro_rules! bit_and_mask_is_mod {
    ($typ:ty, $pname: ident) => {
        verus! {
        pub broadcast proof fn $pname(x: $typ, mask: $typ)
        requires
            mask < $typ::MAX,
            is_pow_of_2((mask + 1) as u64),
        ensures
            #[trigger] (x & mask) == (x as int) % (mask + 1),
        {
            lemma_bit_u64_and_mask_is_mod(x as u64, mask as u64);
        }
        }
    };
}

bit_shl_values! {u64, u64, 1u64, lemma_bit_u64_shl_values}
bit_not_properties! {u64, u64, spec_bit_u64_not_properties, lemma_bit_u64_not_is_sub}
bit_set_clear_mask! {u64, u64, lemma_bit_u64_or_mask, lemma_bit_u64_and_mask}

bit_shl_values! {usize, u64, 1usize, lemma_bit_usize_shl_values}
bit_not_properties! {usize, u64, spec_bit_usize_not_properties, lemma_bit_usize_not_is_sub}
bit_set_clear_mask! {usize, u64, lemma_bit_usize_or_mask, lemma_bit_usize_and_mask}
bit_and_mask_is_mod! {usize, lemma_bit_usize_and_mask_is_mod}

bit_shl_values! {u32, u32, 1usize, lemma_bit_u32_shl_values}
bit_not_properties! {u32, u32, spec_bit_u32_not_properties, lemma_bit_u32_not_is_sub}
bit_set_clear_mask! {u32, u32, lemma_bit_u32_or_mask, lemma_bit_u32_and_mask}
bit_and_mask_is_mod! {u32, lemma_bit_u32_and_mask_is_mod}
verus! {

pub broadcast proof fn lemma_pow2_eq_bit_value(n: nat)
    requires
        n < u64::BITS,
    ensures
        bit_value(n as u64) == #[trigger] pow2(n),
    decreases n,
{
    vstd::arithmetic::power2::lemma2_to64();
    if n > 0 {
        vstd::arithmetic::power2::lemma_pow2_unfold(n);
    }
    if n > 32 {
        lemma_pow2_eq_bit_value((n - 1) as nat);
    }
}

pub broadcast proof fn lemma_bit_usize_shr_is_div(v: usize, n: usize)
    requires
        n < usize::BITS,
    ensures
        (#[trigger] (v >> n)) == v as int / bit_value(n as u64) as int,
{
    vstd::bits::lemma_u64_shr_is_div(v as u64, n as u64);
    lemma_pow2_eq_bit_value(n as nat);
}

} // verus!

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
use vstd::arithmetic::power2::pow2;
use vstd::bits::low_bits_mask;
use vstd::prelude::*;

#[macro_export]
macro_rules! BIT64_MASK {
    ($n: expr) => {
        (((1u64 << ($n)) - 1) as u64)
    };
}
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
    ($typ:ty, $styp:ty, $pname_or_mask: ident, $pname_and_mask: ident, $pname_and_mask_bound: ident) => {
        verus! {
        #[doc = "Proof that a mask m is set with or operation."]
        #[verifier(bit_vector)]
        pub broadcast proof fn $pname_or_mask(a: $typ, m: $typ)
            ensures
                (#[trigger](a | m)) & m == m,
                (a | m) & (!m) == a & (!m),
                a | m >= a,
                a | m >= m,
                a | m <= a + m,
                a == (a|m) - m + (a|!m) - !m,
                m == 0 ==> (a | m) == a,
                a == 0 ==> (a | m) == m,
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
                a == 0 | m == 0 ==> #[trigger](a & m) == 0,
        {}

        #[doc = "Proof that a & m <= a and a & m <= m."]
        #[verifier(bit_vector)]
        pub broadcast proof fn $pname_and_mask_bound(a: $typ, m: $typ)
            ensures
                (#[trigger](a & m)) <= m,
                a & m <= a,
        {}
        }
    };
}

verus! {

#[verifier(bit_vector)]
pub proof fn lemma_bit_u64_bitmask_and_min_effect(x: u64, n: u64, m: u64)
    requires
        n < u64::BITS,
        m < u64::BITS,
    ensures
        n <= m ==> x & BIT64_MASK!(m) & BIT64_MASK!(n) == x & BIT64_MASK!(n),
        n >= m ==> x & BIT64_MASK!(n) & BIT64_MASK!(m) == x & BIT64_MASK!(m),
{
}

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
bit_set_clear_mask! {u64, u64, lemma_bit_u64_or_mask, lemma_bit_u64_and_mask, lemma_bit_u64_and_bound}

bit_shl_values! {usize, u64, 1usize, lemma_bit_usize_shl_values}
bit_not_properties! {usize, u64, spec_bit_usize_not_properties, lemma_bit_usize_not_is_sub}
bit_set_clear_mask! {usize, u64, lemma_bit_usize_or_mask, lemma_bit_usize_and_mask, lemma_bit_usize_and_bound}
bit_and_mask_is_mod! {usize, lemma_bit_usize_and_mask_is_mod}

bit_shl_values! {u32, u32, 1usize, lemma_bit_u32_shl_values}
bit_not_properties! {u32, u32, spec_bit_u32_not_properties, lemma_bit_u32_not_is_sub}
bit_set_clear_mask! {u32, u32, lemma_bit_u32_or_mask, lemma_bit_u32_and_mask, lemma_bit_u32_and_bound}
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

#[verifier(bit_vector)]
pub broadcast proof fn lemma_bit_u64_shr_bound(v: u64, n: u64)
    requires
        n < u64::BITS,
    ensures
        n > 0 ==> (#[trigger] (v >> n)) < 1u64 << (u64::BITS - n) as u64,
        n == 0 ==> (v >> n) == v,
        v >> n <= v,
{
}

pub broadcast proof fn lemma_bit_u64_shr_properties(v: u64, n: u64)
    requires
        n < u64::BITS,
    ensures
        (#[trigger] (v >> n)) == v as int / bit_value(n as u64) as int,
        v < (1u64 << n) <==> v >> n == 0,
        0 >> n == 0,
{
    vstd::bits::lemma_u64_shr_is_div(v as u64, n as u64);
    lemma_pow2_eq_bit_value(n as nat);
    broadcast use lemma_bit_u64_shl_values;

    assert(0 >> n == 0) by (bit_vector);
}

#[verifier(bit_vector)]
pub broadcast proof fn lemma_bit_u64_shl_properties(v: u64, n: u64)
    requires
        n < u64::BITS,
        n > 0 ==> v < 1u64 << (u64::BITS - n) as u64,
    ensures
        #![trigger (v << n)]
        v > 0 ==> (v << n) >= 1u64 << n,
        0 << n == 0,
{
}

#[verifier(bit_vector)]
pub proof fn lemma_u64_or_shl(x: u64, y: u64, n: u64)
    requires
        n < u64::BITS,
    ensures
        (x | y) << n == (x << n) | (y << n),
{
}

#[verifier(bit_vector)]
pub broadcast proof fn lemma_u64_or_is_associative(x: u64, y: u64, z: u64)
    ensures
        #![trigger (x | y | z)]
        (x | y) | z == x | (y | z),
{
}

#[verifier(bit_vector)]
pub broadcast proof fn lemma_u64_shl_is_distributive_or(x: u64, y: u64, n: u64)
    requires
        n < u64::BITS,
    ensures
        #![trigger (x | y) << n]
        #![trigger (x << n) | (y << n)]
        (x | y) << n == (x << n) | (y << n),
{
}

#[verifier(bit_vector)]
pub broadcast proof fn lemma_u64_shr_is_distributive_or(x: u64, y: u64, n: u64)
    requires
        n < u64::BITS,
    ensures
        #![trigger (x | y) >> n]
        (x | y) >> n == (x >> n) | (y >> n),
{
}

#[verifier(bit_vector)]
pub proof fn lemma_u64_and_is_distributive_or(x: u64, y: u64, z: u64)
    ensures
        #![trigger (x | y) & z]
        (x | y) & z == (x & z) | (y & z),
{
}

#[verifier(bit_vector)]
pub proof fn lemma_u64_and_bitmask_lower(x: u64, n: u64)
    requires
        n < u64::BITS,
        x < (1u64 << n),
    ensures
        x & ((1u64 << n) - 1) as u64 == x,
{
}

#[verifier(bit_vector)]
pub proof fn lemma_u64_and_bitmask_higher(x: u64, n: u64, m: u64)
    requires
        n <= m < u64::BITS,
    ensures
        (x << m) & ((1u64 << n) - 1) as u64 == 0,
{
}

pub broadcast proof fn lemma_u64_or_low_high_bitmask_lower(x: u64, y: u64, n: u64, m: u64)
    requires
        n <= m < u64::BITS,
        x <= (1u64 << n) - 1,
    ensures
        #[trigger] ((x | y << m) & ((1u64 << n) - 1) as u64) == x,
{
    let mask = ((1u64 << n) - 1) as u64;
    let tmpy = y << m;
    let ret = (x | tmpy) & mask as u64;
    lemma_u64_and_is_distributive_or(x, y << m, mask as u64);
    assert(ret == (x & mask) | (tmpy & mask));
    lemma_u64_and_bitmask_higher(y, n, m);
    assert((tmpy & mask) == 0);
    lemma_u64_and_bitmask_lower(x, n);
    assert(x | 0 == x) by (bit_vector);
}

#[verifier(bit_vector)]
pub proof fn lemma_u64_shl_add(x: u64, n: u64, m: u64)
    requires
        n + m < u64::BITS,
    ensures
        (x << n) << m == (x << (n + m)),
        (x << m) << n == (x << (m + n)),
{
}

#[verifier(bit_vector)]
proof fn lemma_u64_shr_add_one(x: u64, n: u64)
    requires
        n + 1 < u64::BITS,
    ensures
        (x >> n) >> 1 == (x >> (n + 1)),
{
}

pub proof fn lemma_u64_shr_add(x: u64, n: u64, m: u64)
    requires
        n + m < u64::BITS,
    ensures
        (x >> n) >> m == (x >> (n + m)),
    decreases m,
{
    if m > 0 {
        lemma_u64_shr_add(x, n, (m - 1) as u64);
        lemma_u64_shr_add_one(x >> n, (m - 1) as u64);
        lemma_u64_shr_add_one(x, (n + m - 1) as u64);
        assert((x >> n) >> m == (x >> (n + m - 1)) >> 1);
    } else {
        assert((x >> n) >> 0 == x >> n) by (bit_vector);
    }
}

#[verifier(bit_vector)]
proof fn lemma_u64_shlr_same(x: u64, n: u64)
    requires
        n > 0 ==> x < 1usize << (u64::BITS - n) as u64,
        n < u64::BITS,
    ensures
        (x << n) >> n == x,
{
}

pub broadcast proof fn lemma_u64_shl_shr(x: u64, n: u64, m: u64)
    requires
        n > 0 ==> x < 1usize << (u64::BITS - n),
        n < u64::BITS,
        m < u64::BITS,
        n <= m,
    ensures
        n < m ==> #[trigger] ((x << n) >> m) == (x >> (m - n)),
        n == m ==> (x << n) >> m == x,
    decreases m,
{
    if m == 0 || n == 0 {
        assert((x << n) >> 0 == x << n) by (bit_vector);
        assert(x << 0 == x) by (bit_vector);
        assert(x >> 0 == x) by (bit_vector);
    } else if n == m {
        lemma_u64_shlr_same(x, n);
    } else {
        let mm = (m - 1) as u64;
        lemma_u64_shl_shr(x, n, mm);
        lemma_u64_shr_add_one(x << n, mm);
        if n < m {
            let diff = (mm - n) as u64;
            lemma_u64_shr_add_one(x, diff);
        }
    }
}

proof fn lemma_bit_u64_shl_bit_bound(x: u64, n: u64, m: u64)
    requires
        x < (1u64 << m),
        n + m < u64::BITS,
    ensures
        (x << n) <= (1usize << (m + n)) - (1u64 << n),
        x == ((1u64 << m) - 1) ==> (x << n) == (1usize << (m + n)) - (1u64 << n),
{
    broadcast use lemma_bit_u64_shl_values;
    broadcast use vstd::bits::lemma_u64_pow2_no_overflow;

    let upper = ((1u64 << m) - 1) as u64;
    vstd::bits::lemma_u64_shl_is_mul(1u64, m);
    vstd::bits::lemma_u64_shl_is_mul(1u64, n);
    vstd::bits::lemma_u64_shl_is_mul(1u64, (n + m) as u64);
    vstd::arithmetic::mul::lemma_mul_strict_inequality(
        x as int,
        pow2(m as nat) as int,
        pow2(n as nat) as int,
    );
    vstd::arithmetic::power2::lemma_pow2_adds(m as nat, n as nat);
    vstd::bits::lemma_u64_shl_is_mul(x, n);
    vstd::bits::lemma_u64_shl_is_mul(1u64, (m + n) as u64);
    vstd::arithmetic::mul::lemma_mul_inequality(
        x as int,
        pow2(m as nat) - 1,
        pow2(n as nat) as int,
    );
    vstd::arithmetic::mul::lemma_mul_is_distributive_sub_other_way(
        pow2(n as nat) as int,
        pow2(m as nat) as int,
        1,
    );
}

/// a is the low part, b is the high part
/// n is the number of bits in a
/// m is the number of bits in b
/// a and b are both less than 2^n and 2^m respectively
/// Proves that a and b can be extracted from a | (b << n) using bitwise operations
pub proof fn lemma_bit_u64_extract_fields2(a: u64, b: u64, n: u64, m: u64)
    requires
        a < (1u64 << n),
        n < u64::BITS,
        b < 1u64 << m,
        n + m <= u64::BITS,
        n > 0,
        m > 0,
    ensures
        ((a | (b << n)) >> n) & sub(1u64 << m, 1) == b,
        (a | (b << n)) & sub((1u64 << n), 1) == a,
        (b & sub(1u64 << m, 1)) == b,
        a & sub(1u64 << n, 1) == a,
        (a | (b << n)) >> n == b,
        a >> n == 0,
        (n + m) < u64::BITS ==> (a | b << n) < (1u64 << (n + m)),
{
    let mask1 = sub(1u64 << n, 1);
    let mask2 = sub(1u64 << m, 1);
    let field2 = (b & mask2);
    assert((b << n) <= BIT64_MASK!(m) << n) by (bit_vector)
        requires
            b <= BIT64_MASK!(m),
            n < u64::BITS,
            m < u64::BITS,
    ;
    if (n + m) < u64::BITS {
        lemma_bit_u64_or_mask(a, b << n);
        lemma_bit_u64_shl_bit_bound(b, n, m);
    }
    lemma_u64_and_bitmask_lower(b, m);
    lemma_u64_and_bitmask_lower(a, n);
    lemma_u64_and_bitmask_higher(b, n, n);
    lemma_bit_u64_and_mask(b, mask2);
    lemma_u64_shr_is_distributive_or(a, b << n, n);
    lemma_u64_and_is_distributive_or(a, b << n, mask1);
    lemma_bit_u64_shr_properties(a, n);
    assert(1u64 << m <= 1usize << (u64::BITS - n)) by {
        broadcast use lemma_bit_u64_shl_values;

    };
    lemma_u64_shl_shr(b, n, n);
    lemma_bit_u64_or_mask(0, b);
    lemma_bit_u64_or_mask(a, 0);
}

pub proof fn lemma_bit_u64_extract_mid_field(x: u64, bits1: u64, bits2: u64)
    requires
        bits1 + bits2 < u64::BITS,
    ensures
        (((x & BIT64_MASK!(bits2 + bits1)) >> bits1) & BIT64_MASK!(bits2)) == ((x >> bits1)
            & BIT64_MASK!(bits2)),
        ((x & BIT64_MASK!(bits2 + bits1)) & BIT64_MASK!(bits1)) == (x & BIT64_MASK!(bits1)),
{
    let m = (bits1 + bits2) as u64;
    let mask = BIT64_MASK!(m);
    let mask2 = BIT64_MASK!(bits2);
    assert((x & mask) >> bits1 == (x >> bits1) & (mask >> bits1)) by (bit_vector);
    assert(BIT64_MASK!(m) >> bits1 == BIT64_MASK!(bits2)) by (bit_vector)
        requires
            bits2 <= m < u64::BITS,
            bits1 == m - bits2,
    ;
    lemma_bit_u64_bitmask_and_min_effect(x >> bits1, bits2, bits2);
    lemma_bit_u64_bitmask_and_min_effect(x, bits1, m);
}

} // verus!
macro_rules! bit_xor_neighbor {
    ($typ:ty, $pname: ident) => {
        verus!{
        #[verifier::bit_vector]
        pub proof fn $pname(pfn: $typ, order: $typ)
        requires
            pfn & sub((1u8 as $typ) << order, 1) == 0,
        ensures
            ((pfn & sub((1u8 as $typ) << add(order, 1), 1)) == 0) ==>  (pfn ^ ((1u8 as $typ) << order)) == add(pfn, ((1u8 as $typ) << order)),
            ((pfn & sub((1u8 as $typ) << add(order, 1), 1)) != 0) ==>  (pfn ^ ((1u8 as $typ) << order)) == sub(pfn, ((1u8 as $typ) << order)),
        {}
        }
    };
}

bit_xor_neighbor! {usize, lemma_bit_usize_xor_neighbor}

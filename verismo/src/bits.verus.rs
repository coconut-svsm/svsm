// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
use vstd::prelude::*;

verus! {

#[verifier(inline)]
pub open spec fn bit_value(n: u64) -> u64
    recommends
        n < 64,
{
    if n == 0 {
        0x1
    } else if n == 1 {
        0x2
    } else if n == 2 {
        0x4
    } else if n == 3 {
        0x8
    } else if n == 4 {
        0x10
    } else if n == 5 {
        0x20
    } else if n == 6 {
        0x40
    } else if n == 7 {
        0x80
    } else if n == 8 {
        0x100
    } else if n == 9 {
        0x200
    } else if n == 10 {
        0x400
    } else if n == 11 {
        0x800
    } else if n == 12 {
        0x1000
    } else if n == 13 {
        0x2000
    } else if n == 14 {
        0x4000
    } else if n == 15 {
        0x8000
    } else if n == 16 {
        0x10000
    } else if n == 17 {
        0x20000
    } else if n == 18 {
        0x40000
    } else if n == 19 {
        0x80000
    } else if n == 20 {
        0x100000
    } else if n == 21 {
        0x200000
    } else if n == 22 {
        0x400000
    } else if n == 23 {
        0x800000
    } else if n == 24 {
        0x1000000
    } else if n == 25 {
        0x2000000
    } else if n == 26 {
        0x4000000
    } else if n == 27 {
        0x8000000
    } else if n == 28 {
        0x10000000
    } else if n == 29 {
        0x20000000
    } else if n == 30 {
        0x40000000
    } else if n == 31 {
        0x80000000
    } else if n == 32 {
        0x100000000
    } else if n == 33 {
        0x200000000
    } else if n == 34 {
        0x400000000
    } else if n == 35 {
        0x800000000
    } else if n == 36 {
        0x1000000000
    } else if n == 37 {
        0x2000000000
    } else if n == 38 {
        0x4000000000
    } else if n == 39 {
        0x8000000000
    } else if n == 40 {
        0x10000000000
    } else if n == 41 {
        0x20000000000
    } else if n == 42 {
        0x40000000000
    } else if n == 43 {
        0x80000000000
    } else if n == 44 {
        0x100000000000
    } else if n == 45 {
        0x200000000000
    } else if n == 46 {
        0x400000000000
    } else if n == 47 {
        0x800000000000
    } else if n == 48 {
        0x1000000000000
    } else if n == 49 {
        0x2000000000000
    } else if n == 50 {
        0x4000000000000
    } else if n == 51 {
        0x8000000000000
    } else if n == 52 {
        0x10000000000000
    } else if n == 53 {
        0x20000000000000
    } else if n == 54 {
        0x40000000000000
    } else if n == 55 {
        0x80000000000000
    } else if n == 56 {
        0x100000000000000
    } else if n == 57 {
        0x200000000000000
    } else if n == 58 {
        0x400000000000000
    } else if n == 59 {
        0x800000000000000
    } else if n == 60 {
        0x1000000000000000
    } else if n == 61 {
        0x2000000000000000
    } else if n == 62 {
        0x4000000000000000
    } else if n == 63 {
        0x8000000000000000
    } else {
        0
    }
}

pub open spec fn is_pow_of_2(val: u64) -> bool {
    seq_macro::seq! {N in 0..63 {#(
            val == bit_value(N) ||
        )* false
    }}
}

} // verus!
macro_rules! bit_shl_values {
    ($typ:ty, $styp:ty, $one: expr, $pname: ident) => {
        verus! {
        #[doc = "Proof that shifting 1 by N has a bound."]
        pub broadcast proof fn $pname(offset: $typ)
        requires 0 <= offset < $styp::BITS
        ensures
            #[trigger]($one << offset) == bit_value(offset as u64),
        {
            assert($one << offset == bit_value(offset as u64)) by(bit_vector);
        }
        }
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
                a == add(a & m, a & !m),
        {}
        }
    };
}

bit_shl_values! {u64, u64, 1u64, lemma_bit_u64_shl_values}
bit_not_properties! {u64, u64, spec_bit_u64_not_properties, lemma_bit_u64_not_is_sub}
bit_set_clear_mask! {u64, u64, lemma_bit_u64_or_mask, lemma_bit_u64_and_mask}

bit_shl_values! {usize, u64, 1usize, lemma_bit_usize_shl_values}
bit_not_properties! {usize, u64, spec_bit_usize_not_properties, lemma_bit_usize_not_is_sub}
bit_set_clear_mask! {usize, u64, lemma_bit_usize_or_mask, lemma_bit_usize_and_mask}

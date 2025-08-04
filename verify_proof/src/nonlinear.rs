// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
use vstd::prelude::*;
verus! {

pub proof fn lemma_modulus_product_divisibility(x: int, m: int, k: int)
    requires
        m != 0,
        k != 0,
        x % (k * m) == 0,
    ensures
        x % m == 0,
{
    let n = k * m;
    let i = x / n;
    assert(k * m != 0) by (nonlinear_arith)
        requires
            k != 0,
            m != 0,
    ;
    assert(i * n == x) by (nonlinear_arith)
        requires
            i == x / n,
            x % n == 0,
            n != 0,
    ;
    assert((i * k) * m == i * (k * m)) by (nonlinear_arith);
    assert(x % m == 0) by (nonlinear_arith)
        requires
            x == (i * k) * m,
            m != 0,
    ;
}

pub proof fn lemma_modulus_add_sub_m(x: int, m: int)
    requires
        m != 0,
        x % m == 0,
    ensures
        x % (2 * m) != 0 ==> (((x - m) % (2 * m) == 0) && (x >= m || x <= -m)),
        (x + m) % m == 0,
        (x - m) % m == 0,
{
    let i = x / m;
    let n = 2 * m;

    assert((i + 1) * m == i * m + m) by (nonlinear_arith);
    assert((i - 1) * m == i * m - m) by (nonlinear_arith);
    assert(i * m == x) by (nonlinear_arith)
        requires
            x % m == 0,
            m != 0,
            i == x / m,
    ;
    assert((x + m) % m == 0) by (nonlinear_arith)
        requires
            (i + 1) * m == x + m,
            m != 0,
    ;

    assert((x - m) % m == 0) by (nonlinear_arith)
        requires
            (i - 1) * m == x - m,
            m != 0,
    ;

    let j = i / 2;
    broadcast use vstd::arithmetic::mul::lemma_mul_is_commutative;

    assert(i == j * 2 || i == j * 2 + 1);
    if i == j * 2 {
        assert(j * 2 * m == j * (2 * m)) by (nonlinear_arith);
        assert(x % n == 0) by (nonlinear_arith)
            requires
                j * n == x,
                n != 0,
        ;
    }
    if x % n != 0 {
        assert(i == j * 2 + 1);
        assert(i >= 1 || i <= -1);
        assert(x - m == (j * 2 + 1) * m - m);
        assert((j * 2 + 1) * m - m == j * (2 * m)) by (nonlinear_arith);
        assert((x - m) % n == 0) by (nonlinear_arith)
            requires
                x - m == j * n,
                n != 0,
        ;
        assert(x >= m || x <= -m) by (nonlinear_arith)
            requires
                x == i * m,
                i >= 1 || i <= -1,
        ;
    }
}

#[verifier(inline)]
pub open spec fn align_down_ens(val: int, align: int, ret: int) -> bool {
    &&& ret % align == 0
    &&& ret <= val < ret + align
}

#[verifier(nonlinear)]
proof fn lemma_is_aligned_down_iff(val: int, align: int, ret: int)
    requires
        align > 0,
    ensures
        align_down_ens(val, align, ret) <==> (ret == val - val % align),
{
}

proof fn lemma_mod_bound(val: int, align: int)
    requires
        align > 0,
    ensures
        val >= 0 <==> (val - val % align) >= 0,
        0 <= val % align < align,
{
    assert(val >= 0 <==> (val - val % align) >= 0) by (nonlinear_arith)
        requires
            align > 0,
    ;
    assert(0 <= val % align < align) by (nonlinear_arith)
        requires
            align > 0,
    ;
}

pub proof fn lemma_align_down_properties(val: int, align: int, ret: int)
    requires
        align > 0,
    ensures
        align_down_ens(val, align, ret) <==> (ret == val - val % align),
        val >= 0 <==> (val - val % align) >= 0,
        0 <= val % align < align,
{
    lemma_is_aligned_down_iff(val, align, ret);
    lemma_mod_bound(val, align);
}

pub proof fn lemma_align_up_properties(val: int, align: int, ret: int)
    requires
        align > 0,
        val % align == 0 ==> val == ret,
        val % align != 0 ==> ret == val + align - val % align,
    ensures
        val % align == 0 ==> val == ret,
        val % align != 0 ==> ret / align == val / align + 1,
        ret >= val,
        val > 0 ==> ret >= align,
        ret % align == 0,
{
    lemma_mod_bound(val, align);
    assert((val + align - val % align) / align == val / align + 1) by (nonlinear_arith)
        requires
            align > 0,
    ;
    assert((val % align == 0 && val > 0) ==> val >= align) by (nonlinear_arith);

    if val % align != 0 {
        assert(ret % align == 0) by (nonlinear_arith)
            requires
                ret == val + align - val % align,
                align > 0,
        ;
    }
}

} // verus!

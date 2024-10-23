// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
use super::*;

verus! {

broadcast use verify_proof::bits::lemma_bit_usize_shl_values;

#[verifier(inline)]
pub spec const VADDR_MAX_BITS: nat = 48;

#[verifier(inline)]
pub spec const VADDR_LOWER_MASK: InnerAddr = 0x7fff_ffff_ffff as InnerAddr;

#[verifier(inline)]
pub spec const VADDR_UPPER_MASK: InnerAddr = !VADDR_LOWER_MASK;

#[verifier(inline)]
pub spec const VADDR_RANGE_SIZE: InnerAddr = 0x1_0000_0000_0000u64 as InnerAddr;

#[verifier(inline)]
pub open spec fn check_sign_bit(addr: InnerAddr) -> bool {
    addr & (1usize << (VADDR_MAX_BITS - 1) as InnerAddr) == 1usize << (VADDR_MAX_BITS
        - 1) as InnerAddr
}

#[verifier(inline)]
pub open spec fn vaddr_lower_bits(addr: InnerAddr) -> InnerAddr {
    addr & VADDR_LOWER_MASK
}

#[verifier(inline)]
pub open spec fn vaddr_upper_bits(addr: InnerAddr) -> InnerAddr {
    addr & VADDR_UPPER_MASK
}

#[verifier(inline)]
pub open spec fn top_all_ones(addr: InnerAddr) -> bool {
    addr & VADDR_UPPER_MASK == VADDR_UPPER_MASK
}

#[verifier(inline)]
pub open spec fn top_all_zeros(addr: InnerAddr) -> bool {
    addr & VADDR_UPPER_MASK == 0
}

pub broadcast proof fn lemma_check_sign_bit(bits: InnerAddr)
    requires
        bits < VADDR_RANGE_SIZE,
    ensures
        #![trigger bits & 1usize << (VADDR_MAX_BITS - 1)]
        check_sign_bit(bits) == (bits > VADDR_LOWER_MASK),
{
    assert(check_sign_bit(bits) == (bits > VADDR_LOWER_MASK)) by (bit_vector)
        requires
            bits < VADDR_RANGE_SIZE,
    ;
}

pub broadcast proof fn lemma_upper_address_has_sign_bit(bits: InnerAddr)
    ensures
        #![trigger vaddr_upper_bits(bits)]
        top_all_ones(bits) ==> check_sign_bit(bits),
{
    assert(top_all_ones(bits) ==> check_sign_bit(bits)) by (bit_vector);
}

pub broadcast proof fn lemma_inner_addr_as_vaddr(bits: InnerAddr)
    ensures
        top_all_ones(bits) == (bits >= VADDR_UPPER_MASK),
        top_all_zeros(bits) == (bits <= VADDR_LOWER_MASK),
        top_all_zeros(bits) ==> #[trigger] vaddr_lower_bits(bits) == bits,
        top_all_ones(bits) ==> vaddr_upper_bits(bits) + vaddr_lower_bits(bits) == bits,
        VADDR_UPPER_MASK > VADDR_LOWER_MASK,
{
    broadcast use sign_extend_proof;
    broadcast use verify_proof::bits::lemma_bit_usize_shl_values;

    assert(top_all_ones(bits) == (bits >= VADDR_UPPER_MASK)) by (bit_vector);
    assert(top_all_zeros(bits) == (bits <= VADDR_LOWER_MASK)) by (bit_vector);
    assert(VADDR_UPPER_MASK > VADDR_LOWER_MASK);
}

pub closed spec fn pfn_spec(addr: usize) -> usize {
    addr / PAGE_SIZE
}

pub broadcast proof fn reveal_pfn(addr: usize)
    ensures
        #[trigger] pfn_spec(addr) == addr / PAGE_SIZE,
        pfn_spec(addr) == addr >> PAGE_SHIFT,
{
    broadcast use verify_proof::bits::lemma_bit_usize_shl_values;

    verify_proof::bits::lemma_bit_usize_shr_is_div(addr, PAGE_SHIFT);
}

pub open spec fn align_requires(align: InnerAddr) -> bool {
    &&& verify_proof::bits::is_pow_of_2(align as u64)
}

pub open spec fn _align_up_requires(bits: InnerAddr, align: InnerAddr) -> bool {
    &&& align_requires(align)
    &&& bits + (align - 1) <= InnerAddr::MAX
}

pub open spec fn align_up_requires(bits: InnerAddr, align: InnerAddr) -> bool {
    &&& _align_up_requires(bits, align)
}

pub open spec fn align_up_spec(val: InnerAddr, align: InnerAddr) -> InnerAddr {
    let r = val % align;
    &&& if r == 0 {
        val
    } else {
        (val - r + align) as InnerAddr
    }
}

pub open spec fn align_down_spec(val: InnerAddr, align: InnerAddr) -> int {
    val - val % align
}

broadcast group align_proof {
    verify_proof::bits::lemma_bit_usize_not_is_sub,
    verify_proof::bits::lemma_bit_usize_shl_values,
    verify_proof::bits::lemma_bit_u64_shl_values,
    vstd::bits::lemma_u64_pow2_no_overflow,
    verify_proof::bits::lemma_bit_usize_and_mask,
    verify_proof::bits::lemma_bit_usize_and_mask_is_mod,
}

pub broadcast proof fn proof_align_up(x: usize, align: usize)
    requires
        align_up_requires(x, align),
    ensures
        #[trigger] add(x, sub(align, 1)) & !sub(align, 1) == align_up_spec(x, align),
{
    broadcast use align_proof;

    let mask = (align - 1) as usize;
    let y = (x + mask) as usize;
    assert(y & !mask == sub(y, y & mask));

    if x % align == 0 {
        assert((x + (align - 1)) % (align as int) == align - 1) by (nonlinear_arith)
            requires
                x % align == 0,
                align > 0,
        ;
    } else {
        assert((x + (align - 1)) % (align as int) == (x % align - 1) as int) by (nonlinear_arith)
            requires
                x % align != 0,
                align > 0,
        ;
    }
}

pub broadcast proof fn lemma_align_down(x: usize, align: usize)
    requires
        align_requires(align),
    ensures
        #[trigger] (x & !((align - 1) as usize)) == align_down_spec(x, align),
{
    broadcast use align_proof;

    let mask: usize = sub(align, 1);
    assert(x == (x & !mask) + (x & mask));
}

} // verus!

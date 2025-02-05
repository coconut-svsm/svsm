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

} // verus!

// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
use super::*;

verus! {

use vstd::std_specs::ops::{spec_add_requires, spec_sub_requires};

broadcast use verify_proof::bits::lemma_bit_usize_shl_values;

#[verifier(inline)]
pub spec const VADDR_MAX_BITS: nat = 48;

#[verifier(inline)]
pub spec const VADDR_LOWER_MASK: InnerAddr = 0x7fff_ffff_ffff as InnerAddr;

#[verifier(inline)]
pub spec const VADDR_UPPER_MASK: InnerAddr = !VADDR_LOWER_MASK;

#[verifier(inline)]
pub spec const VADDR_RANGE_SIZE: InnerAddr = 0x1_0000_0000_0000u64 as InnerAddr;

pub trait AddressSpec: Copy + From<InnerAddr> + Into<
    InnerAddr,
> + PartialEq + Eq + PartialOrd + Ord {

}

impl<T> AddressSpec for T where
    T: Copy + From<InnerAddr> + Into<InnerAddr> + PartialEq + Eq + PartialOrd + Ord,
 {

}

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

#[verifier(inline)]
pub open spec fn align_requires(align: InnerAddr) -> bool {
    crate::utils::util::align_requires(align as u64)
}

pub open spec fn addr_align_up_requires<A: AddressSpec>(addr: A, align: InnerAddr) -> bool {
    &&& align_requires(align)
    &&& 0 < align
    &&& forall_into(addr, |iaddr: InnerAddr| iaddr + align - 1 <= InnerAddr::MAX)
}

pub broadcast proof fn lemma_align_up_requires<A: AddressSpec>(
    addr: A,
    align: InnerAddr,
    iaddr: InnerAddr,
)
    requires
        #[trigger] addr_align_up_requires(addr, align),
        A::into.ensures((addr,), iaddr),
    ensures
        #[trigger] crate::utils::util::align_up_requires((iaddr, align)),
{
    assert forall|one: usize|
        call_ensures(usize::from, (1u8,), one) implies #[trigger] spec_sub_requires(align, one) by {
        vstd::std_specs::ops::axiom_sub_requires(align, one);
    }

    assert forall|a: usize, y: usize| a + y <= usize::MAX implies #[trigger] spec_add_requires(
        a,
        y,
    ) by {
        vstd::std_specs::ops::axiom_add_requires(a, y);
    }
}

pub open spec fn addr_align_up_impl<A: AddressSpec>(addr: A, align: InnerAddr, ret: A) -> bool {
    &&& exists|iaddr: InnerAddr, iret: InnerAddr|
        {
            &&& A::into.ensures((addr,), iaddr)
            &&& #[trigger] crate::utils::util::align_up_ens((iaddr, align), iret)
            &&& A::from.ensures((iret,), ret)
        }
}

pub open spec fn addr_align_up_ens<A: AddressSpec>(addr: A, align: InnerAddr, ret: A) -> bool {
    exists|iaddr: InnerAddr, iret: InnerAddr|
        {
            &&& A::into.ensures((addr,), iaddr)
            &&& A::from.ensures((iret,), ret)
            &&& #[trigger] align_up_integer_ens(iaddr, align, iret)
        }
}

#[verifier(inline)]
pub open spec fn addr_align_down_ens<A: AddressSpec>(addr: A, align: InnerAddr, ret: A) -> bool {
    exists|iaddr: InnerAddr, iret: InnerAddr|
        {
            &&& #[trigger] A::into.ensures((addr,), iaddr)
            &&& align_down_integer_ens(iaddr, align, iret)
            &&& #[trigger] A::from.ensures((iret,), ret)
        }
}

pub open spec fn is_aligned_spec(val: InnerAddr, align: InnerAddr) -> bool {
    val % align == 0
}

#[verifier(inline)]
pub open spec fn addr_is_aligned_ens<A: AddressSpec>(addr: A, align: InnerAddr, ret: bool) -> bool {
    exists_into(addr, |inner| is_aligned_spec(inner, align) == ret)
}

pub broadcast proof fn lemma_align_up_ens<A: AddressSpec>(addr: A, align: InnerAddr, ret: A)
    requires
        addr_align_up_requires(addr, align),
        #[trigger] addr_align_up_impl(addr, align, ret),
    ensures
        addr_align_up_ens(addr, align, ret),
{
    let (iaddr, iret) = choose|iaddr: InnerAddr, iret: InnerAddr|
        {
            &&& A::into.ensures((addr,), iaddr)
            &&& crate::utils::util::align_up_ens((iaddr, align), iret)
            &&& A::from.ensures((iret,), ret)
        };
    crate::utils::util::proof_align_up(iaddr, align, iret);
}

} // verus!

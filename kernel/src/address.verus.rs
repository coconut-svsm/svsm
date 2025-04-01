// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
use crate::utils::util::{
    align_down_integer_ens, align_up_integer_ens, proof_align_down, proof_align_up,
};
use verify_external::convert::{exists_into, forall_into, FromSpec};
use vstd::std_specs::ops::{SpecAddRequires, SpecSubRequires};
verus! {

pub broadcast group sign_extend_proof {
    verify_proof::bits::lemma_bit_usize_not_is_sub,
    verify_proof::bits::lemma_bit_usize_shl_values,
    verify_proof::bits::lemma_bit_usize_or_mask,
    verify_proof::bits::lemma_bit_usize_and_mask,
    lemma_check_sign_bit,
}

pub broadcast group address_align_proof {
    crate::types::group_types_proof,
    verify_proof::bits::lemma_bit_usize_and_mask_is_mod,
    proof_align_up,
    proof_align_down,
    address_spec::lemma_align_up_requires,
    address_spec::lemma_align_up_ens,
}

broadcast group vaddr_impl_proof {
    sign_extend_proof,
    address_spec::lemma_inner_addr_as_vaddr,
    address_spec::lemma_upper_address_has_sign_bit,
    verify_proof::bits::lemma_bit_usize_and_mask_is_mod,
    address_align_proof,
    address_spec::reveal_pfn,
}

pub broadcast group group_addr_proofs {
    VirtAddr::property_canonical,
    VirtAddr::lemma_wf,
}

broadcast use vaddr_impl_proof;

/// Define a broadcast function and its related spec function calls in a inner
/// module to avoid cyclic self-reference
mod address_spec { include!("address_inner.verus.rs");  }

pub use address_spec::*;

// The inner address should be smaller than VADDR_RANGE_SIZE.
// Define a simple spec for sign_extend without using bit ops.
pub open spec fn sign_extend_spec(addr: InnerAddr) -> usize
    recommends
        addr < VADDR_RANGE_SIZE,
{
    if addr <= VADDR_LOWER_MASK {
        addr
    } else if addr < VADDR_RANGE_SIZE {
        (addr - VADDR_LOWER_MASK - 1 + VADDR_UPPER_MASK) as usize
    } else {
        sign_extend_impl(addr)
    }
}

// closed since external function should assume addr < VADDR_RANGE_SIZE.
pub closed spec fn sign_extend_impl(addr: InnerAddr) -> InnerAddr {
    if check_sign_bit(addr) {
        (vaddr_lower_bits(addr) + VADDR_UPPER_MASK) as InnerAddr
    } else {
        vaddr_lower_bits(addr)
    }
}

/// Ensures that ret is a new canonical address, throwing out bits 48..64.
#[verifier(inline)]
pub open spec fn sign_extend_ensures(addr: InnerAddr, ret: InnerAddr) -> bool {
    &&& ret == sign_extend_spec(addr)
    &&& vaddr_lower_bits(ret) == vaddr_lower_bits(addr)
}

pub open spec fn pt_idx_spec(addr: InnerAddr, l: usize) -> usize
    recommends
        l <= 5,
{
    let upper = match l {
        0usize => { addr >> 12 },
        1usize => { addr >> 21 },
        2usize => { addr >> 30 },
        3usize => { addr >> 39 },
        4usize => { addr >> 48 },
        5usize => { addr >> 57 },
        _ => { 0 },
    };
    upper % 512
}

pub open spec fn crosses_page_ens<T: Into<InnerAddr>>(addr: T, size: InnerAddr, ret: bool) -> bool {
    exists_into(addr, |inner| ret == (pfn_spec(inner) != pfn_spec((inner + size - 1) as InnerAddr)))
}

// Define a view (@) for VirtAddr
impl View for VirtAddr {
    type V = InnerAddr;

    closed spec fn view(&self) -> InnerAddr {
        self.0
    }
}

impl VirtAddr {
    /// Canonical form addresses run from 0 through 00007FFF'FFFFFFFF,
    /// and from FFFF8000'00000000 through FFFFFFFF'FFFFFFFF.
    #[verifier::type_invariant]
    pub open spec fn is_canonical(&self) -> bool {
        self.is_low() || self.is_high()
    }

    /// Property:
    /// A valid virtual address have a canonical form where the upper bits
    /// are either all zeroes or all ones.
    pub broadcast proof fn property_canonical(&self)
        ensures
            #[trigger] self.is_canonical() == (top_all_zeros(self@) || top_all_ones(self@)),
            self.is_canonical() == (*self === VirtAddr::from_spec(self.offset() as usize)),
            self.is_canonical() ==> self.offset() == if self.is_low() {
                self@ as int
            } else {
                self@ - 0xffff_0000_0000_0000
            },
    {
        broadcast use verify_proof::bits::lemma_bit_usize_not_is_sub;

        assert(VADDR_UPPER_MASK == 0xffff_8000_0000_0000);
    }

    pub broadcast proof fn lemma_wf(v: InnerAddr)
        ensures
            (#[trigger] VirtAddr::from_spec(v)).is_canonical(),
            0 <= v < VADDR_RANGE_SIZE ==> VirtAddr::from_spec(v).offset() == v,
    {
    }

    pub open spec fn is_low(&self) -> bool {
        self@ <= VADDR_LOWER_MASK
    }

    pub open spec fn is_high(&self) -> bool {
        self@ >= VADDR_UPPER_MASK
    }

    // Virtual memory offset indicating the distance from 0
    pub open spec fn offset(&self) -> int
        recommends
            self.is_canonical(),
    {
        if self.is_low() {
            self@ as int
        } else if self.is_high() {
            self@ - VADDR_UPPER_MASK + VADDR_LOWER_MASK + 1
        } else {
            -1
        }
    }

    pub open spec fn new_ensures(self, addr: InnerAddr) -> bool {
        sign_extend_ensures(addr, self@)
    }

    pub open spec fn pgtbl_idx_ensures(&self, l: usize, ret: usize) -> bool {
        ret == pt_idx_spec(self@, l)
    }

    pub open spec fn pfn_spec(&self) -> InnerAddr {
        pfn_spec(self@)
    }
}

impl SpecAddRequires<InnerAddr> for VirtAddr {
    /* Specifications for methods */
    // requires that adding offset will not cause not overflow.
    // If a low address, adding offset to it should not have set any bits in upper 16 bits.
    // If a high address, should not exceed usize::MAX
    open spec fn spec_add_requires(self, offset: InnerAddr) -> bool {
        self.offset() + offset < VADDR_RANGE_SIZE
    }
}

impl VirtAddr {
    pub open spec fn spec_add_ensures(self, offset: InnerAddr, ret: VirtAddr) -> bool {
        &&& self.offset() + offset == ret.offset()
        &&& ret === VirtAddr::from_spec((self@ + offset) as InnerAddr)
    }
}

// Get a new addr by subtracting an offset from an existing virtual address
impl SpecSubRequires<InnerAddr> for VirtAddr {
    open spec fn spec_sub_requires(self, rhs: InnerAddr) -> bool {
        self.offset() >= rhs
    }
}

// Compute the offset between two virtual addresses.
impl SpecSubRequires<VirtAddr> for VirtAddr {
    /// Do not assume they are both high/low addresses.
    open spec fn spec_sub_requires(self, rhs: VirtAddr) -> bool {
        self@ >= rhs@
    }
}

impl<T> FromSpec<*mut T> for VirtAddr {
    closed spec fn from_spec(v: *mut T) -> Self {
        VirtAddr(sign_extend_spec(v as InnerAddr))
    }
}

impl<T> FromSpec<*const T> for VirtAddr {
    closed spec fn from_spec(v: *const T) -> Self {
        VirtAddr(sign_extend_spec(v as InnerAddr))
    }
}

impl FromSpec<InnerAddr> for VirtAddr {
    closed spec fn from_spec(v: InnerAddr) -> Self {
        VirtAddr(sign_extend_spec(v))
    }
}

impl FromSpec<VirtAddr> for InnerAddr {
    open spec fn from_spec(v: VirtAddr) -> Self {
        v@
    }
}

impl FromSpec<VirtAddr> for u64 {
    open spec fn from_spec(v: VirtAddr) -> Self {
        v@ as u64
    }
}

// Define a view (@) for PhysAddr
impl View for PhysAddr {
    type V = InnerAddr;

    closed spec fn view(&self) -> InnerAddr {
        self.0
    }
}

impl FromSpec<InnerAddr> for PhysAddr {
    closed spec fn from_spec(v: InnerAddr) -> Self {
        PhysAddr(v)
    }
}

impl FromSpec<PhysAddr> for InnerAddr {
    closed spec fn from_spec(v: PhysAddr) -> Self {
        v.0
    }
}

impl SpecSubRequires<PhysAddr> for PhysAddr {
    open spec fn spec_sub_requires(self, rhs: PhysAddr) -> bool {
        self@ >= rhs@
    }
}

impl SpecSubRequires<InnerAddr> for PhysAddr {
    open spec fn spec_sub_requires(self, rhs: InnerAddr) -> bool {
        self@ >= rhs
    }
}

impl SpecAddRequires<InnerAddr> for PhysAddr {
    open spec fn spec_add_requires(self, offset: InnerAddr) -> bool {
        self@ + offset <= InnerAddr::MAX
    }
}

} // verus!

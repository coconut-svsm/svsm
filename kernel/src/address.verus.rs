// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
verus! {

use vstd::prelude::*;
use verify_external::convert::{FromSpec, from_spec, axiom_from_spec};

pub broadcast group sign_extend_proof {
    verify_proof::bits::lemma_bit_usize_not_is_sub,
    verify_proof::bits::lemma_bit_usize_shl_values,
    verify_proof::bits::lemma_bit_usize_or_mask,
    verify_proof::bits::lemma_bit_usize_and_mask,
    lemma_check_sign_bit,
}

pub broadcast group address_align_proof {
    crate::types::group_types_proof,
    axiom_from_spec,
    verify_proof::bits::lemma_bit_usize_and_mask_is_mod,
    address_spec::proof_align_up,
    address_spec::lemma_align_down,
}

broadcast group vaddr_impl_proof {
    sign_extend_proof,
    address_spec::lemma_inner_addr_as_vaddr,
    address_spec::lemma_upper_address_has_sign_bit,
    verify_proof::bits::lemma_bit_usize_and_mask_is_mod,
    address_align_proof,
    address_spec::reveal_pfn,
}

broadcast use vaddr_impl_proof;

/// Define a broadcast function and its related spec function calls in a inner
/// module to avoid cyclic self-reference
mod address_spec { include!("address_inner.verus.rs");  }

#[cfg(verus_keep_ghost)]
use address_spec::*;

pub open spec fn is_valid_addr(addr: InnerAddr) -> bool {
    addr <= VADDR_LOWER_MASK || addr >= VADDR_UPPER_MASK
}

#[verifier(inline)]
pub open spec fn sign_extend_spec(addr: InnerAddr) -> InnerAddr {
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
    &&& check_sign_bit(addr) ==> top_all_ones(ret)
    &&& !check_sign_bit(addr) ==> top_all_zeros(ret)
}

pub open spec fn addr_align_up<A>(addr: A, align: InnerAddr) -> A {
    from_spec(align_up_spec(from_spec(addr), align))
}

pub open spec fn addr_page_align_up<A>(addr: A) -> A {
    from_spec(align_up_spec(from_spec(addr), PAGE_SIZE))
}

pub open spec fn addr_page_align_down<A>(addr: A) -> A {
    from_spec(align_down_spec(from_spec(addr), PAGE_SIZE) as usize)
}

pub open spec fn is_aligned_spec(val: InnerAddr, align: InnerAddr) -> bool {
    val % align == 0
}

pub open spec fn addr_is_aligned_spec<A>(addr: A, align: InnerAddr) -> bool {
    is_aligned_spec(from_spec(addr), align)
}

pub open spec fn addr_is_page_aligned_spec<A>(addr: A) -> bool {
    is_aligned_spec(from_spec(addr), PAGE_SIZE)
}

pub open spec fn pt_idx_spec(addr: usize, l: usize) -> usize
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

pub open spec fn crosses_page_spec<T: Into<InnerAddr>>(addr: T, size: InnerAddr) -> bool {
    let inner = from_spec::<_, InnerAddr>(addr);
    pfn_spec(inner) != pfn_spec((inner + size - 1) as InnerAddr)
}

// Define a view (@) for VirtAddr
#[cfg(verus_keep_ghost)]
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
    proof fn property_canonical(&self)
        ensures
            self.is_canonical() == (top_all_zeros(self@) || top_all_ones(self@)),
    {
    }

    pub open spec fn is_low(&self) -> bool {
        self@ <= VADDR_LOWER_MASK
    }

    pub open spec fn is_high(&self) -> bool {
        self@ >= VADDR_UPPER_MASK
    }

    // Virtual memory offset indicating the distance from 0
    pub open spec fn offset(&self) -> int {
        if self.is_low() {
            self@ as int
        } else {
            self@ - VADDR_UPPER_MASK + VADDR_LOWER_MASK + 1
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

    /* Specifications for methods */
    // requires that adding offset will not cause not overflow.
    // If a low address, adding offset to it should not have set any bits in upper 16 bits.
    // If a high address, should not exceed usize::MAX
    pub open spec fn const_add_requires(&self, offset: usize) -> bool {
        self.offset() + offset < VADDR_RANGE_SIZE
    }

    pub open spec fn const_add_ensures(&self, offset: usize, ret: VirtAddr) -> bool {
        &&& self.offset() + offset == ret.offset()
    }

    // The current implementation assumes they are both high or low address.
    pub open spec fn sub_requires(&self, other: Self) -> bool {
        &&& self@ >= other@
        &&& other.is_high() || self.is_low()
    }

    // ret is the size of availabe virtual memory between the two addresses.
    pub open spec fn sub_ensures(&self, other: Self, ret: InnerAddr) -> bool {
        &&& ret == self.offset() - other.offset()
    }

    pub open spec fn sub_usize_requires(&self, other: usize) -> bool {
        self.offset() >= other
    }

    pub open spec fn sub_usize_ensures(&self, other: usize, ret: Self) -> bool {
        ret.offset() == self.offset() - other
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

} // verus!

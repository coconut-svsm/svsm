// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
verus! {

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

pub broadcast group sign_extend_proof {
    verismo::bits::lemma_bit_usize_not_is_sub,
    verismo::bits::lemma_bit_usize_shl_values,
    verismo::bits::lemma_bit_usize_or_mask,
    verismo::bits::lemma_bit_usize_and_mask,
}

broadcast group vaddr_properties {
    sign_extend_proof,
    lemma_inner_addr_as_vaddr,
}

broadcast use vaddr_properties;
/// Define a broadcast function and its related spec function calls in a inner
/// module to avoid cyclic self-reference

#[cfg(verus_keep_ghost)]
mod address_spec {
    use super::*;

    #[verifier(inline)]
    pub spec const VADDR_LOWER_MASK: InnerAddr = 0x7FFF_FFFF_FFFF as InnerAddr;

    #[verifier(inline)]
    pub spec const VADDR_UPPER_MASK: InnerAddr = !VADDR_LOWER_MASK;

    #[verifier(inline)]
    pub open spec fn check_signed(addr: InnerAddr) -> bool {
        addr & (1usize << 47) == 1usize << 47
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
    pub open spec fn vaddr_is_signed(addr: InnerAddr) -> bool {
        addr & VADDR_UPPER_MASK == VADDR_UPPER_MASK
    }

    #[verifier(inline)]
    pub open spec fn vaddr_is_valid(addr: InnerAddr) -> bool {
        addr & VADDR_UPPER_MASK == 0
    }

    pub broadcast proof fn lemma_inner_addr_as_vaddr(bits: InnerAddr)
        ensures
            vaddr_is_signed(bits) == (bits >= VADDR_UPPER_MASK),
            vaddr_is_valid(bits) == (bits <= VADDR_LOWER_MASK),
            vaddr_is_valid(bits) ==> #[trigger] vaddr_lower_bits(bits) == bits,
            vaddr_is_signed(bits) ==> vaddr_upper_bits(bits) + vaddr_lower_bits(bits) == bits,
            VADDR_UPPER_MASK > VADDR_LOWER_MASK,
            vaddr_is_signed(bits) ==> check_signed(bits),
    {
        broadcast use sign_extend_proof;

        assert(vaddr_is_signed(bits) == (bits >= VADDR_UPPER_MASK)) by (bit_vector);
        assert(vaddr_is_signed(bits) ==> check_signed(bits)) by (bit_vector);
        assert(vaddr_is_valid(bits) == (bits <= VADDR_LOWER_MASK)) by (bit_vector);
    }

}

#[cfg(verus_keep_ghost)]
use address_spec::*;

#[verifier(inline)]
pub open spec fn sign_extend_spec(addr: InnerAddr) -> InnerAddr {
    if check_signed(addr) {
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
    &&& check_signed(addr) ==> vaddr_is_signed(ret)
    &&& !check_signed(addr) ==> vaddr_is_valid(ret)
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
    /// A valid virtual address have a canonical form where the upper bits
    /// are either all zeroes or all ones
    #[verifier::type_invariant]
    pub closed spec fn is_canonical_vaddr(&self) -> bool {
        vaddr_is_valid(self@) || vaddr_is_signed(self@)
    }

    pub closed spec fn lower_bits(&self) -> InnerAddr {
        vaddr_lower_bits(self@)
    }

    pub closed spec fn valid_access(&self) -> bool {
        vaddr_is_valid(self@)
    }

    pub open spec fn new_ensures(self, addr: InnerAddr) -> bool {
        sign_extend_ensures(addr, self@)
    }

    /* Specifications for methods */
    // requires that adding offset will not cause not overflow.
    // If the address is valid, it should not exceed max valid address;
    // If the address is invalid, it will not exceed usize::max;
    pub open spec fn const_add_requires(&self, offset: usize) -> bool {
        &&& self.is_canonical_vaddr()
        &&& self@ + offset <= usize::MAX
        &&& self.valid_access() ==> (self@ + offset <= VADDR_LOWER_MASK || offset
            == VADDR_UPPER_MASK)
    }

    #[inline]
    pub open spec fn const_add_ensures(&self, offset: usize, ret: VirtAddr) -> bool {
        &&& ret.is_canonical_vaddr()
        &&& self.valid_access() ==> (ret@ == self@ + offset)
        &&& (offset != VADDR_UPPER_MASK) ==> ret.valid_access() == self.valid_access()
        &&& (offset == VADDR_UPPER_MASK) ==> !ret.valid_access()
    }

    pub open spec fn sub_requires(&self, other: Self) -> bool {
        &&& self.is_canonical_vaddr()
        &&& other.is_canonical_vaddr()
        &&& self@ >= other@
    }

    /// Substract a address from another should only make sense if they are both
    /// valid or invalid. If self is invalid while other is valid, the
    /// sign_extend(self@-other) can be confusing, which could be
    /// self@.lower_bits() - other.lower_bits() or self@ - other or 1usize<<47 +
    /// self@.lower_bits() - other.lower_bits()
    pub open spec fn sub_ensures(&self, other: Self, ret: InnerAddr) -> bool {
        let valid_sub = self.valid_access() == other.valid_access();
        &&& valid_sub ==> ret == self@ - other@
        &&& valid_sub ==> ret == sign_extend_spec((self@ - other@) as InnerAddr)
    }

    // For a valid address, other must be smaller than self.lower_bits()
    // Otherwise, this operation may accidentally make an invalid address valid.
    // We may convert an invalid to valid only when other == VADDR_UPPER_MASK.
    pub open spec fn sub_usize_requires(&self, other: usize) -> bool {
        &&& self.is_canonical_vaddr()
        &&& self@ >= other
        &&& (other <= self.lower_bits() || other == VADDR_UPPER_MASK)
    }

    pub open spec fn sub_usize_ensures(&self, other: usize, ret: Self) -> bool {
        ret.const_add_ensures(other, *self)
    }

    // Proves that a valid virtual address falls into [0, 0x00007FFFFFFFFFFF]
    broadcast proof fn lemma_range(vaddr: VirtAddr)
        requires
            #[trigger] vaddr.is_canonical_vaddr(),
        ensures
            vaddr.valid_access() == (vaddr@ <= VADDR_LOWER_MASK),
            !vaddr.valid_access() == (vaddr@ >= VADDR_UPPER_MASK),
            vaddr.valid_access() ==> vaddr@ == vaddr.lower_bits(),
            !vaddr.valid_access() ==> vaddr@ == vaddr.lower_bits() + VADDR_UPPER_MASK,
    {
    }
}

} // verus!
#[cfg(verus_keep_ghost)]
mod another_impl {
    use super::*;

    /// A different implementation of sign_extend2.
    /// The expected results is the same but impl and proof could be different.
    #[verus_verify]
    #[ensures(|ret: InnerAddr| [sign_extend_ensures(addr, ret)])]
    const fn sign_extend_different_impl(addr: InnerAddr) -> InnerAddr {
        let left_bits = InnerAddr::BITS as usize - SIGN_BIT - 1;
        proof! {
            assert(sign_extend_ensures(addr, ((addr << 16) as i64 >> 16) as InnerAddr))
            by (bit_vector);
        }
        ((addr << left_bits) as i64 >> left_bits) as InnerAddr
    }
}

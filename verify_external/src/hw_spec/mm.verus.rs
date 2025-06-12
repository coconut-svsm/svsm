// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// Defines trusted specifications related to address translation.
// Address and AddressMap implementations should implement those traits to demonstrate their correctness.
use vstd::prelude::*;

verus! {

pub trait SpecVAddrImpl {
    spec fn spec_int_addr(&self) -> Option<int>;

    /// To a set of integer adddresses
    spec fn region_to_dom(&self, size: nat) -> Set<int>;

    proof fn lemma_vaddr_region_len(&self, size: nat)
        requires
            self.spec_int_addr().is_some(),
            size > 0,
        ensures
            self.region_to_dom(size).finite(),
            self.region_to_dom(1).len() > 0 <==> self.region_to_dom(1).contains(
                self.spec_int_addr().unwrap(),
            ),
            self.region_to_dom(size).len() >= self.region_to_dom(1).len(),
    ;

    /// Unique when casting to int address
    proof fn lemma_unique(v1: &Self, v2: &Self)
        ensures
            (v1.spec_int_addr() == v2.spec_int_addr()) == (v1 === v2),
    ;

    /// If a size is valid, then smaller size must be valid
    proof fn lemma_valid_small_size(&self, size1: nat, size2: nat)
        requires
            size2 >= size1,
        ensures
            self.region_to_dom(size1).subset_of(self.region_to_dom(size2)),
    ;
}

// Define a trait describing the memory mapping groundtruth
pub trait SpecMemMapTr {
    type VAddr;

    type PAddr;

    spec fn to_paddr(&self, vaddr: Self::VAddr) -> Option<Self::PAddr>;

    spec fn to_vaddr(&self, paddr: Self::PAddr) -> Option<Self::VAddr>;

    open spec fn is_one_to_one_mapping(&self) -> bool {
        true
    }

    open spec fn to_vaddrs(&self, paddr: Self::PAddr) -> Set<Self::VAddr> {
        let s = self.to_vaddr(paddr);
        if s.is_some() {
            set!{s.unwrap()}
        } else {
            Set::empty()
        }
    }

    proof fn proof_one_to_one_mapping(&self, a: Self::PAddr)
        requires
            self.is_one_to_one_mapping(),
        ensures
            self.to_vaddrs(a).len() <= 1,
            self.to_vaddr(a).is_some() ==> self.to_paddr(self.to_vaddr(a).unwrap()).is_some(),
    ;

    proof fn proof_one_to_one_mapping_vaddr(&self, a: Self::VAddr)
        requires
            self.is_one_to_one_mapping(),
        ensures
            self.to_paddr(a).is_some() ==> self.to_vaddr(self.to_paddr(a).unwrap()) == Some(a),
    ;

    proof fn proof_correct_mapping_vaddr(&self, a: Self::VAddr)
        requires
            self.to_paddr(a).is_some(),
        ensures
            self.to_vaddrs(self.to_paddr(a).unwrap()).contains(a),
    ;

    proof fn proof_correct_mapping_paddr(&self, a: Self::PAddr)
        ensures
            (self.to_vaddrs(a).len() > 0) == self.to_vaddr(a).is_some(),
            self.to_vaddr(a).is_some() ==> self.to_vaddrs(a).contains(self.to_vaddr(a).unwrap()),
            self.to_vaddrs(a).len() > 0 ==> self.to_vaddrs(a).contains(self.to_vaddr(a).unwrap()),
    ;

    proof fn proof_correct_mapping_addrs(&self, a: Self::PAddr, vaddr: Self::VAddr)
        requires
            self.to_vaddrs(a).contains(vaddr),
        ensures
            self.to_paddr(vaddr) === Some(a),
    ;
}

} // verus!

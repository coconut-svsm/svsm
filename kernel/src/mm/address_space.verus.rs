// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// This module defines specification helper functions to verify the correct use of memory.
//
// Trusted Assumptions:
// - hw_spec::SpecMemMapTr is correct
// Proofs:
// - FixedAddressMappingRange is viewed as LinearMap
// - LinearMap satisfies all properties in hw_spec::SpecMemMapTr
use verify_external::convert::FromSpec;
use verify_external::hw_spec::SpecMemMapTr;

use crate::address::VADDR_RANGE_SIZE;

mod address_space_spec {
    use super::*;
    include!("address_space_spec.verus.rs");
}

pub use address_space_spec::LinearMap;

verus! {

impl FixedAddressMappingRange {
    pub closed spec fn view(&self) -> LinearMap {
        LinearMap::spec_new(self.virt_start, self.virt_end, self.phys_start)
    }

    pub open spec fn req_new(
        virt_start: VirtAddr,
        virt_end: VirtAddr,
        phys_start: PhysAddr,
    ) -> bool {
        &&& virt_start@ % crate::types::PAGE_SIZE == phys_start@ % crate::types::PAGE_SIZE
        &&& virt_end@ > virt_start@
        &&& virt_end@ - virt_start@ + phys_start@ < usize::MAX + 1
    }

    #[verifier::type_invariant]
    pub closed spec fn wf(&self) -> bool {
        &&& Self::req_new(self.virt_start, self.virt_end, self.phys_start)
    }

    pub proof fn use_type_invariant(tracked &self)
        ensures
            self@.wf(),
            self.wf(),
    {
        broadcast use verify_proof::bits::lemma_bit_usize_shl_values;

        use_type_invariant(self);
        use_type_invariant(self.virt_start);
        use_type_invariant(self.virt_end);
        assert(crate::address::VADDR_UPPER_MASK == 0xffff_8000_0000_0000) by (compute);
        reveal(LinearMap::wf_virt_phy_page);
    }
}

} // verus!

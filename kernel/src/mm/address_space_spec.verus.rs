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
// - LinearMap satisfy all properties in hw_spec::SpecMemMapTr
verus! {

#[allow(missing_debug_implementations)]
pub ghost struct LinearMap {
    pub virt_start: VirtAddr,
    pub phys_start: int,
    pub size: nat,
}

impl LinearMap {
    pub open spec fn is_identity_map(&self) -> bool {
        self.virt_start@ == VirtAddr::from_spec(self.phys_start as usize)@
    }

    pub open spec fn spec_phys_to_virt(&self, paddr: int) -> Option<VirtAddr> {
        let offset = paddr - self.phys_start;
        if 0 <= offset < self.size && (self.virt_start.offset() + offset < VADDR_RANGE_SIZE) {
            let inner = (self.virt_start.offset() + offset) as usize;
            Some(VirtAddr::from_spec(inner))
        } else {
            None
        }
    }

    pub open spec fn spec_virt_to_phys(&self, vaddr: VirtAddr) -> Option<int> {
        let offset = vaddr.offset() - self.virt_start.offset();
        if 0 <= offset < self.size && (self.virt_start.offset() + offset < VADDR_RANGE_SIZE)
            && self.virt_start.is_canonical() && vaddr.is_canonical() {
            Some(self.phys_start + offset)
        } else {
            None
        }
    }

    pub open spec fn spec_new(
        virt_start: VirtAddr,
        virt_end: VirtAddr,
        phys_start: PhysAddr,
    ) -> LinearMap {
        LinearMap {
            virt_start: virt_start,
            phys_start: phys_start@ as int,
            size: (virt_end.offset() - virt_start.offset()) as nat,
        }
    }

    #[verifier(opaque)]
    pub open spec fn wf_virt_phy_page(&self) -> bool {
        self.virt_start@ % crate::types::PAGE_SIZE == self.phys_start
            % crate::types::PAGE_SIZE as int
    }

    pub open spec fn wf(&self) -> bool {
        &&& self.wf_virt_phy_page()
        &&& self.virt_start.is_canonical()
        &&& self.virt_start.offset() + self.size <= crate::address::VADDR_RANGE_SIZE
        &&& self.phys_start + self.size <= usize::MAX + 1
    }

    pub open spec fn try_get_virt(&self, pfn: usize) -> Option<VirtAddr> {
        let phy = self.phys_start + pfn * crate::types::PAGE_SIZE;
        self.to_vaddr(phy)
    }

    pub proof fn lemma_get_virt(&self, pfn: usize) -> (ret: VirtAddr)
        requires
            self.wf(),
            pfn < self.size / crate::types::PAGE_SIZE as nat,
        ensures
            ret == self.try_get_virt(pfn).unwrap(),
            self.try_get_virt(pfn).is_some(),
            ret.is_canonical(),
            ret.offset() == self.virt_start.offset() + (pfn * crate::types::PAGE_SIZE),
            ret == VirtAddr::from_spec(
                (self.virt_start.offset() + (pfn * crate::types::PAGE_SIZE)) as usize,
            ),
    {
        broadcast use crate::types::lemma_page_size;

        reveal(<LinearMap as SpecMemMapTr>::to_vaddr);
        VirtAddr::lemma_wf((self.virt_start.offset() + (pfn * crate::types::PAGE_SIZE)) as usize);
        self.try_get_virt(pfn).unwrap()
    }

    pub broadcast proof fn lemma_get_paddr(&self, vaddr: VirtAddr)
        requires
            self.wf(),
            vaddr.is_canonical(),
            self.virt_start.offset() <= vaddr.offset() < self.virt_start.offset() + self.size,
        ensures
            (#[trigger] self.to_paddr(vaddr)).is_some(),
            self.phys_start <= self.to_paddr(vaddr).unwrap() <= self.phys_start + self.size,
    {
        reveal(<LinearMap as SpecMemMapTr>::to_paddr);
    }

    pub open spec fn get_pfn(&self, vaddr: VirtAddr) -> Option<usize> {
        if let Some(paddr) = self.to_paddr(vaddr) {
            Some(((paddr - self.phys_start) / crate::types::PAGE_SIZE as int) as usize)
        } else {
            None
        }
    }

    pub broadcast proof fn lemma_get_pfn_get_virt(&self, vaddr: VirtAddr)
        requires
            self.wf(),
            vaddr.is_canonical(),
            self.virt_start.offset() <= vaddr.offset() < self.virt_start.offset() + self.size,
        ensures
            (self.virt_start@ % 0x1000 == 0) && (vaddr@ % 0x1000 == 0) ==> (#[trigger] self.get_pfn(
                vaddr,
            )).is_some() ==> self.try_get_virt(self.get_pfn(vaddr).unwrap()) == Some(vaddr),
            (#[trigger] self.get_pfn(vaddr)).is_some() ==> self.try_get_virt(
                self.get_pfn(vaddr).unwrap(),
            ).is_some(),
    {
        broadcast use crate::types::lemma_page_size;

        reveal(<LinearMap as SpecMemMapTr>::to_paddr);
        reveal(<LinearMap as SpecMemMapTr>::to_vaddr);
        if vaddr@ % 0x1000 == 0 && self.virt_start@ % 0x1000 == 0 {
            assert(vaddr.offset() - self.virt_start.offset() == (vaddr.offset()
                - self.virt_start.offset()) / 0x1000 * 0x1000) by {
                vaddr.property_canonical();
                self.virt_start.property_canonical();
                assert(self.virt_start.offset() % 0x1000 == 0);
                broadcast use verify_proof::bits::lemma_bit_usize_not_is_sub;

            }
        }
        self.proof_one_to_one_mapping_vaddr(vaddr);
    }
}

impl SpecMemMapTr for LinearMap {
    type VAddr = VirtAddr;

    type PAddr = int;

    open spec fn to_vaddrs(&self, paddr: int) -> Set<VirtAddr> {
        let s = self.to_vaddr(paddr);
        if s.is_some() {
            set!{s.unwrap()}
        } else {
            Set::empty()
        }
    }

    #[verifier(opaque)]
    open spec fn to_vaddr(&self, paddr: int) -> Option<VirtAddr> {
        if self.virt_start.is_canonical() {
            self.spec_phys_to_virt(paddr)
        } else {
            None
        }
    }

    #[verifier(opaque)]
    open spec fn to_paddr(&self, vaddr: VirtAddr) -> Option<int> {
        if self.virt_start.is_canonical() && vaddr.is_canonical() {
            self.spec_virt_to_phys(vaddr)
        } else {
            None
        }
    }

    open spec fn is_one_to_one_mapping(&self) -> bool {
        true
    }

    proof fn proof_one_to_one_mapping(&self, paddr: Self::PAddr) {
        reveal(<LinearMap as SpecMemMapTr>::to_vaddr);
        reveal(<LinearMap as SpecMemMapTr>::to_paddr);
        let offset = paddr - self.phys_start;
        let inner = (self.virt_start.offset() + offset) as usize;
        VirtAddr::lemma_wf(inner);
    }

    proof fn proof_one_to_one_mapping_vaddr(&self, vaddr: Self::VAddr) {
        reveal(<LinearMap as SpecMemMapTr>::to_vaddr);
        reveal(<LinearMap as SpecMemMapTr>::to_paddr);
        if self.to_paddr(vaddr).is_some() {
            self.proof_correct_mapping_vaddr(vaddr);
        }
    }

    proof fn proof_correct_mapping_vaddr(&self, addr: Self::VAddr) {
        reveal(<LinearMap as SpecMemMapTr>::to_vaddr);
        reveal(<LinearMap as SpecMemMapTr>::to_paddr);
        let offset = self.to_paddr(addr).unwrap() - self.phys_start;
        let inner = (self.virt_start.offset() + offset) as usize;
        addr.property_canonical();
    }

    proof fn proof_correct_mapping_paddr(&self, paddr: Self::PAddr) {
        reveal(<LinearMap as SpecMemMapTr>::to_vaddr);
        reveal(<LinearMap as SpecMemMapTr>::to_vaddrs);
        reveal(<LinearMap as SpecMemMapTr>::to_paddr);
        assert(set!{self.to_vaddr(paddr).unwrap()}.contains(self.to_vaddr(paddr).unwrap()));
        if self.to_vaddr(paddr).is_some() {
            assert(self.to_vaddrs(paddr).contains(self.to_vaddr(paddr).unwrap()));
        }
        assert(Set::<VirtAddr>::empty().is_empty());
        VirtAddr::lemma_wf((self.virt_start.offset() + paddr - self.phys_start) as usize);
    }

    proof fn proof_correct_mapping_addrs(&self, paddr: Self::PAddr, vaddr: Self::VAddr) {
        reveal(<LinearMap as SpecMemMapTr>::to_vaddr);
        reveal(<LinearMap as SpecMemMapTr>::to_vaddrs);
        reveal(<LinearMap as SpecMemMapTr>::to_paddr);
        VirtAddr::lemma_wf((self.virt_start.offset() + paddr - self.phys_start) as usize);
    }
}

} // verus!

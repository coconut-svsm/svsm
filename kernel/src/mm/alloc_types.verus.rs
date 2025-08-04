// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// Proves the encode/decode functions for PageInfo used in alloc.rs.
use vstd::simple_pptr::MemContents;
verus! {

// prove the size of PageStorageType
global size_of PageStorageType == 8;

spec fn spec_page_storage_type(mem: MemContents<PageStorageType>) -> Option<PageStorageType> {
    if mem.is_init() {
        Some(mem.value())
    } else {
        None
    }
}

#[verifier(opaque)]
spec fn spec_page_info(mem: MemContents<PageStorageType>) -> Option<PageInfo> {
    let mem = spec_page_storage_type(mem);
    if mem.is_some() {
        PageInfo::spec_decode(mem.unwrap())
    } else {
        None
    }
}

spec fn spec_free_info(perm: MemContents<PageStorageType>) -> Option<FreeInfo> {
    let p_info = spec_page_info(perm);
    if p_info.is_some() {
        let pi = p_info.unwrap();
        pi.spec_get_free()
    } else {
        None
    }
}

impl PageType {
    spec fn spec_is_deallocatable(&self) -> bool {
        matches!(self, PageType::Allocated | PageType::SlabPage | PageType::File)
    }
}

impl PageInfo {
    spec fn spec_order(&self) -> usize {
        match *self {
            PageInfo::Compound(CompoundInfo { order }) => order,
            PageInfo::Allocated(AllocatedInfo { order }) => order,
            PageInfo::Free(FreeInfo { order, .. }) => order,
            _ => 0,
        }
    }

    spec fn spec_type(&self) -> PageType {
        match *self {
            PageInfo::Free(_) => PageType::Free,
            PageInfo::Allocated(_) => PageType::Allocated,
            PageInfo::Slab(_) => PageType::SlabPage,
            PageInfo::Compound(_) => PageType::Compound,
            PageInfo::File(_) => PageType::File,
            PageInfo::Reserved(_) => PageType::Reserved,
        }
    }

    spec fn spec_get_free(&self) -> Option<FreeInfo> {
        match *self {
            PageInfo::Free(info) => { Some(info) },
            _ => { None },
        }
    }
}

// Prove the encode/decode functions.
// The implementation must satisfying the proof.
trait SpecDecoderProof<T>: core::marker::Sized {
    spec fn spec_decode(mem: T) -> Option<Self> {
        if exists|x: Self| #[trigger] x.spec_encode() === Some(mem) {
            Some(choose|x: Self| #[trigger] x.spec_encode() === Some(mem))
        } else {
            None
        }
    }

    spec fn spec_encode(&self) -> Option<T>;

    proof fn lemma_encode_decode(&self)
        requires
            self.spec_encode().is_some(),
        ensures
            Self::spec_decode(self.spec_encode().unwrap()) === Some(*self),
    ;

    proof fn proof_encode_decode(&self)
        ensures
            self.spec_encode().is_some() ==> Self::spec_decode(self.spec_encode().unwrap())
                === Some(*self),
    {
        if self.spec_encode().is_some() {
            self.lemma_encode_decode();
        }
    }
}

impl AllocatedInfo {
    #[verifier::type_invariant]
    spec fn inv(&self) -> bool {
        self.order < MAX_ORDER
    }
}

impl CompoundInfo {
    #[verifier::type_invariant]
    spec fn inv(&self) -> bool {
        self.order < MAX_ORDER
    }
}

impl FileInfo {
    #[verifier::type_invariant]
    spec fn inv(&self) -> bool {
        self.ref_count < (1u64 << (u64::BITS - PageStorageType::TYPE_SHIFT) as u64)
    }
}

impl SlabPageInfo {
    #[verifier::type_invariant]
    spec fn inv(&self) -> bool {
        self.item_size <= PageStorageType::SLAB_MASK
    }
}

impl FreeInfo {
    #[verifier::type_invariant]
    spec fn inv(&self) -> bool {
        &&& self.next_page < MAX_PAGE_COUNT
        &&& self.order < MAX_ORDER
    }
}

impl PageInfo {
    spec fn inv(&self) -> bool {
        match self {
            PageInfo::Free(info) => info.inv(),
            PageInfo::Allocated(info) => info.inv(),
            PageInfo::Slab(info) => info.inv(),
            PageInfo::Compound(info) => info.inv(),
            PageInfo::File(info) => info.inv(),
            PageInfo::Reserved(info) => true,
        }
    }

    proof fn use_type_invariant(tracked &self)
        ensures
            self.inv(),
    {
        match self {
            PageInfo::Free(info) => {
                use_type_invariant(info);
            },
            PageInfo::Allocated(info) => {
                use_type_invariant(info);
            },
            PageInfo::Slab(info) => {
                use_type_invariant(info);
            },
            PageInfo::Compound(info) => {
                use_type_invariant(info);
            },
            PageInfo::File(info) => {
                use_type_invariant(info);
            },
            _ => {},
        }
    }
}

impl PageStorageType {
    spec fn wf(&self) -> bool {
        let mem_type = PageType::spec_decode(*self);
        if mem_type.is_none() {
            false
        } else {
            match mem_type.unwrap() {
                (PageType::Free
                | PageType::Allocated
                | PageType::Compound) => self.spec_decode_order() < MAX_ORDER,
                _ => true,
            }
        }
    }
}

impl SpecDecoderProof<PageStorageType> for FreeInfo {
    spec fn spec_decode(mem: PageStorageType) -> Option<Self> {
        Some(Self::spec_decode_impl(mem))
    }

    spec fn spec_encode(&self) -> Option<PageStorageType> {
        if self.inv() {
            Some(self.spec_encode_impl())
        } else {
            None
        }
    }

    proof fn lemma_encode_decode(&self)
        ensures
            PageType::spec_decode(self.spec_encode().unwrap()) === Some(PageType::Free),
    {
        let info = *self;
        let order = info.order as u64;
        let next_page = info.next_page as u64;
        let mem = PageType::Free as u64;
        let bit1 = PageStorageType::TYPE_SHIFT;
        let bit2 = (PageStorageType::NEXT_SHIFT - PageStorageType::TYPE_SHIFT) as u64;
        let bit3 = (u64::BITS - PageStorageType::NEXT_SHIFT) as u64;
        lemma_u64_and_bitmask_lower(order, bit2);
        let ret = mem | (order << bit1) | (next_page << (bit1 + bit2)) as u64;
        lemma_bit_u64_extract_fields2(mem, order, bit1, bit2);
        lemma_bit_u64_extract_fields2(
            mem | (order << bit1),
            next_page,
            PageStorageType::NEXT_SHIFT,
            (u64::BITS - PageStorageType::NEXT_SHIFT) as u64,
        );
        lemma_bit_u64_extract_mid_field(ret, bit1, bit2);
    }
}

impl SpecDecoderProof<PageStorageType> for AllocatedInfo {
    spec fn spec_decode(mem: PageStorageType) -> Option<Self> {
        Some(Self::spec_decode_impl(mem))
    }

    spec fn spec_encode(&self) -> Option<PageStorageType> {
        if self.inv() {
            Some(self.spec_encode_impl())
        } else {
            None
        }
    }

    proof fn lemma_encode_decode(&self)
        ensures
            PageType::spec_decode(self.spec_encode().unwrap()) === Some(PageType::Allocated),
    {
        PageType::Allocated.lemma_encode_decode();
        lemma_bit_u64_extract_fields2(
            PageType::Allocated as u64,
            self.order as u64,
            PageStorageType::TYPE_SHIFT,
            (PageStorageType::NEXT_SHIFT - PageStorageType::TYPE_SHIFT) as u64,
        );
    }
}

impl SpecDecoderProof<PageStorageType> for SlabPageInfo {
    spec fn spec_decode(mem: PageStorageType) -> Option<Self> {
        Some(Self::spec_decode_impl(mem))
    }

    spec fn spec_encode(&self) -> Option<PageStorageType> {
        if self.inv() {
            Some(self.spec_encode_impl())
        } else {
            None
        }
    }

    proof fn lemma_encode_decode(&self)
        ensures
            PageType::spec_decode(self.spec_encode().unwrap()) === Some(PageType::SlabPage),
    {
        PageType::SlabPage.lemma_encode_decode();
        assert(self.item_size <= (1u64 << 16)) by (compute);
        lemma_bit_u64_extract_fields2(
            PageType::SlabPage as u64,
            self.item_size as u64,
            PageStorageType::TYPE_SHIFT,
            16,
        );
    }
}

impl SpecDecoderProof<PageStorageType> for CompoundInfo {
    spec fn spec_decode(mem: PageStorageType) -> Option<Self> {
        Some(Self::spec_decode_impl(mem))
    }

    spec fn spec_encode(&self) -> Option<PageStorageType> {
        if self.inv() {
            Some(self.spec_encode_impl())
        } else {
            None
        }
    }

    proof fn lemma_encode_decode(&self)
        ensures
            PageType::spec_decode(self.spec_encode().unwrap()) === Some(PageType::Compound),
    {
        PageType::Compound.lemma_encode_decode();
        lemma_bit_u64_extract_fields2(
            PageType::Compound as u64,
            self.order as u64,
            PageStorageType::TYPE_SHIFT,
            8,
        );
    }
}

impl SpecDecoderProof<PageStorageType> for FileInfo {
    spec fn spec_decode(mem: PageStorageType) -> Option<Self> {
        Some(Self::spec_decode_impl(mem))
    }

    spec fn spec_encode(&self) -> Option<PageStorageType> {
        if self.inv() {
            Some(self.spec_encode_impl())
        } else {
            None
        }
    }

    proof fn lemma_encode_decode(&self)
        ensures
            PageType::spec_decode(self.spec_encode().unwrap()) === Some(PageType::File),
    {
        PageType::File.lemma_encode_decode();
        let ref_count = self.ref_count as u64;
        let tbits = PageStorageType::TYPE_SHIFT;
        let bits = (u64::BITS - PageStorageType::TYPE_SHIFT) as u64;
        let mem = self.spec_encode().unwrap().0;
        lemma_bit_u64_extract_fields2(
            PageType::File as u64,
            ref_count,
            PageStorageType::TYPE_SHIFT,
            bits,
        );
    }
}

impl SpecDecoderProof<PageStorageType> for ReservedInfo {
    spec fn spec_encode(&self) -> Option<PageStorageType> {
        Some(self.spec_encode_impl())
    }

    spec fn spec_decode(mem: PageStorageType) -> Option<Self> {
        Some(Self::spec_decode_impl(mem))
    }

    proof fn lemma_encode_decode(&self)
        ensures
            PageType::spec_decode(self.spec_encode().unwrap()) === Some(PageType::Reserved),
    {
        PageType::Reserved.lemma_encode_decode();
        lemma_u64_and_bitmask_lower(PageType::Reserved as u64, PageStorageType::TYPE_SHIFT);
    }
}

impl PageType {
    spec fn spec_try_from(val: u64) -> Option<Self> {
        match val {
            v if v == Self::Free as u64 => Some(Self::Free),
            v if v == Self::Allocated as u64 => Some(Self::Allocated),
            v if v == Self::SlabPage as u64 => Some(Self::SlabPage),
            v if v == Self::Compound as u64 => Some(Self::Compound),
            v if v == Self::File as u64 => Some(Self::File),
            v if v == Self::Reserved as u64 => Some(Self::Reserved),
            _ => None,
        }
    }

    pub closed spec fn ens_try_from(val: u64, ret: Result<Self, AllocError>) -> bool {
        &&& ret.is_ok() == PageType::spec_try_from(val).is_some()
        &&& ret.is_ok() ==> ret.unwrap() == PageType::spec_try_from(val).unwrap()
    }
}

impl SpecDecoderProof<PageStorageType> for PageType {
    spec fn spec_encode(&self) -> Option<PageStorageType> {
        Some(PageStorageType(*self as u64))
    }

    spec fn spec_decode(mem: PageStorageType) -> Option<Self> {
        let val = mem.0 & PageStorageType::TYPE_MASK;
        PageType::spec_try_from(val)
    }

    proof fn lemma_encode_decode(&self) {
        let mem = self.spec_encode().unwrap();
        let val = mem.0;
        assert(val & 0xf == val) by (bit_vector)
            requires
                val < 16,
        ;
        assert(PageType::spec_decode(mem) == Some(*self));
    }
}

impl SpecDecoderProof<PageStorageType> for PageInfo {
    closed spec fn spec_encode(&self) -> Option<PageStorageType> {
        match self {
            Self::Free(fi) => fi.spec_encode(),
            Self::Allocated(ai) => ai.spec_encode(),
            Self::Slab(si) => si.spec_encode(),
            Self::Compound(ci) => ci.spec_encode(),
            Self::File(fi) => fi.spec_encode(),
            Self::Reserved(ri) => ri.spec_encode(),
        }
    }

    spec fn spec_decode(v: PageStorageType) -> Option<PageInfo> {
        let mem_type = PageType::spec_decode(v);
        if mem_type.is_none() {
            None
        } else {
            match mem_type.unwrap() {
                PageType::Free => Some(PageInfo::Free(FreeInfo::spec_decode_impl(v))),
                PageType::Allocated => Some(
                    PageInfo::Allocated(AllocatedInfo::spec_decode_impl(v)),
                ),
                PageType::SlabPage => Some(PageInfo::Slab(SlabPageInfo::spec_decode_impl(v))),
                PageType::Compound => Some(PageInfo::Compound(CompoundInfo::spec_decode_impl(v))),
                PageType::File => Some(PageInfo::File(FileInfo::spec_decode_impl(v))),
                PageType::Reserved => Some(PageInfo::Reserved(ReservedInfo::spec_decode_impl(v))),
            }
        }
    }

    proof fn lemma_encode_decode(&self) {
        let info = *self;
        let mem = info.spec_encode().unwrap();
        let memval = mem.0;
        match info {
            PageInfo::Free(finfo) => {
                finfo.lemma_encode_decode();
            },
            PageInfo::Reserved(rinfo) => {
                rinfo.lemma_encode_decode();
            },
            PageInfo::Allocated(ainfo) => {
                ainfo.lemma_encode_decode();
            },
            PageInfo::Slab(sinfo) => {
                sinfo.lemma_encode_decode();
            },
            PageInfo::Compound(cinfo) => {
                cinfo.lemma_encode_decode();
            },
            PageInfo::File(finfo) => {
                finfo.lemma_encode_decode();
            },
        }
    }
}

} // verus!

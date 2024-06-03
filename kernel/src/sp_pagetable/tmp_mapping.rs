use crate::cpu::percpu::this_cpu_mut;
use crate::cpu::tlb::flush_address_sync;
use crate::mm::pagetable::PTEntryFlags;
use crate::mm::virtualrange::{
    virt_alloc_range_2m, virt_alloc_range_4k, virt_free_range_2m, virt_free_range_4k,
};
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::utils::MemoryRegion;
use crate::error::SvsmError;
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
#[derive(Debug, Clone, Copy)]
pub struct TemporaryPageMapping {
    mapping: MemoryRegion<VirtAddr>,
    phy_add: PhysAddr,
}

impl Default for TemporaryPageMapping {
    fn default() -> Self {
        TemporaryPageMapping {
            mapping: MemoryRegion::new(VirtAddr::from(0u64),0),
            phy_add: PhysAddr::from(0u64),
        }
    }
}

impl TemporaryPageMapping {
    pub fn create(
        paddr_start: PhysAddr,
        paddr_end: PhysAddr,
        alignment: usize,
    ) -> Result<Self, SvsmError> {
        let align_mask = (PAGE_SIZE << alignment) - 1;
        let size = paddr_end - paddr_start;
        assert!((size & align_mask) == 0);
        assert!((paddr_start.bits() & align_mask) == 0);
        assert!((paddr_end.bits() & align_mask) == 0);

        let flags = PTEntryFlags::data();
        let huge = ((paddr_start.bits() & (PAGE_SIZE_2M - 1)) == 0)
            && ((paddr_end.bits() & (PAGE_SIZE_2M - 1)) == 0);
        let vaddr = if huge {
            let vaddr = virt_alloc_range_2m(size, 0)?;
            //let reg = MemoryRegion::<VirtAddr>::new(vaddr, size);
            if let Err(e) =
                this_cpu_mut()
                    .get_pgtable()
                    .map_region_2m(vaddr, paddr_start, flags)
            {
                virt_free_range_2m(vaddr);
                return Err(e);
            }
            vaddr
        } else {
            let vaddr = virt_alloc_range_4k(size, 0)?;
            //let reg = MemoryRegion::<VirtAddr>::new(vaddr, size);
            if let Err(e) =
                this_cpu_mut()
                    .get_pgtable()
                    .map_region_4k(vaddr, paddr_start, flags)
            {
                virt_free_range_4k(vaddr);
                return Err(e);
            }
            vaddr
        };

        //let raw_mapping = MemoryRegion::<VirtAddr>::new(vaddr, size);

        Ok(TemporaryPageMapping {
            mapping: vaddr,
            phy_add: paddr_start,
        })
    }

    pub fn create_4k(paddr: PhysAddr) -> Result<Self, SvsmError> {
        Self::create(paddr, paddr + PAGE_SIZE, 0)
    }
    pub fn create_4k_clear12(paddr: PhysAddr) -> Result<Self, SvsmError> {
        let paddr = PhysAddr::from(paddr.bits() as u64 & 0x000f_ffff_ffff_f000u64);
        Self::create(paddr, paddr + PAGE_SIZE, 0)
    }

    pub fn virt_addr(&self) -> VirtAddr {
        self.mapping.start()
    }

    pub fn remove(&self) {
        let start = self.mapping.start();
        let end = self.mapping.end();
        //let size = self.mapping.len();

        let reg = MemoryRegion::<VirtAddr>::from_addresses(start, end);

        this_cpu_mut().get_pgtable().unmap_region_4k(reg);
        virt_free_range_4k(reg);
        flush_address_sync(start);
    }
    pub fn delete(&self) {
        if u64::from(self.phy_add) == 0 {
            return;
        }
        self.remove();
    }
}
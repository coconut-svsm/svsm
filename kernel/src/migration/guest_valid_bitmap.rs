use crate::mm::PageBox;
use crate::error::SvsmError;
use crate::address::PhysAddr;
use crate::utils::memory_region::MemoryRegion;

use crate::locking::SpinLock;
use crate::utils::valid_bitmap::{ValidBitmap,bitmap_elems};

// FIXME: Defines number of continuous regions, that can be tracked. In future,
// the number of regions should be decided dynamically at runtime.
const REGIONS_COUNT: usize = 2;

#[derive(Debug)]
pub struct GuestValidBitmap {
    bitmap: [SpinLock<Option<ValidBitmap>>;REGIONS_COUNT]
}


impl GuestValidBitmap {
    pub const fn new() -> Self{
        GuestValidBitmap {
            bitmap: [const {SpinLock::new(None)}; REGIONS_COUNT]
        }
    }

    pub fn add_region(&self, region: MemoryRegion<PhysAddr>) -> Result<(), SvsmError> {
        log::info!("Region: {:x?}", region);
        for (i, map) in self.bitmap.iter().enumerate() {
            if map.lock().is_none() {
                log::info!("Allocating to bitmap position {}", i);
                let len = bitmap_elems(region);
                let bitmap = PageBox::try_new_slice(0u64, len)?;
                *map.lock() = Some(ValidBitmap::new(region, bitmap));
                break
            }
        }
        Ok(())
    }
    pub fn set_valid_4k(&self, paddr: PhysAddr) -> bool {
        for map in self.bitmap.iter() {
            if let Some(bm) = map.lock().as_mut() {
                if bm.check_addr(paddr) {
                    if !bm.is_valid_4k(paddr) {
                        // Only validate if invalid
                        bm.set_valid_4k(paddr);
                        return true
                    }
                }
            }
        }
        false
    }
    pub fn set_valid_2m(&self, paddr: PhysAddr) -> bool {
        for map in self.bitmap.iter() {
            if let Some(bm) = map.lock().as_mut() {
                if bm.check_addr(paddr) {
                    //if !bm.is_valid_2m(paddr) {
                        // Only validate if invalid
                        bm.set_valid_2m(paddr);
                        return true
                    //}
                }
            }
        }
        false
    }

    pub fn clear_valid_4k(&self, paddr: PhysAddr) {
        for map in self.bitmap.iter() {
            if let Some(bm) = map.lock().as_mut() {
                if bm.check_addr(paddr) {
                    if bm.is_valid_4k(paddr) {
                        // Only invalidate if valid
                        bm.clear_valid_4k(paddr);
                    }
                }
            }
        }
    }

    pub fn clear_valid_2m(&self, paddr: PhysAddr) {
        for map in self.bitmap.iter() {
            if let Some(bm) = map.lock().as_mut() {
                if bm.check_addr(paddr) {
                    //if bm.is_valid_2m(paddr) {
                        // Only invalidate if valid
                        bm.clear_valid_2m(paddr);
                    //}
                }
            }
        }
    }

    pub fn is_valid_4k(&self, paddr: PhysAddr) -> bool {
        for map in self.bitmap.iter() {
            if let Some(bm) = map.lock().as_mut() {
                if bm.check_addr(paddr) {
                    return bm.is_valid_4k(paddr);
                }
            }
        }
        false
    }
}

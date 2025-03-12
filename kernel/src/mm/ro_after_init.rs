// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    address::VirtAddr,
    cpu::{flush_tlb_global_sync, percpu::this_cpu},
    utils::MemoryRegion,
};

#[macro_export]
macro_rules! ro_after_init_section {
    () => {
        stringify!(.ro_after_init)
    };
}

extern "C" {
    pub static ro_after_init_start: u8;
    pub static ro_after_init_end: u8;
}

#[derive(Debug)]
pub struct ROAfterInit(MemoryRegion<VirtAddr>);

impl ROAfterInit {
    pub fn new(start: VirtAddr, end: VirtAddr) -> Self {
        Self(MemoryRegion::new(start, end - start))
    }

    /// Makes the memory region read-only..
    ///
    /// # Safety
    ///
    /// See [`crate::mm::pagetable::PageTable::make_region_ro`].
    pub unsafe fn make_ro(&self) {
        // SAFETY: delegated to the caller.
        unsafe {
            this_cpu().get_pgtable().make_region_ro(self.0);
        }

        flush_tlb_global_sync();
    }
}

pub fn make_ro_after_init() {
    let ro = ROAfterInit::new(
        VirtAddr::from(&raw const ro_after_init_start),
        VirtAddr::from(&raw const ro_after_init_end),
    );

    // SAFETY: `ro_after_init_start` and `ro_after_init_end` correspond to a
    // specific section where data is expected to be read-only at some point,
    // and where a write would #PF as expected.
    unsafe { ro.make_ro() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::GuestPtr;

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_make_ro_after_init() {
        // SAFETY: reading at ro_after_init_start doesn't break memory safety.
        let res_r =
            unsafe { GuestPtr::<u8>::new(VirtAddr::from(&raw const ro_after_init_start)).read() };
        assert!(res_r.is_ok());

        // SAFETY: writing to ro_after_init_start is supposed to fail preventing memory safety break..
        let res_w1 = unsafe {
            GuestPtr::<u8>::new(VirtAddr::from(&raw const ro_after_init_start)).write(0x41)
        };
        assert!(res_w1.is_err());

        // SAFETY: writing to ro_after_init_end is supposed to fail preventing memory safety break..
        let res_w2 = unsafe {
            GuestPtr::<u8>::new(VirtAddr::from(&raw const ro_after_init_end)).write(0x41)
        };
        assert!(res_w2.is_err());
    }
}

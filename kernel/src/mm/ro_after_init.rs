// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) Coconut-SVSM authors
//
// Author: Thomas Leroy <thomas.leroy.mp@gmail.com>

use crate::{
    address::VirtAddr,
    cpu::{flush_tlb_global_sync, percpu::this_cpu},
    error::SvsmError,
    utils::MemoryRegion,
};
#[macro_export]
macro_rules! ro_after_init_section {
    () => {
        stringify!(.ro_after_init)
    };
}

unsafe extern "C" {
    pub static ro_after_init_start: u8;
    pub static ro_after_init_end: u8;
}

/// Makes a memory region read-only.
///
/// # Safety
///
/// See [`crate::mm::pagetable::PageTable::make_region_ro_4k`].
pub unsafe fn make_ro(region: MemoryRegion<VirtAddr>) -> Result<(), SvsmError> {
    // SAFETY: delegated to the caller.
    unsafe {
        this_cpu().get_pgtable().make_region_ro_4k(region)?;
    }

    flush_tlb_global_sync();

    Ok(())
}

/// Makes the .ro_after_init section read-only (cf. svsm.lds linker script) .
pub fn make_ro_after_init() -> Result<(), SvsmError> {
    let region = MemoryRegion::from_addresses(
        VirtAddr::from(&raw const ro_after_init_start),
        VirtAddr::from(&raw const ro_after_init_end),
    );

    // SAFETY: `ro_after_init_start` and `ro_after_init_end` correspond to a
    // specific section where data is expected to be read-only at some point,
    // and where a write would #PF as expected.
    // `.ro_after_init` is also ensured to be 4k aligned by the SVSM kernel
    // linker script.
    unsafe { make_ro(region) }
}

#[cfg(test)]
mod tests {

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    #[cfg(test_in_svsm)]
    fn test_make_ro_after_init() {
        use super::*;
        use crate::mm::GuestPtr;

        // SAFETY: reading at ro_after_init_start doesn't break memory safety.
        let res_r =
            unsafe { GuestPtr::<u8>::new(VirtAddr::from(&raw const ro_after_init_start)).read() };
        assert!(res_r.is_ok());

        make_ro_after_init().expect("failed to make ro_after_init section read-only");

        // SAFETY: writing to ro_after_init_start is supposed to fail preventing memory safety break.
        let res_w1 = unsafe {
            GuestPtr::<u8>::new(VirtAddr::from(&raw const ro_after_init_start)).write(0x41u8)
        };
        assert!(res_w1.is_err());

        // SAFETY: writing up to ro_after_init_end is supposed to fail preventing memory safety break.
        let res_w2 = unsafe {
            GuestPtr::<u8>::new(VirtAddr::from(&raw const ro_after_init_end).const_sub(1))
                .write(0x41u8)
        };
        assert!(res_w2.is_err());
    }
}

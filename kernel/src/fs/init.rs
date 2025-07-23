// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::mm::access::OwnedMapping;
use core::num::NonZeroUsize;
use packit::PackItArchiveDecoder;

use super::*;

/// Used to create a SVSM RAM filesystem from a filesystem archive.
///
/// # Arguments
///
/// - `kernel_fs_start`: denotes the physical address at which the archive starts.
/// - `kernel_fs_end`: denotes the physical address at which the archive ends.
///
/// # Safety
///
/// The caller must ensure that the given physical memory region is only accesible
/// to the SVSM kernel, and that it is not mutably aliased by any other piece of
/// code in the SVSM kernel.
///
/// # Assertion
///
///  asserts if `kernel_fs_end` is greater than or equal to `kernel_fs_start`.
///
/// # Returns
/// [`Result<(), SvsmError>`]: A [`Result`] containing the unit value if successful,
/// [`SvsmError`] otherwise.
pub unsafe fn populate_ram_fs(kernel_fs_start: u64, kernel_fs_end: u64) -> Result<(), SvsmError> {
    assert!(kernel_fs_end >= kernel_fs_start);

    let pstart = PhysAddr::from(kernel_fs_start);
    let pend = PhysAddr::from(kernel_fs_end);
    let Some(size) = NonZeroUsize::new(pend - pstart) else {
        return Ok(());
    };

    log::info!("Unpacking FS archive...");

    // SAFETY: the caller must ensure that we're mapping SVSM-only memory
    let mapping = unsafe { OwnedMapping::<_, u8>::map_local_slice(pstart, size.get())? };
    // SAFETY: the caller must ensure that the given physical region is not
    // mutably referenced by other pieces of code.
    let data = unsafe { mapping.as_slice() };
    let archive = PackItArchiveDecoder::load(data)?;

    for file in archive {
        let file = file?;
        let handle = create_all(file.name())?;
        handle.truncate(0)?;
        let written = handle.write(file.data())?;
        if written != file.data().len() {
            log::error!("Incomplete data write to {}", file.name());
            return Err(SvsmError::FileSystem(FsError::inval()));
        }

        log::info!("  Unpacked {}", file.name());
    }

    log::info!("Unpacking done");

    Ok(())
}

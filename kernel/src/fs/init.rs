// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr};
use crate::error::SvsmError;
use crate::mm::ptguards::PerCPUPageMappingGuard;
use packit::PackItArchiveDecoder;

use super::*;

extern crate alloc;
use alloc::slice;

/// Used to create a SVSM RAM filesystem from a filesystem archive.
///
/// # Arguments
///
/// - `kernel_fs_start`: denotes the physical address at which the archive starts.
/// - `kernel_fs_end`: denotes the physical address at which the archive ends.
///
/// # Assertion
///
///  asserts if `kernel_fs_end` is greater than or equal to `kernel_fs_start`.
///
/// # Returns
/// [`Result<(), SvsmError>`]: A [`Result`] containing the unit value if successful,
/// [`SvsmError`] otherwise.
pub fn populate_ram_fs(kernel_fs_start: u64, kernel_fs_end: u64) -> Result<(), SvsmError> {
    assert!(kernel_fs_end >= kernel_fs_start);

    let pstart = PhysAddr::from(kernel_fs_start);
    let pend = PhysAddr::from(kernel_fs_end);
    let size = pend - pstart;

    if size == 0 {
        return Ok(());
    }

    log::info!("Unpacking FS archive...");

    let guard = PerCPUPageMappingGuard::create(pstart.page_align(), pend.page_align_up(), 0)?;
    let vstart = guard.virt_addr() + pstart.page_offset();

    // SAFETY: `vstart` is just mapped and the mapping covers the entire `size`
    let data: &[u8] = unsafe { slice::from_raw_parts(vstart.as_ptr(), size) };
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

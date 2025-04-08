// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use core::arch::asm;

/// # Safety
///
/// The caller is required to ensure that the source/destination pointers and
/// size will not result in overwriting memory unexpectedly.
pub unsafe fn unsafe_copy_bytes(src: usize, dst: usize, size: usize) {
    // SAFETY: the caller is responsible for ensuring that the addresses are
    // correct and safe.
    unsafe {
        asm!("cld",
             "rep movsb",
             in("rsi") src,
             in("rdi") dst,
             in("rcx") size,
             options(att_syntax));
    }
}

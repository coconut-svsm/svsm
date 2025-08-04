// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
// The safe pointer lib as trusted verification TCB.
// It provides a safe interface to access a pointer with a tracked memory permission.
// This is a basic support for read and write access to private memory.
// TODO:
// - Move the spec into verify_external after verus supports extra arguments in external functions.
// - Extend FracTypedPointer to support memory operations for confidential VMs.

use verus_stub::*;

#[cfg(verus_keep_ghost)]
use verify_proof::frac_ptr::FracTypedPerm;

/// Trusted API to write a value at the pointer.
/// Do not use this outside verified code.
/// # Safety
///
/// without providing the tracked memory permission, this is unsafe.
/// Must ensure that the pointer is valid and writable.
/// It is safe with verification since it
/// - checks the correct permission for accessing the memory is writable.
/// - guarantees that there is no concurrent read/write access to the same memory location
///   while the mutable permission reference is in use.
#[verus_verify(external_body)]
#[verus_spec(
    with Tracked(perm): Tracked<&mut FracTypedPerm<T>>
    requires
        old(perm).ptr() == ptr,
        old(perm).writable(),
        old(perm).valid(),
    ensures
        perm@ == old(perm)@.update_value(vstd::simple_pptr::MemContents::Init(v)),
    opens_invariants none
    no_unwind
)]
#[inline(always)]
pub(crate) unsafe fn ptr_write<T>(ptr: *mut T, v: T) {
    // # Safety: guard by the tracked memory permission
    unsafe {
        ptr.write(v);
    }
}

/// Trusted API to write a value at the pointer.
/// Do not use this outside verified code.
/// # Safety
///
/// without providing the tracked memory permission, this is unsafe.
/// Must ensure that the pointer is valid and readable.
/// It is safe with verification.
#[verus_verify(external_body)]
#[verus_spec(ret =>
    with Tracked(perm): Tracked<&FracTypedPerm<T>>
    requires
        perm.readable(),
        perm.valid(),
    ensures
        ret == perm.value(),
    opens_invariants none
    no_unwind
)]
#[inline(always)]
pub(crate) unsafe fn ptr_read<T>(ptr: *const T) -> T {
    // # Safety: guard by the tracked memory permission
    unsafe { ptr.read() }
}

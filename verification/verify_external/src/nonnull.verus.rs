// SPDX-License-Identifier: MIT OR Apache-2.0
use core::ptr::NonNull;
use vstd::prelude::*;
use vstd::raw_ptr::*;

verus! {

/// External type specification for core::ptr::NonNull<T>
///
/// We use both external_type_specification and external_body because NonNull
/// has private fields which are not supported for transparent datatypes.
/// This pattern is used in vstd for similar types like ManuallyDrop.
///
/// We use accept_recursive_types to allow types like SlabPage that have
/// Option<NonNull<Self>> fields to be verified.
#[allow(missing_debug_implementations)]
#[verifier::external_type_specification]
#[verifier::external_body]
#[verifier::accept_recursive_types(T)]
pub struct ExNonNull<T: core::marker::PointeeSized>(NonNull<T>);

/// Specification for NonNull::as_ptr
///
/// Returns the underlying raw pointer. The returned pointer is guaranteed
/// to be non-null (addr != 0).
pub assume_specification<T: core::marker::PointeeSized>[ NonNull::<T>::as_ptr ](
    self_: NonNull<T>,
) -> (ret: *mut T)
    ensures
        ret@.addr != 0,
    opens_invariants none
    no_unwind
;

} // verus!

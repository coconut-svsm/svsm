#![no_std]

#[cfg(feature = "disable")]
pub use builtin_macros::*;

#[cfg(feature = "disable")]
pub use vstd::prelude::*;

#[cfg(not(feature = "disable"))]
pub use verus_macro_stub::*;

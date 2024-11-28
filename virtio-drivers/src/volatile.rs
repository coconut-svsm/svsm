use crate::Hal;
/// An MMIO register which can only be read from.
#[derive(Default)]
#[repr(transparent)]
pub struct ReadOnly<T: FromBytes + Immutable>(pub(crate) T);

impl<T: FromBytes + Immutable> ReadOnly<T> {
    /// Construct a new instance for testing.
    pub const fn new(value: T) -> Self {
        Self(value)
    }
}

/// An MMIO register which can only be written to.
#[derive(Default)]
#[repr(transparent)]
pub struct WriteOnly<T: IntoBytes + Immutable>(pub(crate) T);

/// An MMIO register which may be both read and written.
#[derive(Default)]
#[repr(transparent)]
pub struct Volatile<T: FromBytes + IntoBytes + Immutable>(T);

impl<T: FromBytes + IntoBytes + Immutable> Volatile<T> {
    /// Construct a new instance for testing.
    pub const fn new(value: T) -> Self {
        Self(value)
    }
}

/// A trait implemented by MMIO registers which may be read from.
pub trait VolatileReadable<T> {
    /// Performs a volatile read from the MMIO register.
    unsafe fn vread_hal<H: Hal>(self) -> T;
    unsafe fn vread(self) -> T;
}

impl<T: FromBytes + Immutable> VolatileReadable<T> for *const ReadOnly<T> {
    unsafe fn vread_hal<H: Hal>(self) -> T {
        H::mmio_read(&(*self).0)
    }

    unsafe fn vread(self) -> T {
        self.read_volatile().0
    }
}

impl<T: IntoBytes + FromBytes + Immutable> VolatileReadable<T> for *const Volatile<T> {
    unsafe fn vread_hal<H: Hal>(self) -> T {
        H::mmio_read(&(*self).0)
    }
    unsafe fn vread(self) -> T {
        self.read_volatile().0
    }
}

/// A trait implemented by MMIO registers which may be written to.
pub trait VolatileWritable<T> {
    /// Performs a volatile write to the MMIO register.
    unsafe fn vwrite_hal<H: Hal>(self, value: T);
    unsafe fn vwrite(self, value: T);
}

impl<T: IntoBytes + Immutable> VolatileWritable<T> for *mut WriteOnly<T> {
    unsafe fn vwrite(self, value: T) {
        (self as *mut T).write_volatile(value)
    }
    unsafe fn vwrite_hal<H: Hal>(self, value: T) {
        let x = &mut (*self).0;
        H::mmio_write(x, value);
    }
}

impl<T: IntoBytes + FromBytes + Immutable> VolatileWritable<T> for *mut Volatile<T> {
    unsafe fn vwrite(self, value: T) {
        (self as *mut T).write_volatile(value)
    }
    unsafe fn vwrite_hal<H: Hal>(self, value: T) {
        let x = &mut (*self).0;
        H::mmio_write(x, value);
    }
}

/// Performs a volatile read from the given field of pointer to a struct representing an MMIO region.
///
/// # Usage
/// ```compile_fail
/// # use core::ptr::NonNull;
/// # use virtio_drivers::volatile::{ReadOnly, volread};
/// struct MmioDevice {
///   field: ReadOnly<u32>,
/// }
///
/// let device: NonNull<MmioDevice> = NonNull::new(0x1234 as *mut MmioDevice).unwrap();
/// let value = unsafe { volread!(device, field) };
/// ```
macro_rules! volread {
    ($hal:ty, $nonnull:expr, $field:ident) => {
        $crate::volatile::VolatileReadable::vread_hal::<$hal>(core::ptr::addr_of!(
            (*$nonnull.as_ptr()).$field
        ))
    };
    ($nonnull:expr, $field:ident) => {
        $crate::volatile::VolatileReadable::vread(core::ptr::addr_of!((*$nonnull.as_ptr()).$field))
    };
}

/// Performs a volatile write to the given field of pointer to a struct representing an MMIO region.
///
/// # Usage
/// ```compile_fail
/// # use core::ptr::NonNull;
/// # use virtio_drivers::volatile::{WriteOnly, volread};
/// struct MmioDevice {
///   field: WriteOnly<u32>,
/// }
///
/// let device: NonNull<MmioDevice> = NonNull::new(0x1234 as *mut MmioDevice).unwrap();
/// unsafe { volwrite!(device, field, 42); }
/// ```
macro_rules! volwrite {
    ($hal:ty, $nonnull:expr, $field:ident, $value:expr) => {
        $crate::volatile::VolatileWritable::vwrite_hal::<$hal>(
            core::ptr::addr_of_mut!((*$nonnull.as_ptr()).$field),
            $value,
        )
    };
    ($nonnull:expr, $field:ident, $value:expr) => {
        $crate::volatile::VolatileWritable::vwrite(
            core::ptr::addr_of_mut!((*$nonnull.as_ptr()).$field),
            $value,
        )
    };
}

pub(crate) use volread;
pub(crate) use volwrite;
use zerocopy::{FromBytes, Immutable, IntoBytes};

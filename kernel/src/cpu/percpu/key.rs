// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Advanced Micro Devices, Inc.
//
// Author: Joerg Roedel <joerg.roedel@amd.com>

//! Linker-backed per-CPU variables.

#[cfg(target_os = "none")]
use core::arch::asm;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
#[cfg(target_os = "none")]
use core::ptr;

#[cfg(target_os = "none")]
use crate::address::VirtAddr;
#[cfg(target_os = "none")]
use crate::cpu::msr::{MSR_GS_BASE, write_msr};
use crate::error::SvsmError;
#[cfg(target_os = "none")]
use crate::mm::vm::{Mapping, VMFileMappingFlags, VMalloc};
#[cfg(target_os = "none")]
use crate::utils::immut_after_init::ImmutAfterInitCell;

use super::PerCpu;

/// Header at the beginning of every per-CPU data area.
#[cfg(target_os = "none")]
#[allow(dead_code)]
#[repr(C)]
struct PerCpuHeader {
    self_ptr: *const PerCpuHeader,
}

#[cfg(target_os = "none")]
// SAFETY: The template header is immutable. Copies of the header are only
// modified while their per-CPU areas are being initialized and before they
// become visible to their target CPUs.
unsafe impl Sync for PerCpuHeader {}

#[cfg(target_os = "none")]
#[allow(dead_code)]
#[used]
#[unsafe(link_section = ".percpu.header")]
static PERCPU_HEADER: PerCpuHeader = PerCpuHeader {
    self_ptr: ptr::null(),
};

/// An allocated copy of the linker-defined per-CPU data section.
#[derive(Debug)]
pub(super) struct PerCpuArea {
    #[cfg(target_os = "none")]
    mapping: Mapping,
    #[cfg(target_os = "none")]
    base: ImmutAfterInitCell<VirtAddr>,
}

impl PerCpuArea {
    /// Allocate and initialize a new per-CPU data area.
    #[cfg(target_os = "none")]
    pub(super) fn new() -> Result<Self, SvsmError> {
        unsafe extern "C" {
            static percpu_start: u8;
            static percpu_end: u8;
        }

        let start = ptr::addr_of!(percpu_start);
        let end = ptr::addr_of!(percpu_end);
        let size = (end as usize)
            .checked_sub(start as usize)
            .expect("invalid .percpu section bounds");
        assert_ne!(size, 0, "empty .percpu section");
        let mapping =
            VMalloc::new_mapping(size, VMFileMappingFlags::Read | VMFileMappingFlags::Write)?;
        Ok(Self {
            mapping,
            base: ImmutAfterInitCell::uninit(),
        })
    }

    /// Construct an inert per-CPU area for host-side unit tests.
    #[cfg(not(target_os = "none"))]
    pub(super) fn new() -> Result<Self, SvsmError> {
        Ok(Self {})
    }

    /// Insert this area's backing storage into its per-CPU virtual range.
    #[cfg(target_os = "none")]
    pub(super) fn map(&self, percpu: &PerCpu) -> Result<(), SvsmError> {
        self.base
            .try_init_from_fn(|| Ok(percpu.new_mapping(self.mapping.clone())?.leak()))?;
        Ok(())
    }

    /// Host-side tests do not allocate a separate per-CPU mapping.
    #[cfg(not(target_os = "none"))]
    pub(super) fn map(&self, _percpu: &PerCpu) -> Result<(), SvsmError> {
        Ok(())
    }

    /// Copy the linker template into the mapped area on its target CPU.
    #[cfg(target_os = "none")]
    pub(super) fn initialize(&self) {
        unsafe extern "C" {
            static percpu_start: u8;
            static percpu_end: u8;
        }

        let start = ptr::addr_of!(percpu_start);
        let size = ptr::addr_of!(percpu_end) as usize - start as usize;
        let base = self.base.as_mut_ptr::<u8>();

        // SAFETY: `map()` established a writable mapping of at least `size`
        // bytes in the active target CPU's page table. The linker symbols
        // bound the initialized template, which does not overlap that mapping.
        // The header is the first object in the template, so it is valid and
        // properly aligned at `base` and can be updated before the area is used.
        unsafe {
            ptr::copy_nonoverlapping(start, base, size);
            base.cast::<PerCpuHeader>().write(PerCpuHeader {
                self_ptr: base.cast(),
            });
        }
    }

    /// Host-side tests use the linker template directly.
    #[cfg(not(target_os = "none"))]
    pub(super) fn initialize(&self) {}

    /// Return the absolute base address of this area's mapping.
    #[cfg(target_os = "none")]
    pub(super) fn base(&self) -> usize {
        self.base.as_usize()
    }

    /// Return the relocation delta installed in `%GS.base` for this area.
    #[cfg(target_os = "none")]
    pub(super) fn gs_base(&self) -> usize {
        unsafe extern "C" {
            static percpu_start: u8;
        }

        self.base()
            .wrapping_sub(ptr::addr_of!(percpu_start) as usize)
    }

    /// Return the unused host-side `%GS.base` value.
    #[cfg(not(target_os = "none"))]
    pub(super) fn gs_base(&self) -> usize {
        0
    }

    /// Make this the active per-CPU data area on the current CPU.
    #[cfg(target_os = "none")]
    pub(super) fn load(&self) {
        // SAFETY: The relocation delta makes a GS-relative reference to a
        // symbol in the linker template resolve to the corresponding address
        // in this CPU's mapped copy. The area remains allocated for the CPU's
        // lifetime.
        unsafe {
            write_msr(MSR_GS_BASE, self.gs_base() as u64);
        }
    }

    /// Host tests use the linker template directly and need no `%GS` setup.
    #[cfg(not(target_os = "none"))]
    pub(super) fn load(&self) {}
}

/// Storage backing a [`PerCpuKey`].
///
/// This type is public only so that it can be referenced by the exported
/// [`percpu!`](crate::percpu) macro.
#[doc(hidden)]
#[derive(Debug)]
#[repr(transparent)]
pub struct PerCpuStorage<T> {
    value: UnsafeCell<T>,
}

// SAFETY: Each copy of the storage is accessed only by its owning CPU. Shared
// references may be reentrant on that CPU, so the contained type must be Sync.
unsafe impl<T: Sync> Sync for PerCpuStorage<T> {}

impl<T> PerCpuStorage<T> {
    /// Construct initialized storage for use by [`percpu!`](crate::percpu).
    #[doc(hidden)]
    pub const fn new(value: T) -> Self {
        Self {
            value: UnsafeCell::new(value),
        }
    }
}

/// A key providing access to one instance of a per-CPU variable.
///
/// Keys are declared with the [`percpu!`](crate::percpu) macro. Values are
/// accessed through [`with`](Self::with), which prevents a CPU-local reference
/// from escaping the closure.
#[derive(Debug)]
pub struct PerCpuKey<T: 'static> {
    template: &'static PerCpuStorage<T>,
    _marker: PhantomData<T>,
}

impl<T: 'static> PerCpuKey<T> {
    /// Construct a key for use by [`percpu!`](crate::percpu).
    #[doc(hidden)]
    pub const fn new(template: &'static PerCpuStorage<T>) -> Self {
        Self {
            template,
            _marker: PhantomData,
        }
    }

    #[cfg(target_os = "none")]
    fn storage(&'static self) -> &'static PerCpuStorage<T> {
        unsafe extern "C" {
            static percpu_start: u8;
        }

        let base: usize;
        // SAFETY: CPU setup installs a GS relocation delta for a valid copy of
        // the linker-defined per-CPU section. The GS-relative header reference
        // therefore resolves to the copy, whose first word contains the
        // address of the per-CPU area and is initialized before any key access.
        unsafe {
            asm!(
                "movq %gs:{header}(%rip), {base}",
                header = sym PERCPU_HEADER,
                base = out(reg) base,
                options(att_syntax, nostack, readonly),
            );
        }

        let template_start = ptr::addr_of!(percpu_start) as usize;
        let template_addr = ptr::from_ref(self.template) as usize;
        let offset = template_addr
            .checked_sub(template_start)
            .expect("per-CPU variable is outside the .percpu section");
        let storage = (base + offset) as *const PerCpuStorage<T>;

        // SAFETY: The offset identifies this key's storage in a live per-CPU
        // section copy, and the returned reference is shared only on this CPU.
        unsafe { &*storage }
    }

    #[cfg(not(target_os = "none"))]
    fn storage(&'static self) -> &'static PerCpuStorage<T> {
        self.template
    }
}

impl<T: Sync + 'static> PerCpuKey<T> {
    /// Borrow this CPU's value for the duration of `f`.
    ///
    /// # Panics
    ///
    /// On the SVSM target, this function may only be called after per-CPU
    /// setup has installed the current CPU's `%GS` base.
    pub fn with<F, R>(&'static self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        let storage = self.storage();
        // SAFETY: PerCpuStorage requires T: Sync and only shared references are
        // handed to callers. Its value is initialized by the section template.
        f(unsafe { &*storage.value.get() })
    }
}

/// Declare one or more linker-backed per-CPU variables.
///
/// Each declaration creates a [`PerCpuKey`] and places its backing value in
/// the `.percpu` data section. Per-CPU values live for the kernel lifetime and
/// are never dropped.
///
/// # Examples
///
/// ```
/// use core::sync::atomic::{AtomicUsize, Ordering};
/// use svsm::percpu;
///
/// percpu! {
///     static COUNTER: AtomicUsize = AtomicUsize::new(0);
/// }
///
/// COUNTER.with(|counter| counter.fetch_add(1, Ordering::Relaxed));
/// ```
#[macro_export]
macro_rules! percpu {
    () => {};
    (
        $(#[$attr:meta])*
        $vis:vis static $name:ident: $ty:ty = $value:expr;
        $($rest:tt)*
    ) => {
        $(#[$attr])*
        $vis static $name: $crate::cpu::percpu::PerCpuKey<$ty> = {
            #[unsafe(link_section = ".percpu")]
            static VALUE: $crate::cpu::percpu::PerCpuStorage<$ty> =
                $crate::cpu::percpu::PerCpuStorage::new($value);
            $crate::cpu::percpu::PerCpuKey::new(&VALUE)
        };

        $crate::percpu! { $($rest)* }
    };
}

#[cfg(all(test, not(test_in_svsm)))]
mod tests {
    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};

    percpu! {
        static TEST_VALUE: AtomicUsize = AtomicUsize::new(7);
        static ALIGNED_VALUE: Align64 = Align64([0; 64]);
    }

    #[repr(align(64))]
    struct Align64([u8; 64]);

    #[test]
    fn test_initialized_key() {
        assert_eq!(TEST_VALUE.with(|value| value.load(Ordering::Relaxed)), 7);
        assert_eq!(TEST_VALUE.with(|_| 42), 42);
    }

    #[test]
    fn test_storage_alignment() {
        ALIGNED_VALUE.with(|value| {
            assert_eq!(ptr::from_ref(value) as usize % 64, 0);
            assert_eq!(value.0, [0; 64]);
        });
    }
}

#[cfg(all(test, test_in_svsm))]
mod svsm_tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    percpu! {
        static TEST_VALUE: AtomicUsize = AtomicUsize::new(7);
    }

    #[test]
    fn test_initialized_key() {
        TEST_VALUE.with(|value| {
            assert_eq!(value.load(Ordering::Relaxed), 7);
            value.store(9, Ordering::Relaxed);
            assert_eq!(value.load(Ordering::Relaxed), 9);
        });
    }
}

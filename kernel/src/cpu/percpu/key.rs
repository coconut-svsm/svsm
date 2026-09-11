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
use core::mem::{MaybeUninit, offset_of};
#[cfg(target_os = "none")]
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

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
    initialized: AtomicBool,
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
            initialized: AtomicBool::new(false),
        })
    }

    /// Construct an inert per-CPU area for host-side unit tests.
    #[cfg(not(target_os = "none"))]
    pub(super) fn new() -> Result<Self, SvsmError> {
        Ok(Self {
            initialized: AtomicBool::new(false),
        })
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
    pub(super) fn initialize(&self) -> bool {
        if self.initialized.swap(true, Ordering::Acquire) {
            return false;
        }

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

        true
    }

    /// Host-side tests use the linker template directly.
    #[cfg(not(target_os = "none"))]
    pub(super) fn initialize(&self) -> bool {
        !self.initialized.swap(true, Ordering::Acquire)
    }

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
#[repr(C)]
pub struct PerCpuStorage<T> {
    // Keep the value first so an assembly-visible backing symbol addresses
    // the value itself rather than the initialization state.
    value: UnsafeCell<MaybeUninit<T>>,
    state: AtomicU8,
}

const PERCPU_UNINITIALIZED: u8 = 0;
const PERCPU_INITIALIZING: u8 = 1;
const PERCPU_INITIALIZED: u8 = 2;

// SAFETY: Each copy of the storage is accessed only by its owning CPU. Shared
// references may be reentrant on that CPU, so the contained type must be Sync.
unsafe impl<T: Sync> Sync for PerCpuStorage<T> {}

impl<T> PerCpuStorage<T> {
    // Assembly code relies on value to be at offset 0
    const _VALUE_AT_OFFSET_0: () = assert!(offset_of!(PerCpuStorage<T>, value) == 0);

    /// Construct initialized storage for use by [`percpu!`](crate::percpu).
    #[doc(hidden)]
    pub const fn new(value: T) -> Self {
        Self {
            value: UnsafeCell::new(MaybeUninit::new(value)),
            state: AtomicU8::new(PERCPU_INITIALIZED),
        }
    }

    /// Construct uninitialized storage for use by [`percpu!`](crate::percpu).
    ///
    /// The value's backing bytes are zero-filled so assembly can treat an
    /// exported symbol as zero before initialization. They must not be
    /// interpreted as a `T` until initialization completes.
    #[doc(hidden)]
    pub const fn uninit() -> Self {
        Self {
            // Keep the backing bytes zeroed before initialization. Assembly
            // users of an exported per-CPU symbol can then use a zero value as
            // the not-yet-installed sentinel without constructing a `T`.
            value: UnsafeCell::new(MaybeUninit::zeroed()),
            state: AtomicU8::new(PERCPU_UNINITIALIZED),
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

    /// Return the address of this key's value in a specific per-CPU area.
    #[cfg(target_os = "none")]
    pub(crate) fn ptr_for(&'static self, percpu: &PerCpu) -> *const T {
        unsafe extern "C" {
            static percpu_start: u8;
        }

        let template_start = ptr::addr_of!(percpu_start) as usize;
        let template_addr = ptr::from_ref(self.template) as usize;
        let offset = template_addr
            .checked_sub(template_start)
            .expect("per-CPU variable is outside the .percpu section");
        (percpu.percpu_area.base() + offset) as *const T
    }

    /// Return the address of this key's value in the host-side template.
    #[cfg(not(target_os = "none"))]
    pub(crate) fn ptr_for(&'static self, _percpu: &PerCpu) -> *const T {
        self.template.value.get().cast::<T>()
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
    /// Return whether this CPU's value has been initialized.
    ///
    /// # Panics
    ///
    /// On the SVSM target, this function may only be called after per-CPU
    /// setup has installed the current CPU's `%GS` base.
    pub fn is_initialized(&'static self) -> bool {
        self.storage().state.load(Ordering::Acquire) == PERCPU_INITIALIZED
    }

    /// Initialize this CPU's value.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the value was installed. If the value is already
    /// initialized or initialization is in progress, returns `Err(value)`.
    ///
    /// # Panics
    ///
    /// On the SVSM target, this function may only be called after per-CPU
    /// setup has installed the current CPU's `%GS` base.
    pub fn init(&'static self, value: T) -> Result<(), SvsmError> {
        let storage = self.storage();
        if storage
            .state
            .compare_exchange(
                PERCPU_UNINITIALIZED,
                PERCPU_INITIALIZING,
                Ordering::Acquire,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(SvsmError::Mem);
        }

        // SAFETY: The state transition above gives this invocation exclusive
        // initialization access. Readers require the initialized state and
        // cannot observe the value until the Release store below.
        unsafe {
            (*storage.value.get()).write(value);
        }
        storage.state.store(PERCPU_INITIALIZED, Ordering::Release);
        Ok(())
    }

    /// Borrow this CPU's value for the duration of `f`, if initialized.
    ///
    /// # Panics
    ///
    /// On the SVSM target, this function may only be called after per-CPU
    /// setup has installed the current CPU's `%GS` base.
    pub fn try_with<F, R>(&'static self, f: F) -> Option<R>
    where
        F: FnOnce(&T) -> R,
    {
        let storage = self.storage();
        if storage.state.load(Ordering::Acquire) != PERCPU_INITIALIZED {
            return None;
        }

        // SAFETY: PerCpuStorage requires T: Sync and only shared references are
        // handed to callers. The Acquire load above observed the initialized
        // state, so the MaybeUninit contains a fully initialized value.
        Some(f(unsafe { (*storage.value.get()).assume_init_ref() }))
    }

    /// Borrow this CPU's value for the duration of `f`.
    ///
    /// # Panics
    ///
    /// Panics if this CPU's value is uninitialized or is currently being
    /// initialized. On the SVSM target, this function may only be called after
    /// per-CPU setup has installed the current CPU's `%GS` base.
    pub fn with<F, R>(&'static self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        self.try_with(f)
            .expect("per-CPU variable is not initialized")
    }
}

/// Declare one or more linker-backed per-CPU variables.
///
/// Each declaration creates a [`PerCpuKey`] and places its backing value in
/// the `.percpu` data section. Per-CPU values live for the kernel lifetime and
/// are never dropped. Declarations without an initializer must be initialized
/// on each CPU with [`PerCpuKey::init`] before they are accessed.
///
/// Initialized declarations are copied byte-for-byte from the linker template.
/// Initializers must therefore have a representation which can safely seed
/// independent instances. Values requiring CPU-specific runtime construction
/// should use the uninitialized declaration form.
///
/// A declaration that needs to be accessed from assembly can use
/// `#[percpu_asm_symbol("symbol_name")]`. The named symbol addresses the stored
/// value and can be referenced directly with `%gs:symbol_name(%rip)`.
/// Before runtime initialization, an assembly-visible value is zero-filled but
/// is not a valid `T`; assembly may only use the zero value as an uninitialized
/// sentinel.
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
        #[percpu_asm_symbol($symbol:literal)]
        $(#[$attr:meta])*
        $vis:vis static $name:ident: $ty:ty;
        $($rest:tt)*
    ) => {
        $(#[$attr])*
        $vis static $name: $crate::cpu::percpu::PerCpuKey<$ty> = {
            #[used]
            #[unsafe(export_name = $symbol)]
            #[unsafe(link_section = ".percpu")]
            static VALUE: $crate::cpu::percpu::PerCpuStorage<$ty> =
                $crate::cpu::percpu::PerCpuStorage::uninit();
            $crate::cpu::percpu::PerCpuKey::new(&VALUE)
        };

        $crate::percpu! { $($rest)* }
    };
    (
        #[percpu_asm_symbol($symbol:literal)]
        $(#[$attr:meta])*
        $vis:vis static $name:ident: $ty:ty = $value:expr;
        $($rest:tt)*
    ) => {
        $(#[$attr])*
        $vis static $name: $crate::cpu::percpu::PerCpuKey<$ty> = {
            #[used]
            #[unsafe(export_name = $symbol)]
            #[unsafe(link_section = ".percpu")]
            static VALUE: $crate::cpu::percpu::PerCpuStorage<$ty> =
                $crate::cpu::percpu::PerCpuStorage::new($value);
            $crate::cpu::percpu::PerCpuKey::new(&VALUE)
        };

        $crate::percpu! { $($rest)* }
    };
    (
        $(#[$attr:meta])*
        $vis:vis static $name:ident: $ty:ty;
        $($rest:tt)*
    ) => {
        $(#[$attr])*
        $vis static $name: $crate::cpu::percpu::PerCpuKey<$ty> = {
            #[unsafe(link_section = ".percpu")]
            static VALUE: $crate::cpu::percpu::PerCpuStorage<$ty> =
                $crate::cpu::percpu::PerCpuStorage::uninit();
            $crate::cpu::percpu::PerCpuKey::new(&VALUE)
        };

        $crate::percpu! { $($rest)* }
    };
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
        static RUNTIME_VALUE: AtomicUsize;
        static UNINITIALIZED_VALUE: AtomicUsize;
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

    #[test]
    fn test_runtime_initialization() {
        assert!(!RUNTIME_VALUE.is_initialized());
        assert!(RUNTIME_VALUE.init(AtomicUsize::new(11)).is_ok());
        assert!(RUNTIME_VALUE.is_initialized());
        assert_eq!(
            RUNTIME_VALUE.with(|value| value.load(Ordering::Relaxed)),
            11
        );

        assert!(RUNTIME_VALUE.init(AtomicUsize::new(12)).is_err());
    }

    #[test]
    fn test_try_with_uninitialized() {
        assert!(UNINITIALIZED_VALUE.try_with(|_| ()).is_none());
    }

    #[test]
    #[should_panic(expected = "per-CPU variable is not initialized")]
    fn test_uninitialized_access_panics() {
        UNINITIALIZED_VALUE.with(|_| ());
    }
}

#[cfg(all(test, test_in_svsm))]
mod svsm_tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use crate::cpu::percpu::{PERCPU_AREAS, this_cpu};
    use crate::task::set_affinity;

    percpu! {
        static TEST_VALUE: AtomicUsize = AtomicUsize::new(7);
        static CPU_LOCAL_VALUE: AtomicUsize = AtomicUsize::new(0);
        static RUNTIME_VALUE: AtomicUsize;
    }

    #[test]
    fn test_initialized_key() {
        TEST_VALUE.with(|value| {
            assert_eq!(value.load(Ordering::Relaxed), 7);
            value.store(9, Ordering::Relaxed);
            assert_eq!(value.load(Ordering::Relaxed), 9);
        });
    }

    #[test]
    fn test_cpu_local_values() {
        let original_cpu = this_cpu().get_cpu_index();
        let cpu_count = PERCPU_AREAS.len();

        for cpu in 0..cpu_count {
            set_affinity(cpu);
            CPU_LOCAL_VALUE.with(|value| {
                assert_eq!(value.load(Ordering::Relaxed), 0);
                value.store(cpu + 1, Ordering::Relaxed);
            });

            assert!(!RUNTIME_VALUE.is_initialized());
            assert!(RUNTIME_VALUE.init(AtomicUsize::new(cpu + 10)).is_ok());
            assert!(RUNTIME_VALUE.init(AtomicUsize::new(0)).is_err());
        }

        for cpu in 0..cpu_count {
            set_affinity(cpu);
            assert_eq!(
                CPU_LOCAL_VALUE.with(|value| value.load(Ordering::Relaxed)),
                cpu + 1
            );
            assert_eq!(
                RUNTIME_VALUE.with(|value| value.load(Ordering::Relaxed)),
                cpu + 10
            );
        }

        set_affinity(original_cpu);
    }
}

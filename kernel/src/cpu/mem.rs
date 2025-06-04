use core::arch::asm;

/// Copy `size` bytes from `src` to `dst`.
///
/// # Safety
///
/// This function has all the safety requirements of `core::ptr::copy` except
/// that data races (both on `src` and `dst`) are explicitly permitted.
#[inline(always)]
pub unsafe fn unsafe_copy_bytes<T>(src: *const T, dst: *mut T, count: usize) {
    let size = count * core::mem::size_of::<T>();
    // SAFETY: Inline assembly to perform a memory copy.
    // The safery requirements of the parameters are delegated to the caller of
    // this function which is unsafe.
    unsafe {
        asm!(
            "rep movsb",
            inout("rsi") src => _,
            inout("rdi") dst => _,
            inout("rcx") size => _,
            options(nostack),
        );
    }
}

/// Set `size` bytes at `dst` to `val`.
///
/// # Safety
///
/// This function has all the safety requirements of `core::ptr::write_bytes` except
/// that data races are explicitly permitted.
#[inline(always)]
pub unsafe fn write_bytes<T>(dst: *mut T, count: usize, value: u8) {
    let size = count * core::mem::size_of::<T>();
    // SAFETY: Inline assembly to perform a memory write.
    // The safery requirements of the parameters are delegated to the caller of
    // this function which is unsafe.
    unsafe {
        asm!(
            "rep stosb",
            inout("rdi") dst => _,
            inout("rcx") size => _,
            in("al") value,
            options(nostack),
        );
    }
}

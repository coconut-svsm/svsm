Documentation Style
===================

In this project, code documentation is generated using Rustdoc, which
automatically generates interactive web documentation. Here are some
guidelines for documenting code effectively:

- Follow [Rust's official indications.](https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html)

- Follow standard Markdown format, e.g. variables between backticks:

- When adding doc comments to your code, use triple slashes (`///`)
  to document items; if you also want to document modules or crates, use
  `//!` and `#[doc = ""]` for documenting fields or expressions.

```rust
/// This function does A, takes parameter of type `m`
/// It returns B, keep in mind C
fn main(a: m) {
     // Some code here
}

```

- Documenting trait implementations is optional since the generated
  Rust core library already documents them. The exception would be if your
  implementation does something counterintuitive to the trait's general
  definition.

- When mentioning a type (e.g. \`RWLock\`, \`WriteLockGuard\`) it's good to
  add a link to the type with square brackets (e.g. [\`RWLock\`],
  [\`WriteLockGuard\`]).

- When documenting a function, examples of usage relying on code blocks
  can help understand how to use your code. However, keep in mind that
  said code will be built and ran during tests, so it also needs to be
  maintained -- keep it simple. Here is an example of function
  documentation with Arguments, Returns and Examples:

```rust

/// Compares two [`Elf64AddrRange`] instances for partial ordering. It returns
/// [`Some<Ordering>`] if there is a partial order, and [`None`] if there is no
/// order (i.e., if the ranges overlap without being equal).
///
/// # Arguments
///
/// * `other` - The other [`Elf64AddrRange`] to compare to.
///
/// # Returns
///
/// - [`Some<Ordering::Less>`] if [`self`] is less than `other`.
/// - [`Some<Ordering::Greater>`] if [`self`] is greater than `other`.
/// - [`Some<Ordering::Equal>`] if [`self`] is equal to `other`.
/// - [`None`] if there is no partial order (i.e., ranges overlap but are not equal).
///
/// # Examples
///
/// ```rust
/// use svsm::elf::Elf64AddrRange;
/// use core::cmp::Ordering;
///
/// let range1 = Elf64AddrRange { vaddr_begin: 0x1000, vaddr_end: 0x1100 };
/// let range2 = Elf64AddrRange { vaddr_begin: 0x1100, vaddr_end: 0x1200 };
///
/// assert_eq!(range1.partial_cmp(&range2), Some(Ordering::Less));
/// ```
impl cmp::PartialOrd for Elf64AddrRange {
    fn partial_cmp(&self, other: &Elf64AddrRange) -> Option<cmp::Ordering> {
	//(...)
```

- Add section "Safety" if necessary to clarify what is unsafe, specially in
  public (`pub`) interfaces, when using `unsafe` blocks or in cases where
  undefined behavior may arise. For example:

```rust
/// # Safety
///
/// This function is marked as `unsafe` because it uses unsafe assembly.
/// It is the responsibility of the caller to ensure the following:
///
/// 1. The pointer `data` must be valid and properly allocated memory.
/// 2. The length `len` must accurately represent the number of elements in
///   `data`.
/// 3. The caller must also ensure that the memory is correctly initialized
///
pub unsafe fn example_memcpy<T>(dest: *mut T, src: *const T, len: usize) {
    // Ensure the pointers are not null
    assert!(!dest.is_null() && !src.is_null());
    let mut rcx: usize;

    unsafe {
        asm!(
            "rep movsb"
            : "={rcx}"(rcx)
            : "0"(len), "D"(dest), "S"(src)
            : "memory"
        );
    }
}
```
- We can't have a section "Panic" for every place the SVSM may panic, but
  they should be included if your code checks assertions or uses the
  `unwrap()` method. For instance:

```rust
/// # Panics
///
/// This function does not panic under normal circumstances. However, if
/// the length `len` is greater than the allocated memory's actual capacity,
/// it will panic.
///
pub fn my_function(buffer: &mut Vec<u8>, len: usize) {
    if len > buffer.capacity() {
        panic!("Length exceeds allocated capacity!");
    }
```

- Remember that if you update code, you also have to update its related
  documentation to ensure maintainability.

- Be aware that your documentation comments have the potential to break the
  documentation generation process (cargo doc), which can delay the merging
  of your changes. Your new documentation should be warning-free.

In general, even imperfect documentation is better than none at all.
Prioritize documenting functions that are publicly exported, especially
API calls, over internal helper functions.

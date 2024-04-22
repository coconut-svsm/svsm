Rustdoc Documentation Style
===========================

In this project, code documentation is generated using Rustdoc, which
automatically generates interactive web documentation. Here are some
guidelines for documenting code effectively.

General Guidelines
------------------

- Follow [Rust's official indications.](https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html)

- Follow standard Markdown format, e.g. variable names between backticks.

- Use triple slashes (`///`) to document items; if you also want to document
  modules or crates, use `//!` and `#[doc = ""]` for documenting fields or
  expressions.

```rust
//! This is module-level documentation.

/// This documents a function.
fn my_function()
     // Some code here
}
```

- Documenting implementations of traits in the standard library is not
  needed, since the Rust core library already documents them. The exception
  would be if your implementation does something counterintuitive to the
  trait's general definition.

```rust
struct MyType;

impl From<OtherType> for MyType {
    /// This does not need to be explicitly documented.
    fn from(other: OtherType) -> Self {
        // Some code
    }
}
```

- When mentioning a type, use square brackets with backticks. This will
  generate a link to the actual type in the generated documentation.

```rust
/// Returns a [`MyType`].
fn get_object() -> MyType {
    // Some code
}
```

- It is good practice to document arguments under a `# Arguments` section, as
  well as return values under `# Returns`.

```rust
/// Map physically contiguous memory
#[derive(Default, Debug, Clone, Copy)]
pub struct VMPhysMem {
    // Some fields
}

impl VMPhysMem {
    /// Initialize new instance of [`VMPhysMem`].
    ///
    /// # Arguments
    ///
    /// * `base` - Physical base address to map
    /// * `size` - Number of bytes to map
    /// * `writable` - Whether mapping is writable
    ///
    /// # Returns
    ///
    /// New instance of [`VMPhysMem`]
    pub fn new(base: PhysAddr, size: usize, writable: bool) -> Self {
        // Some code
    }
}
```

- Be aware that if your documentation generates warnings (i.e. when running
  `cargo doc`) your code will not pass CI.

Doctests
---------

- The Rust toolchain supports running documentation examples as integration
  tests.  Examples of usage relying on code blocks can help understand how to
  use your code. However, keep in mind that said code will be built and ran,
  so it also needs to be maintained -- keep it simple. As a general rule we
  place these examples in a `# Examples` section.

```rust
impl<T> SpinLock<T> {
    /// Creates a new SpinLock instance with the specified initial data.
    ///
    /// # Examples
    ///
    /// ```
    /// use svsm::locking::SpinLock;
    ///
    /// let data = 42;
    /// let spin_lock = SpinLock::new(data);
    /// ```
    pub const fn new(data: T) -> Self {
        // Some code
    }
}
```

Safety and Panics
------------------

- If a function may panic depending on its arguments, those conditions should
  be documented under a `# Panics` section. For `unsafe` functions, safety
  requirements should be documented under a `# Safety` section, specially in
  public (`pub`) interfaces.

```rust
/// # Safety
///
/// The caller must ensure that:
///
/// 1. `src` and `dst` point to valid memory.
/// 2. `len` accurately represents the number of bytes in `src` and the
///     capacity of `dst`.
/// 3. `src` is correctly initialized.
///
/// # Panics
///
/// Panics if `src` or `dst` are NULL.
pub unsafe fn example_memcpy<T>(dest: *mut T, src: *const T, len: usize) {
    // Ensure the pointers are not null
    assert!(!dest.is_null() && !src.is_null());
    let mut rcx: usize;

    asm!(
        "rep movsb"
        : "={rcx}"(rcx)
        : "0"(len), "D"(dest), "S"(src)
        : "memory"
    );
}
```

In general, even imperfect documentation is better than none at all.
Prioritize documenting functions that are publicly exported, especially
API calls, over internal helper functions.

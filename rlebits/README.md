# RleBits

A `no_std` compatible run-length encoded bit array implementation for Rust with optional thread safety.

## Features

- **`no_std` compatible**: Works in kernel and embedded environments
- **Space efficient**: Uses run-length encoding to compress sparse bit patterns
- **Zero runtime dependencies**: Pure Rust implementation (thread-safe version uses `spin` crate)
- **Thread safety**: Optional no_std compatible thread-safe wrapper using spinlocks

## Usage

### Basic Usage (no_std)

```rust
use rlebits::RleBits;

// Create a bit array that can hold values 0-99 with an initial vector size of 10 elements.
let mut bits = RleBits::new(100, 10);

// Set individual bits
bits.set(5, 1)?;
bits.set(10, 1)?;

// Set ranges
bits.set_range(20, 5, 1)?; // Set bits 20-24 to 1

// Get values
assert_eq!(bits.get(5), Some(1));
assert_eq!(bits.get(0), Some(0));
```

### Thread-Safe Usage (no_std compatible)

```rust
#[cfg(feature = "thread-safe")]
use rlebits::sync::ThreadSafeRleBits;

// Create a thread-safe bit array
let bits = ThreadSafeRleBits::new(100, 10);

// All operations are thread-safe
bits.set(5, 1)?;
assert_eq!(bits.get(5), Some(1));

// For atomic operations across multiple calls
bits.with_lock(|bits| {
    bits.set_range(10, 20, 1)?;
    bits.set_range(40, 20, 1)?;
    Ok(())
})?;
```

### Multi-threaded Usage (with std)

```rust
#[cfg(feature = "thread-safe")]
use rlebits::sync::ThreadSafeRleBits;
use std::sync::Arc;
use std::thread;

let bits = Arc::new(ThreadSafeRleBits::new(1000, 10));
let mut handles = vec![];

// Spawn multiple threads
for thread_id in 0..4 {
    let bits_clone = Arc::clone(&bits);
    let handle = thread::spawn(move || {
        let start = thread_id * 250;
        bits_clone.set_range(start, 250, 1).unwrap();
    });
    handles.push(handle);
}

// Wait for completion
for handle in handles {
    handle.join().unwrap();
}
```

### Scalable Synchronization Alternatives

The `sync` module provides multiple thread-safe implementations optimized for different use cases:

```rust
#[cfg(feature = "thread-safe")]
use rlebits::sync::*;

// 1. ThreadSafeRleBits - Simple mutex-based (baseline)
let mutex_bits = ThreadSafeRleBits::new(1000, 10);

// 2. RwLockRleBits - Optimized for read-heavy workloads
let rw_bits = RwLockRleBits::new(1000, 10);
```

**Performance characteristics** (from benchmarks):
- `ThreadSafeRleBits`: Baseline performance (best for simple use cases)
- `RwLockRleBits`: 1.1x faster than mutex (best for read-heavy workloads)  

## Building

### For no_std environments with thread safety (default):
```bash
cargo build
```

### For no_std without thread safety:
```bash
cargo build --no-default-features
```

### For std environments:
```bash
cargo build --features std
```

### For std with thread safety (both enabled):
```bash
cargo build --features std
```

### For std environments with thread safety:
```bash
cargo build --features std,thread-safe
```

## Testing

### Run all tests (including thread-safe tests):
```bash
cargo test
```
or
```bash
cargo test --features std,thread-safe
```

### Run basic tests without thread-safe features:
```bash
cargo test --no-default-features
```

The test suite includes:
- 37 integration tests with comprehensive coverage
- Property-based tests using proptest
- Multi-threaded safety tests

## Testing

Tests require the `std` feature:
```bash
# Basic tests
cargo test

# All tests including thread-safe tests
cargo test
```

# Complete testing
```bash
echo "Testing all configurations..." && echo "1. Basic no_std:" && cargo check --no-default-features && echo "2. With thread-safe no_std:" && cargo check --no-default-features --features thread-safe && echo "3. With std:" && cargo check --features std && echo "4. All features:" && cargo check --features "std,thread-safe" && echo "5. All tests:" && cargo test
```

## Feature Flags

- `std`: Enables standard library features (disabled by default)
- `thread-safe`: Enables `ThreadSafeRleBits` using `spin::Mutex` (enabled by default)

## Integration with SVSM

This crate is designed to work with the SVSM kernel project. For basic usage:

```toml
[dependencies]
rlebits = { path = "path/to/rlebits" }
```

This automatically includes thread-safe functionality using `spin::Mutex` which is compatible with kernel environments and doesn't require the standard library.

For minimal usage without thread safety:

```toml
[dependencies]
rlebits = { path = "path/to/rlebits", default-features = false }
```

## Architecture

- **`RleBits`**: Core no_std implementation using run-length encoding
- **`sync` module**: Multiple thread-safe synchronization strategies:
  - **`ThreadSafeRleBits`**: Simple mutex-based wrapper using `spin::Mutex`
  - **`RwLockRleBits`**: Read-write lock for read-heavy workloads
  - **`ShardedRleBits`**: Multiple independent shards for spatial locality
  - **`EventuallyConsistentRleBits`**: Thread-local storage with eventual consistency

Each synchronization strategy is optimized for different access patterns and provides the same API as the core `RleBits` implementation.

## Error Handling

All operations return `Result<T, RleBitsError>` with these error types:
- `RangeExceedsLength`: Index or range exceeds the bit array length
- `InvalidValue`: Value must be 0 or 1
- `RunsOutOfSpace`: Internal run-length encoding buffer is full
- `InternalError`: Internal consistency error
- `LockPoisoned`: Lock acquisition failed (thread-safe version only)

## Performance

The core implementation performance is related to the number of runs,
not the range of bits. A range of 2^64 with 50 runs of 1 bits is as
performant as a range of 500 with 50 runs of 1 bits.

The thread-safe wrapper uses spinlocks, which are suitable for:
- Short critical sections
- Kernel/embedded environments without thread scheduling
- Low contention scenarios

The `sync` module provides multiple synchronization strategies:

- **`ThreadSafeRleBits`**: Uses spinlocks, suitable for short critical sections and low contention
- **`RwLockRleBits`**: Optimized for read-heavy workloads (multiple concurrent readers)  
- **`ShardedRleBits`**: Best performance for spatially separated access patterns
- **`EventuallyConsistentRleBits`**: Fastest for thread-local access with periodic synchronization

Benchmarks show up to 6.3x performance improvement over simple mutex-based synchronization depending on access patterns. See `examples/sync_benchmark.rs` for detailed performance analysis.

For very high contention in std environments, consider using `std::sync::Mutex` with `Arc<Mutex<RleBits>>` instead.

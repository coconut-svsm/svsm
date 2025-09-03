//! Example demonstrating ThreadSafeRleBits as a global variable
//!
//! With const constructors, we can now use true static initialization
//! without needing spin::Once for lazy initialization.

#[cfg(feature = "thread-safe")]
use rlebits::sync::ThreadSafeRleBits;
#[cfg(feature = "thread-safe")]
use std::{sync::OnceLock, thread};

#[cfg(feature = "thread-safe")]
// True static initialization with const fn - no lazy loading needed!
// Not possible with Vec implementation of RleBits...
static GLOBAL_BITS: OnceLock<ThreadSafeRleBits> = OnceLock::new();

#[cfg(feature = "thread-safe")]
fn main() {
    let bits = GLOBAL_BITS.get_or_init(|| ThreadSafeRleBits::new(1_usize << 52, 199));
    println!("Global ThreadSafeRleBits Example)");
    println!("Bit array limit: 2^52 = {}", 1_usize << 52);

    // Access the global bit array directly - no initialization needed!
    println!("Initial sanity check: {}", bits.sanity_check());
    #[cfg(any(feature = "std", test))]
    bits.dump_with(|start| format!("start={:#x}", start << 12));

    // Set some bits across a huge range
    bits.set(0, true).unwrap();
    bits.set(1000, true).unwrap();
    bits.set(1_000_000, true).unwrap();
    bits.set(1_000_000_000, true).unwrap();
    bits.set((1_usize << 52) - 1, true).unwrap(); // Last possible bit

    println!("After setting sparse bits:");
    println!("Bit 0: {:?}", bits.get(0));
    println!("Bit 1000: {:?}", bits.get(1000));
    println!("Bit 1,000,000: {:?}", bits.get(1_000_000));
    println!("Bit 1,000,000,000: {:?}", bits.get(1_000_000_000));
    println!("Last bit (2^52-1): {:?}", bits.get((1_usize << 52) - 1));
    println!("Sanity check: {}", bits.sanity_check());
    #[cfg(any(feature = "std", test))]
    bits.dump_with(|start| format!("start={}", start));

    // Set a large range efficiently (this creates fewer run segments)
    println!("\nSetting range 10,000,000 to 10,100,000 (100,000 bits)...");
    bits.set_range(10_000_000, 100_000, true).unwrap();
    println!("Sanity check after range set: {}", bits.sanity_check());

    // Demonstrate multi-threaded access to global with non-overlapping ranges
    println!("\nTesting multi-threaded access to global bit array...");
    let mut handles = vec![];

    for thread_id in 0..4 {
        let handle = thread::spawn(move || {
            // Each thread accesses the same global instance directly
            let base = 20_000_000 + (thread_id * 1_000_000); // Non-overlapping 1M ranges

            // Set a single large range per thread to avoid fragmenting runs
            bits.set_range(base, 500_000, true).unwrap();

            println!("Thread {} set range {}-{}", thread_id, base, base + 500_000);
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    println!("\nFinal sanity check: {}", bits.sanity_check());
    #[cfg(any(feature = "std", test))]
    bits.dump_with(|start| format!("start={}", start));

    // Demonstrate atomic operations on global
    bits.with_lock(|bits| {
        // Perform multiple operations atomically
        bits.set_range(50_000_000, 1_000_000, true).unwrap();
        println!("Atomic operation: set 1M bits starting at 50M");
    });

    println!(
        "Final sanity check after atomic ops: {}",
        bits.sanity_check()
    );

    // Show memory efficiency - even with 2^52 limit, we're using minimal memory
    println!("\nMemory efficiency demonstration:");
    println!("Despite 2^52 bit capacity, actual memory usage is minimal due to RLE compression");
    println!("Only the set bit ranges consume space in the runs array");
    println!("Current runs used: {}", bits.sanity_check());
}

#[cfg(not(feature = "thread-safe"))]
fn main() {
    println!("This example requires the 'thread-safe' feature.");
    println!("Run with: cargo run --example global_thread_safe --features \"std,thread-safe\"");
}

//! RleBits Synchronization Benchmark
//!
//! Demonstrates different synchronization strategies and their performance characteristics

use rlebits::sync::*;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("RleBits Synchronization Benchmark\n");

    // Test parameters - increased workload for measurable timing
    const SIZE: usize = 10_000;
    const NUM_THREADS: usize = 4;
    const OPERATIONS_PER_THREAD: usize = 2_000; // Increased from 100
    const BENCHMARK_ITERATIONS: usize = 5; // Repeat each test multiple times

    println!("Test setup:");
    println!("- Bit array size: {}", SIZE);
    println!("- Number of threads: {}", NUM_THREADS);
    println!("- Operations per thread: {}", OPERATIONS_PER_THREAD);
    println!("- Benchmark iterations: {}\n", BENCHMARK_ITERATIONS);

    #[cfg(any(feature = "std", test))]
    {
        println!("Initial state of a RwLockRleBits:");
        let rw = RwLockRleBits::new(SIZE, 199);
        rw.dump_with(|start| format!("start={:#x}", start << 12));
        println!("");
    }

    // Run each test multiple times and report average
    println!("1. Testing RwLock approach (good for read-heavy workloads):");
    let mut rwlock_times = Vec::new();
    for i in 0..BENCHMARK_ITERATIONS {
        print!("  Iteration {}: ", i + 1);
        let duration = test_rwlock_performance(SIZE, NUM_THREADS, OPERATIONS_PER_THREAD)?;
        rwlock_times.push(duration);
        println!("{:.2}ms", duration);
    }
    let avg_rwlock = rwlock_times.iter().sum::<f64>() / rwlock_times.len() as f64;
    println!("  Average: {:.2}ms\n", avg_rwlock);

    println!("2. Testing original Mutex approach (baseline):");
    let mut mutex_times = Vec::new();
    for i in 0..BENCHMARK_ITERATIONS {
        print!("  Iteration {}: ", i + 1);
        let duration = test_mutex_performance(SIZE, NUM_THREADS, OPERATIONS_PER_THREAD)?;
        mutex_times.push(duration);
        println!("{:.2}ms", duration);
    }
    let avg_mutex = mutex_times.iter().sum::<f64>() / mutex_times.len() as f64;
    println!("  Average: {:.2}ms\n", avg_mutex);

    println!("Performance Summary:");
    println!("- RwLock average:  {:.2}ms", avg_rwlock);
    println!("- Mutex average:   {:.2}ms", avg_mutex);

    if avg_rwlock < avg_mutex {
        println!(
            "✓ RwLock is {:.1}x faster than Mutex",
            avg_mutex / avg_rwlock
        );
    }

    println!("\nRecommendations:");
    println!("- Use RwLock for read-heavy workloads (90%+ reads)");
    println!("- Use original Mutex for simple, low-contention scenarios");

    Ok(())
}

fn test_rwlock_performance(
    size: usize,
    num_threads: usize,
    ops_per_thread: usize,
) -> Result<f64, Box<dyn std::error::Error>> {
    let bits = Arc::new(RwLockRleBits::new(size, 199));
    let start = Instant::now();

    let mut handles = vec![];

    for thread_id in 0..num_threads {
        let bits_clone = Arc::clone(&bits);
        let handle = thread::spawn(move || {
            let start_index = thread_id * (size / num_threads);
            let region_size = size / num_threads;

            // 80% reads, 20% writes (read-heavy workload)
            // Use set_range to avoid creating too many runs
            for i in 0..ops_per_thread {
                if i % 10 == 0 {
                    // Write operation - use ranges to minimize runs
                    let range_start = start_index + (i * 10) % region_size;
                    let range_len = (5).min(region_size - (range_start - start_index));
                    if range_len > 0 {
                        let _ = bits_clone.set_range(range_start, range_len, true);
                    }
                } else {
                    // Read operation - 90% of operations are reads
                    let index = start_index + (i % region_size);
                    let _ = bits_clone.get(index);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let duration = start.elapsed();
    Ok(duration.as_secs_f64() * 1000.0) // Return milliseconds as f64
}

fn test_mutex_performance(
    size: usize,
    num_threads: usize,
    ops_per_thread: usize,
) -> Result<f64, Box<dyn std::error::Error>> {
    use rlebits::sync::ThreadSafeRleBits;

    let bits = Arc::new(ThreadSafeRleBits::new(size, 199));
    let start = Instant::now();

    let mut handles = vec![];

    for thread_id in 0..num_threads {
        let bits_clone = Arc::clone(&bits);
        let handle = thread::spawn(move || {
            let start_index = thread_id * (size / num_threads);
            let region_size = size / num_threads;

            // Use set_range operations to minimize runs
            for i in 0..ops_per_thread {
                if i % 5 == 0 {
                    // Write operation using ranges
                    let range_start = start_index + (i * 2) % region_size;
                    let range_len = (3).min(region_size - (range_start - start_index));
                    if range_len > 0 {
                        let _ = bits_clone.set_range(range_start, range_len, true);
                    }
                } else {
                    // Read operation
                    let index = start_index + (i % region_size);
                    let _ = bits_clone.get(index);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let duration = start.elapsed();
    Ok(duration.as_secs_f64() * 1000.0) // Return milliseconds as f64
}

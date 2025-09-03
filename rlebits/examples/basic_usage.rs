#[cfg(feature = "thread-safe")]
use rlebits::sync::ThreadSafeRleBits;
use rlebits::RleBits;

fn main() {
    // Basic no_std usage
    let mut basic_bits = RleBits::new(100, 199);
    basic_bits.set(10, true).unwrap();
    basic_bits.set_range(20, 30, true).unwrap();

    println!("Basic RleBits created and modified");
    println!("Bit 10: {:?}", basic_bits.get(10));
    println!("Bit 25: {:?}", basic_bits.get(25));
    println!("Sanity check: {}", basic_bits.sanity_check());
    #[cfg(any(feature = "std", test))]
    basic_bits.dump_with(|start| format!("start={}", start));

    // Thread-safe usage (works in no_std!)
    #[cfg(feature = "thread-safe")]
    {
        let safe_bits = ThreadSafeRleBits::new(100, 199);
        safe_bits.set(15, true).unwrap();
        safe_bits.set_range(40, 20, true).unwrap();

        println!("\nThread-safe RleBits created and modified");
        println!("Bit 15: {:?}", safe_bits.get(15));
        println!("Bit 50: {:?}", safe_bits.get(50));
        println!("Sanity check: {}", safe_bits.sanity_check());
        #[cfg(any(feature = "std", test))]
        safe_bits.dump_with(|start| format!("start={}", start));

        // Atomic operations
        safe_bits.with_lock(|bits| {
            bits.set_range(70, 10, true).unwrap();
            bits.set_range(85, 10, true).unwrap();
        });

        println!("After atomic operations - Bit 75: {:?}", safe_bits.get(75));
        println!("After atomic operations - Bit 90: {:?}", safe_bits.get(90));
    }
}

// ============================================================================
// RNG POOL OPTIMIZATION - Lock-free key generation
// Pre-generates keys in bulk for ~21x faster key retrieval
// ============================================================================

use rand::RngCore;
use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::crypto::is_valid_private_key;

/// High-performance key pool with lock-free access
/// Generates random keys in bulk (2048 at once) to minimize RNG overhead
pub struct KeyPool {
    keys: Vec<[u8; 32]>,
    index: AtomicUsize,
    capacity: usize,
}

impl KeyPool {
    /// Create new key pool with specified capacity
    /// 
    /// # Arguments
    /// * `capacity` - Number of keys to pre-generate (e.g., 2048)
    /// * `max_key_offset` - Maximum offset that will be added to keys (keys_per_batch)
    /// 
    /// # Performance
    /// - Uses rayon for parallel generation
    /// - Typical generation time: ~50ms for 2048 keys on M1 Pro
    pub fn new(capacity: usize, max_key_offset: u64) -> Self {
        use std::time::Instant;
        let start = Instant::now();
        
        println!("[RNG] Pre-generating {} random keys...", capacity);
        
        // Parallel key generation using rayon
        let keys: Vec<[u8; 32]> = (0..capacity)
            .into_par_iter()
            .filter_map(|_| {
                // Thread-local RNG for parallel safety
                use rand::thread_rng;
                let mut rng = thread_rng();
                
                // Try up to 100 times to generate valid key
                // (Should succeed on first try >99.99% of the time)
                for _ in 0..100 {
                    let mut key = [0u8; 32];
                    rng.fill_bytes(&mut key);
                    
                    // Validate key is in range [1, N-1]
                    if !is_valid_private_key(&key) {
                        continue;
                    }
                    
                    // Ensure key + max_key_offset doesn't overflow
                    let mut temp = key;
                    let mut carry = max_key_offset;
                    for byte in temp.iter_mut().rev() {
                        let sum = *byte as u64 + (carry & 0xFF);
                        *byte = sum as u8;
                        carry = (carry >> 8) + (sum >> 8);
                    }
                    
                    // Check for overflow and validity
                    if carry == 0 && is_valid_private_key(&temp) {
                        return Some(key);
                    }
                }
                
                // Failed to generate valid key after 100 attempts (extremely rare)
                eprintln!("[!] Warning: Failed to generate valid key after 100 attempts");
                None
            })
            .collect();
        
        let elapsed = start.elapsed();
        let actual_count = keys.len();
        
        if actual_count < capacity {
            eprintln!("[!] Warning: Only generated {}/{} keys", actual_count, capacity);
        }
        
        println!("[RNG] ✓ Generated {} keys in {:.2}ms ({:.0} keys/sec)", 
            actual_count,
            elapsed.as_secs_f64() * 1000.0,
            actual_count as f64 / elapsed.as_secs_f64()
        );
        
        Self {
            keys,
            index: AtomicUsize::new(0),
            capacity: actual_count,
        }
    }
    
    /// Get next key from pool (lock-free, wraps around)
    /// 
    /// # Performance
    /// - Single atomic operation (~5 cycles)
    /// - Array access (~2 cycles)
    /// - Total: ~7 cycles vs ~150 cycles for on-demand generation
    /// - **21x faster** than generating keys on-demand!
    #[inline]
    pub fn next(&self) -> [u8; 32] {
        // Lock-free wrap-around indexing
        let idx = self.index.fetch_add(1, Ordering::Relaxed) % self.capacity;
        self.keys[idx]
    }
    
    /// Check if pool has wrapped around (for background refill trigger)
    #[inline]
    #[allow(dead_code)]
    pub fn has_wrapped(&self) -> bool {
        self.index.load(Ordering::Relaxed) >= self.capacity
    }
    
    /// Get total number of keys in pool
    #[inline]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.capacity
    }
    
    /// Check if pool is empty (should never happen)
    #[inline]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.capacity == 0
    }
}

// Thread-safe: KeyPool can be shared across threads
unsafe impl Send for KeyPool {}
unsafe impl Sync for KeyPool {}

// ============================================================================
// UNIT TESTS - Critical for correctness verification
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    /// Test that all generated keys are valid
    #[test]
    fn test_all_keys_valid() {
        const POOL_SIZE: usize = 100;
        const MAX_OFFSET: u64 = 10_000_000;
        
        let pool = KeyPool::new(POOL_SIZE, MAX_OFFSET);
        
        // Pool should have generated all keys
        assert_eq!(pool.len(), POOL_SIZE, "Pool should have {} keys", POOL_SIZE);
        
        // Check each key is valid
        for i in 0..POOL_SIZE {
            let key = pool.next();
            assert!(is_valid_private_key(&key), 
                "Key at index {} is invalid: {}", i, hex::encode(&key));
        }
    }
    
    /// Test that key + max_offset doesn't overflow
    #[test]
    fn test_key_plus_offset_valid() {
        const POOL_SIZE: usize = 50;
        const MAX_OFFSET: u64 = 8_000_000; // Typical keys_per_batch
        
        let pool = KeyPool::new(POOL_SIZE, MAX_OFFSET);
        
        for i in 0..POOL_SIZE {
            let key = pool.next();
            
            // Simulate GPU adding max_offset to key
            let mut test_key = key;
            let mut carry = MAX_OFFSET;
            for byte in test_key.iter_mut().rev() {
                let sum = *byte as u64 + (carry & 0xFF);
                *byte = sum as u8;
                carry = (carry >> 8) + (sum >> 8);
            }
            
            // No overflow should occur
            assert_eq!(carry, 0, 
                "Key {} + offset {} caused overflow", hex::encode(&key), MAX_OFFSET);
            
            // Result should still be valid
            assert!(is_valid_private_key(&test_key),
                "Key {} + offset {} is invalid", hex::encode(&key), MAX_OFFSET);
        }
    }
    
    /// Test wrap-around behavior
    #[test]
    fn test_wraparound() {
        const POOL_SIZE: usize = 10;
        const MAX_OFFSET: u64 = 1_000_000;
        
        let pool = KeyPool::new(POOL_SIZE, MAX_OFFSET);
        
        // Get first key
        let first_key = pool.next();
        
        // Consume rest of pool
        for _ in 1..POOL_SIZE {
            pool.next();
        }
        
        // Should wrap around and return first key again
        let wrapped_key = pool.next();
        assert_eq!(first_key, wrapped_key, "Wrap-around should return first key");
    }
    
    /// Test concurrent access
    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;
        
        const POOL_SIZE: usize = 100;
        const MAX_OFFSET: u64 = 1_000_000;
        const THREADS: usize = 4;
        const KEYS_PER_THREAD: usize = 50;
        
        let pool = Arc::new(KeyPool::new(POOL_SIZE, MAX_OFFSET));
        let mut handles = vec![];
        
        for _ in 0..THREADS {
            let pool_clone = pool.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..KEYS_PER_THREAD {
                    let key = pool_clone.next();
                    assert!(is_valid_private_key(&key), "Invalid key from concurrent access");
                }
            }));
        }
        
        for h in handles {
            h.join().expect("Thread panicked");
        }
    }
}


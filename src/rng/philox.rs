// src/rng/philox.rs
// Philox4x32-10 - Counter-based cryptographic RNG
// Reference: "Parallel Random Numbers: As Easy as 1, 2, 3" (Salmon et al., 2011)

use std::sync::atomic::{AtomicU64, Ordering};

/// Philox4x32 constants (maximally equidistributed)
const PHILOX_M0: u32 = 0xD2511F53;
const PHILOX_M1: u32 = 0xCD9E8D57;
const PHILOX_W0: u32 = 0x9E3779B9; // Golden ratio constant
const PHILOX_W1: u32 = 0xBB67AE85; // sqrt(3) - 1

/// Philox state: 128-bit counter + 64-bit key
#[derive(Clone, Copy, Debug)]
pub struct PhiloxState {
    pub counter: [u32; 4],
    pub key: [u32; 2],
}

impl PhiloxState {
    /// Create new state from seed
    pub fn new(seed: u64) -> Self {
        Self {
            counter: [0, 0, 0, 0],
            key: [(seed & 0xFFFFFFFF) as u32, (seed >> 32) as u32],
        }
    }
    
    /// Create state for specific thread/key offset from base state
    /// This matches GPU's philox_for_thread() exactly!
    pub fn for_thread(&self, thread_id: u32) -> Self {
        let mut state = *self;
        // 128-bit counter + thread_id (same as GPU Metal shader)
        let sum = (state.counter[0] as u64) + (thread_id as u64);
        state.counter[0] = sum as u32;
        
        let mut carry = sum >> 32;
        if carry > 0 {
            let sum1 = (state.counter[1] as u64) + carry;
            state.counter[1] = sum1 as u32;
            carry = sum1 >> 32;
        }
        if carry > 0 {
            let sum2 = (state.counter[2] as u64) + carry;
            state.counter[2] = sum2 as u32;
            carry = sum2 >> 32;
        }
        if carry > 0 {
            state.counter[3] = state.counter[3].wrapping_add(carry as u32);
        }
        
        state
    }
    
    /// Increment counter (for next batch)
    /// Returns true if increment succeeded, false if 128-bit overflow occurred
    /// 
    /// CRITICAL: Proper carry propagation prevents key space collision
    /// Without this, after ~2^32 batches the counter would wrap silently
    /// causing the same keys to be generated again!
    pub fn increment(&mut self, amount: u64) -> bool {
        // Use wrapping_add to handle overflow explicitly
        let low = (self.counter[0] as u64).wrapping_add(amount);
        self.counter[0] = low as u32;
        
        // Propagate carry through all 128 bits
        if low > u32::MAX as u64 {
            let carry = low >> 32;
            return self.increment_with_carry(1, carry);
        }
        true
    }
    
    /// Internal helper: propagate carry through counter[start_idx..4]
    /// Returns false if 128-bit overflow occurred (counter wrapped around)
    fn increment_with_carry(&mut self, start_idx: usize, mut carry: u64) -> bool {
        for i in start_idx..4 {
            if carry == 0 {
                return true; // No more carry, done
            }
            
            let sum = (self.counter[i] as u64).wrapping_add(carry);
            self.counter[i] = sum as u32;
            carry = sum >> 32;
        }
        
        // If carry is still non-zero after processing all words,
        // we've overflowed the full 128-bit counter
        carry == 0
    }
}

/// Philox round function (single step)
#[inline]
fn philox_round(mut ctr: [u32; 4], key: [u32; 2]) -> [u32; 4] {
    // Multiply-high and multiply-low
    let prod0 = (ctr[0] as u64) * (PHILOX_M0 as u64);
    let prod1 = (ctr[2] as u64) * (PHILOX_M1 as u64);
    
    // Mix high and low parts
    ctr[0] = (prod1 >> 32) as u32 ^ ctr[1] ^ key[0];
    ctr[1] = prod1 as u32;
    ctr[2] = (prod0 >> 32) as u32 ^ ctr[3] ^ key[1];
    ctr[3] = prod0 as u32;
    
    ctr
}

/// Full Philox4x32-10 (10 rounds for cryptographic strength)
pub fn philox4x32_10(state: &PhiloxState) -> [u32; 4] {
    let mut ctr = state.counter;
    let mut key = state.key;
    
    // 10 rounds with key schedule
    for _ in 0..10 {
        ctr = philox_round(ctr, key);
        // Key schedule: k = k + W
        key[0] = key[0].wrapping_add(PHILOX_W0);
        key[1] = key[1].wrapping_add(PHILOX_W1);
    }
    
    ctr
}

/// Convert Philox output to 256-bit private key
pub fn philox_to_privkey(state: &PhiloxState) -> [u8; 32] {
    let random = philox4x32_10(state);
    
    let mut key = [0u8; 32];
    
    // First 128 bits from Philox output
    key[0..4].copy_from_slice(&random[0].to_be_bytes());
    key[4..8].copy_from_slice(&random[1].to_be_bytes());
    key[8..12].copy_from_slice(&random[2].to_be_bytes());
    key[12..16].copy_from_slice(&random[3].to_be_bytes());
    
    // Second 128 bits: hash the output for more entropy
    let mut state2 = *state;
    state2.counter[0] ^= 0xDEADBEEF; // Domain separation
    let random2 = philox4x32_10(&state2);
    
    key[16..20].copy_from_slice(&random2[0].to_be_bytes());
    key[20..24].copy_from_slice(&random2[1].to_be_bytes());
    key[24..28].copy_from_slice(&random2[2].to_be_bytes());
    key[28..32].copy_from_slice(&random2[3].to_be_bytes());
    
    key
}

/// Global counter for GPU batches
pub struct PhiloxCounter {
    counter: AtomicU64,
    base_seed: u64,
}

impl PhiloxCounter {
    pub fn new(seed: u64) -> Self {
        Self {
            counter: AtomicU64::new(0),
            base_seed: seed,
        }
    }
    
    /// Get state for next GPU batch
    /// 
    /// Handles overflow gracefully:
    /// - 64-bit overflow: Logs warning, wraps around (realistic edge case after 18.4 exakeys)
    /// - 128-bit overflow: Logs critical error, wraps around (astronomically unlikely)
    pub fn next_batch(&self, batch_size: u64) -> PhiloxState {
        let counter_val = self.counter.fetch_add(batch_size, Ordering::Relaxed);
        let mut state = PhiloxState::new(self.base_seed);
        
        // Check for 64-bit overflow first (more likely than 128-bit)
        if counter_val.checked_add(batch_size).is_none() {
            eprintln!("[WARN] Philox 64-bit counter overflow! Wrapping around.");
            // Fallback: wrap around and continue
            let wrapped = counter_val.wrapping_add(batch_size);
            state.counter[0] = wrapped as u32;
            state.counter[1] = (wrapped >> 32) as u32;
            return state;
        }
        
        // Check for 128-bit overflow (astronomically unlikely)
        if !state.increment(counter_val) {
            eprintln!("[CRITICAL] Philox 128-bit counter overflow! 2^128 keys scanned. Wrapping around.");
            // Instead of panic, wrap around - better to continue scanning than crash
            state.counter = [0, 0, 0, 0];
        }
        state
    }
    
    pub fn total_generated(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_philox_deterministic() {
        let state1 = PhiloxState::new(12345);
        let state2 = PhiloxState::new(12345);
        
        let out1 = philox4x32_10(&state1);
        let out2 = philox4x32_10(&state2);
        
        assert_eq!(out1, out2, "Same seed should give same output");
    }
    
    #[test]
    fn test_philox_different_seeds() {
        let state1 = PhiloxState::new(12345);
        let state2 = PhiloxState::new(54321);
        
        let out1 = philox4x32_10(&state1);
        let out2 = philox4x32_10(&state2);
        
        assert_ne!(out1, out2, "Different seeds should give different output");
    }
    
    #[test]
    fn test_counter_increment() {
        let mut state = PhiloxState::new(1);
        let out1 = philox4x32_10(&state);
        
        state.increment(1);
        let out2 = philox4x32_10(&state);
        
        assert_ne!(out1, out2, "Incrementing counter should change output");
    }
    
    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;
        
        let counter = Arc::new(PhiloxCounter::new(42));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let counter_clone = counter.clone();
                thread::spawn(move || {
                    for _ in 0..1000 {
                        let _state = counter_clone.next_batch(128);
                    }
                })
            })
            .collect();
        
        for t in threads {
            t.join().unwrap();
        }
        
        assert_eq!(counter.total_generated(), 8 * 1000 * 128);
    }
    
    #[test]
    fn test_privkey_validity() {
        use crate::crypto::is_valid_private_key;
        
        let state = PhiloxState::new(9999);
        let key = philox_to_privkey(&state);
        
        // Should be valid secp256k1 key
        assert!(is_valid_private_key(&key), "Generated key should be valid");
        
        // Should not be zero
        assert_ne!(key, [0u8; 32], "Key should not be zero");
    }
    
    #[test]
    fn test_known_vector() {
        // Test against reference implementation
        // From Philox paper: seed=0, counter=0 → known output
        let state = PhiloxState::new(0);
        let output = philox4x32_10(&state);
        
        // These values are from the original Philox paper
        // (verifies our implementation matches reference)
        let expected = [0x6627_e8d5, 0xe169_c58d, 0xbc57_ac4c, 0x9b00_dbd8];
        
        assert_eq!(output, expected, "Should match reference Philox output");
    }
    
    #[test]
    fn test_for_thread_matches_gpu() {
        // CRITICAL: Verify for_thread() matches GPU's philox_for_thread()
        // GPU code:
        //   ulong sum = (ulong)base_counter->x + (ulong)thread_id;
        //   state.counter.x = (uint)sum;
        //   ulong carry = sum >> 32;
        //   ... (propagate carry through y, z, w)
        
        let base_state = PhiloxState {
            counter: [1000, 5, 0, 0],
            key: [0x12345678, 0x9ABCDEF0],
        };
        
        // Test various thread_ids
        for thread_id in [0u32, 1, 100, 1000, 0xFFFFFFFF] {
            let thread_state = base_state.for_thread(thread_id);
            
            // Manually compute expected counter (GPU algorithm)
            let sum0 = (base_state.counter[0] as u64) + (thread_id as u64);
            let expected_c0 = sum0 as u32;
            let carry0 = sum0 >> 32;
            
            let sum1 = (base_state.counter[1] as u64) + carry0;
            let expected_c1 = sum1 as u32;
            let carry1 = sum1 >> 32;
            
            let sum2 = (base_state.counter[2] as u64) + carry1;
            let expected_c2 = sum2 as u32;
            let carry2 = sum2 >> 32;
            
            let expected_c3 = base_state.counter[3].wrapping_add(carry2 as u32);
            
            assert_eq!(thread_state.counter[0], expected_c0, 
                "counter[0] mismatch for thread_id={}", thread_id);
            assert_eq!(thread_state.counter[1], expected_c1, 
                "counter[1] mismatch for thread_id={}", thread_id);
            assert_eq!(thread_state.counter[2], expected_c2, 
                "counter[2] mismatch for thread_id={}", thread_id);
            assert_eq!(thread_state.counter[3], expected_c3, 
                "counter[3] mismatch for thread_id={}", thread_id);
            
            // Key should be unchanged
            assert_eq!(thread_state.key, base_state.key, 
                "key should be unchanged for thread_id={}", thread_id);
        }
    }
    
    #[test]
    fn test_for_thread_overflow_handling() {
        // Test 128-bit overflow propagation
        // This is critical for GPU/CPU sync!
        
        // Case 1: Overflow in counter[0]
        let state1 = PhiloxState {
            counter: [0xFFFFFFFF, 0, 0, 0],
            key: [1, 2],
        };
        let result1 = state1.for_thread(2);
        assert_eq!(result1.counter, [1, 1, 0, 0], 
            "Overflow should propagate from counter[0] to counter[1]");
        
        // Case 2: Cascade overflow
        let state2 = PhiloxState {
            counter: [0xFFFFFFFF, 0xFFFFFFFF, 0, 0],
            key: [1, 2],
        };
        let result2 = state2.for_thread(1);
        assert_eq!(result2.counter, [0, 0, 1, 0], 
            "Cascade overflow should propagate through counter[1] to counter[2]");
        
        // Case 3: Full cascade
        let state3 = PhiloxState {
            counter: [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0],
            key: [1, 2],
        };
        let result3 = state3.for_thread(1);
        assert_eq!(result3.counter, [0, 0, 0, 1], 
            "Full cascade should reach counter[3]");
    }
    
    #[test]
    fn test_thread_keys_unique() {
        // Verify different threads produce different keys
        let base_state = PhiloxState::new(42);
        
        let key0 = philox_to_privkey(&base_state.for_thread(0));
        let key1 = philox_to_privkey(&base_state.for_thread(1));
        let key100 = philox_to_privkey(&base_state.for_thread(100));
        
        assert_ne!(key0, key1, "Thread 0 and 1 should have different keys");
        assert_ne!(key0, key100, "Thread 0 and 100 should have different keys");
        assert_ne!(key1, key100, "Thread 1 and 100 should have different keys");
    }
}


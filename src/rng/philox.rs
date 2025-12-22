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
    
    /// Increment counter (for next batch)
    pub fn increment(&mut self, amount: u64) {
        let low = self.counter[0] as u64 + amount;
        self.counter[0] = low as u32;
        let carry = low >> 32;
        
        if carry > 0 {
            let mid = self.counter[1] as u64 + carry;
            self.counter[1] = mid as u32;
            let carry2 = mid >> 32;
            
            if carry2 > 0 {
                let high = self.counter[2] as u64 + carry2;
                self.counter[2] = high as u32;
                self.counter[3] = self.counter[3].wrapping_add((high >> 32) as u32);
            }
        }
    }
    
    /// Generate thread-specific state (for GPU)
    pub fn for_thread(&self, thread_id: u64) -> Self {
        let mut state = *self;
        state.increment(thread_id);
        state
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
    pub fn next_batch(&self, batch_size: u64) -> PhiloxState {
        let counter_val = self.counter.fetch_add(batch_size, Ordering::Relaxed);
        let mut state = PhiloxState::new(self.base_seed);
        state.increment(counter_val);
        state
    }
    
    /// Get total keys generated
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
}


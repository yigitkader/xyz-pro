use std::sync::atomic::{AtomicU64, Ordering};

const PHILOX_M0: u32 = 0xD2511F53;
const PHILOX_M1: u32 = 0xCD9E8D57;
const PHILOX_W0: u32 = 0x9E3779B9;
const PHILOX_W1: u32 = 0xBB67AE85;

#[derive(Clone, Copy, Debug)]
pub struct PhiloxState {
    pub counter: [u32; 4],
    pub key: [u32; 2],
}

impl PhiloxState {
    pub fn new(seed: u64) -> Self {
        Self {
            counter: [0, 0, 0, 0],
            key: [(seed & 0xFFFFFFFF) as u32, (seed >> 32) as u32],
        }
    }
    
    pub fn for_thread(&self, thread_id: u32) -> Self {
        let mut state = *self;
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
    
    pub fn increment(&mut self, amount: u64) -> bool {
        let low = (self.counter[0] as u64).wrapping_add(amount);
        self.counter[0] = low as u32;
        
        if low > u32::MAX as u64 {
            let carry = low >> 32;
            return self.increment_with_carry(1, carry);
        }
        true
    }
    
    fn increment_with_carry(&mut self, start_idx: usize, mut carry: u64) -> bool {
        for i in start_idx..4 {
            if carry == 0 {
                return true;
            }
            let sum = (self.counter[i] as u64).wrapping_add(carry);
            self.counter[i] = sum as u32;
            carry = sum >> 32;
        }
        carry == 0
    }
}

#[inline]
fn philox_round(mut ctr: [u32; 4], key: [u32; 2]) -> [u32; 4] {
    let prod0 = (ctr[0] as u64) * (PHILOX_M0 as u64);
    let prod1 = (ctr[2] as u64) * (PHILOX_M1 as u64);
    
    ctr[0] = (prod1 >> 32) as u32 ^ ctr[1] ^ key[0];
    ctr[1] = prod1 as u32;
    ctr[2] = (prod0 >> 32) as u32 ^ ctr[3] ^ key[1];
    ctr[3] = prod0 as u32;
    ctr
}

pub fn philox4x32_10(state: &PhiloxState) -> [u32; 4] {
    let mut ctr = state.counter;
    let mut key = state.key;
    
    for _ in 0..10 {
        ctr = philox_round(ctr, key);
        key[0] = key[0].wrapping_add(PHILOX_W0);
        key[1] = key[1].wrapping_add(PHILOX_W1);
    }
    ctr
}

pub fn philox_to_privkey(state: &PhiloxState) -> [u8; 32] {
    let random = philox4x32_10(state);
    let mut key = [0u8; 32];
    
    key[0..4].copy_from_slice(&random[0].to_be_bytes());
    key[4..8].copy_from_slice(&random[1].to_be_bytes());
    key[8..12].copy_from_slice(&random[2].to_be_bytes());
    key[12..16].copy_from_slice(&random[3].to_be_bytes());
    
    let mut state2 = *state;
    state2.counter[0] ^= 0xDEADBEEF;
    let random2 = philox4x32_10(&state2);
    
    key[16..20].copy_from_slice(&random2[0].to_be_bytes());
    key[20..24].copy_from_slice(&random2[1].to_be_bytes());
    key[24..28].copy_from_slice(&random2[2].to_be_bytes());
    key[28..32].copy_from_slice(&random2[3].to_be_bytes());
    key
}

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
    
    pub fn next_batch(&self, batch_size: u64) -> PhiloxState {
        let counter_val = self.counter.fetch_add(batch_size, Ordering::Relaxed);
        let mut state = PhiloxState::new(self.base_seed);
        
        if counter_val.checked_add(batch_size).is_none() {
            eprintln!("[WARN] Philox 64-bit counter overflow!");
            let wrapped = counter_val.wrapping_add(batch_size);
            state.counter[0] = wrapped as u32;
            state.counter[1] = (wrapped >> 32) as u32;
            return state;
        }
        
        if !state.increment(counter_val) {
            eprintln!("[CRITICAL] Philox 128-bit counter overflow!");
            state.counter = [0, 0, 0, 0];
        }
        state
    }
    
    #[allow(dead_code)]
    pub fn total_generated(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_philox_deterministic() {
        let out1 = philox4x32_10(&PhiloxState::new(12345));
        let out2 = philox4x32_10(&PhiloxState::new(12345));
        assert_eq!(out1, out2);
    }
    
    #[test]
    fn test_philox_different_seeds() {
        let out1 = philox4x32_10(&PhiloxState::new(12345));
        let out2 = philox4x32_10(&PhiloxState::new(54321));
        assert_ne!(out1, out2);
    }
    
    #[test]
    fn test_counter_increment() {
        let mut state = PhiloxState::new(1);
        let out1 = philox4x32_10(&state);
        state.increment(1);
        let out2 = philox4x32_10(&state);
        assert_ne!(out1, out2);
    }
    
    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;
        
        let counter = Arc::new(PhiloxCounter::new(42));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let c = counter.clone();
                thread::spawn(move || {
                    for _ in 0..1000 {
                        c.next_batch(128);
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
        let key = philox_to_privkey(&PhiloxState::new(9999));
        assert!(is_valid_private_key(&key));
        assert_ne!(key, [0u8; 32]);
    }
    
    #[test]
    fn test_known_vector() {
        let output = philox4x32_10(&PhiloxState::new(0));
        assert_eq!(output, [0x6627_e8d5, 0xe169_c58d, 0xbc57_ac4c, 0x9b00_dbd8]);
    }
    
    #[test]
    fn test_for_thread_matches_gpu() {
        let base = PhiloxState { counter: [1000, 5, 0, 0], key: [0x12345678, 0x9ABCDEF0] };
        
        for tid in [0u32, 1, 100, 1000, 0xFFFFFFFF] {
            let result = base.for_thread(tid);
            
            let sum0 = (base.counter[0] as u64) + (tid as u64);
            let c0 = sum0 as u32;
            let carry0 = sum0 >> 32;
            
            let sum1 = (base.counter[1] as u64) + carry0;
            let c1 = sum1 as u32;
            let carry1 = sum1 >> 32;
            
            let sum2 = (base.counter[2] as u64) + carry1;
            let c2 = sum2 as u32;
            let carry2 = sum2 >> 32;
            
            let c3 = base.counter[3].wrapping_add(carry2 as u32);
            
            assert_eq!(result.counter, [c0, c1, c2, c3]);
            assert_eq!(result.key, base.key);
        }
    }
    
    #[test]
    fn test_for_thread_overflow() {
        let s1 = PhiloxState { counter: [0xFFFFFFFF, 0, 0, 0], key: [1, 2] };
        assert_eq!(s1.for_thread(2).counter, [1, 1, 0, 0]);
        
        let s2 = PhiloxState { counter: [0xFFFFFFFF, 0xFFFFFFFF, 0, 0], key: [1, 2] };
        assert_eq!(s2.for_thread(1).counter, [0, 0, 1, 0]);
        
        let s3 = PhiloxState { counter: [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0], key: [1, 2] };
        assert_eq!(s3.for_thread(1).counter, [0, 0, 0, 1]);
    }
    
    #[test]
    fn test_thread_keys_unique() {
        let base = PhiloxState::new(42);
        let k0 = philox_to_privkey(&base.for_thread(0));
        let k1 = philox_to_privkey(&base.for_thread(1));
        let k100 = philox_to_privkey(&base.for_thread(100));
        
        assert_ne!(k0, k1);
        assert_ne!(k0, k100);
        assert_ne!(k1, k100);
    }
}

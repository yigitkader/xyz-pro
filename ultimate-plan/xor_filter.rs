// src/filter/xor_filter.rs
// Xor Filter: Space-efficient probabilistic data structure
// O(1) lookup, ~14 bits/element, <0.4% false positive rate

use std::hash::{Hash, Hasher};
use fxhash::FxHasher;

/// Xor16 filter optimized for GPU
/// Uses 16-bit fingerprints for balance between size and FP rate
pub struct XorFilter16 {
    /// Fingerprint table (3x larger than input set)
    fingerprints: Vec<u16>,
    /// Seeds for 3 hash functions
    seeds: [u64; 3],
    /// Block size for construction
    block_length: usize,
}

impl XorFilter16 {
    /// Construct Xor filter from hash set
    /// targets: 20-byte hash160 values
    pub fn new(targets: &[[u8; 20]]) -> Self {
        let size = targets.len();
        let capacity = Self::calculate_capacity(size);
        let block_length = capacity / 3;
        
        println!("[Xor] Building filter for {} targets...", size);
        println!("[Xor] Capacity: {} (3 × {} blocks)", capacity, block_length);
        
        // Generate hash seeds (deterministic but pseudo-random)
        let seeds = [0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xAAAAAAAA55555555];
        
        // Initialize fingerprint table
        let mut fingerprints = vec![0u16; capacity];
        
        // Build Xor filter using Dietzfelbinger construction
        Self::construct_filter(targets, &mut fingerprints, block_length, &seeds);
        
        println!("[Xor] Filter built: {:.1} MB", 
            (fingerprints.len() * 2) as f64 / 1_000_000.0);
        
        Self {
            fingerprints,
            seeds,
            block_length,
        }
    }
    
    /// Calculate optimal capacity (must be divisible by 3)
    fn calculate_capacity(size: usize) -> usize {
        // Xor filter needs 1.23x space overhead minimum
        let min_capacity = ((size as f64) * 1.23) as usize;
        // Round up to multiple of 3
        ((min_capacity + 2) / 3) * 3
    }
    
    /// Construct filter using Dietzfelbinger algorithm
    fn construct_filter(
        targets: &[[u8; 20]],
        fingerprints: &mut [u16],
        block_length: usize,
        seeds: &[u64; 3],
    ) {
        // Mapping phase: assign each key to 3 positions
        let mut sets: Vec<Vec<usize>> = vec![Vec::new(); fingerprints.len()];
        let mut key_fingerprints = Vec::with_capacity(targets.len());
        
        for (idx, hash) in targets.iter().enumerate() {
            let fp = Self::compute_fingerprint(hash);
            key_fingerprints.push(fp);
            
            let (h0, h1, h2) = Self::hash_triple(hash, seeds, block_length);
            sets[h0].push(idx);
            sets[h1].push(idx);
            sets[h2].push(idx);
        }
        
        // Peeling phase: find order to assign fingerprints
        let mut queue: Vec<usize> = Vec::new();
        let mut alone = vec![false; fingerprints.len()];
        
        // Find singleton sets
        for (pos, set) in sets.iter().enumerate() {
            if set.len() == 1 {
                alone[pos] = true;
                queue.push(pos);
            }
        }
        
        // Peel the graph
        let mut assignments = vec![None; targets.len()];
        
        while let Some(pos) = queue.pop() {
            if sets[pos].len() != 1 {
                continue;
            }
            
            let key_idx = sets[pos][0];
            assignments[key_idx] = Some(pos);
            
            // Remove this key from all its sets
            let hash = &targets[key_idx];
            let (h0, h1, h2) = Self::hash_triple(hash, seeds, block_length);
            
            for &h in &[h0, h1, h2] {
                if h == pos {
                    continue;
                }
                
                sets[h].retain(|&x| x != key_idx);
                
                if sets[h].len() == 1 && !alone[h] {
                    alone[h] = true;
                    queue.push(h);
                }
            }
        }
        
        // Assignment phase: compute fingerprints
        for (key_idx, &maybe_pos) in assignments.iter().enumerate() {
            if let Some(assigned_pos) = maybe_pos {
                let hash = &targets[key_idx];
                let fp = key_fingerprints[key_idx];
                let (h0, h1, h2) = Self::hash_triple(hash, seeds, block_length);
                
                // XOR all three positions
                let xor_val = fingerprints[h0] ^ fingerprints[h1] ^ fingerprints[h2];
                fingerprints[assigned_pos] = xor_val ^ fp;
            }
        }
    }
    
    /// Hash to 3 positions (one per block)
    fn hash_triple(hash: &[u8; 20], seeds: &[u64; 3], block_length: usize) -> (usize, usize, usize) {
        let h0 = Self::hash_to_range(hash, seeds[0], block_length, 0);
        let h1 = Self::hash_to_range(hash, seeds[1], block_length, 1);
        let h2 = Self::hash_to_range(hash, seeds[2], block_length, 2);
        (h0, h1, h2)
    }
    
    /// Hash to specific block range
    fn hash_to_range(hash: &[u8; 20], seed: u64, block_length: usize, block: usize) -> usize {
        let mut hasher = FxHasher::default();
        hasher.write_u64(seed);
        hasher.write(hash);
        let h = hasher.finish();
        
        let pos = (h as usize) % block_length;
        block * block_length + pos
    }
    
    /// Compute 16-bit fingerprint
    fn compute_fingerprint(hash: &[u8; 20]) -> u16 {
        let mut hasher = FxHasher::default();
        hasher.write(hash);
        (hasher.finish() >> 48) as u16  // Top 16 bits
    }
    
    /// Check if hash is in filter (may have false positives)
    pub fn contains(&self, hash: &[u8; 20]) -> bool {
        let fp = Self::compute_fingerprint(hash);
        let (h0, h1, h2) = Self::hash_triple(hash, &self.seeds, self.block_length);
        
        let xor_val = self.fingerprints[h0] ^ self.fingerprints[h1] ^ self.fingerprints[h2];
        xor_val == fp
    }
    
    /// Get GPU-compatible data (fingerprints + metadata)
    pub fn gpu_data(&self) -> (&[u16], [u64; 3], u32) {
        (&self.fingerprints, self.seeds, self.block_length as u32)
    }
    
    /// Memory usage in bytes
    pub fn memory_bytes(&self) -> usize {
        self.fingerprints.len() * 2 + 24 + 4  // fingerprints + seeds + block_length
    }
    
    /// Bits per element (ideal: 14-15 for Xor16)
    pub fn bits_per_element(&self, num_keys: usize) -> f64 {
        (self.memory_bytes() * 8) as f64 / num_keys as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    
    fn random_hash() -> [u8; 20] {
        let mut rng = rand::thread_rng();
        let mut h = [0u8; 20];
        rng.fill(&mut h);
        h
    }
    
    #[test]
    fn test_xor_filter_basic() {
        let mut targets = Vec::new();
        for _ in 0..1000 {
            targets.push(random_hash());
        }
        
        let filter = XorFilter16::new(&targets);
        
        // All inserted keys should be found
        for hash in &targets {
            assert!(filter.contains(hash), "Inserted key should be found");
        }
    }
    
    #[test]
    fn test_false_positive_rate() {
        let mut targets = Vec::new();
        for _ in 0..10_000 {
            targets.push(random_hash());
        }
        
        let filter = XorFilter16::new(&targets);
        
        // Test 100k random non-member keys
        let mut false_positives = 0;
        for _ in 0..100_000 {
            let random = random_hash();
            if !targets.contains(&random) && filter.contains(&random) {
                false_positives += 1;
            }
        }
        
        let fp_rate = false_positives as f64 / 100_000.0;
        println!("False positive rate: {:.2}%", fp_rate * 100.0);
        
        // Xor16 should have <0.4% FP rate
        assert!(fp_rate < 0.004, "FP rate too high: {:.2}%", fp_rate * 100.0);
    }
    
    #[test]
    fn test_memory_efficiency() {
        let sizes = [1_000, 10_000, 100_000, 1_000_000];
        
        for &size in &sizes {
            let mut targets = Vec::new();
            for _ in 0..size {
                targets.push(random_hash());
            }
            
            let filter = XorFilter16::new(&targets);
            let bits_per_elem = filter.bits_per_element(size);
            
            println!("Size {}: {:.2} bits/element", size, bits_per_elem);
            
            // Should be around 14-15 bits/element (Xor filter optimal)
            assert!(bits_per_elem < 16.0, "Too much space: {:.2} bits/elem", bits_per_elem);
        }
    }
    
    #[test]
    fn test_large_set() {
        // Test with 50M-like scenario (scaled down)
        let size = 100_000;
        let mut targets = Vec::new();
        
        for i in 0..size {
            let mut h = [0u8; 20];
            h[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            targets.push(h);
        }
        
        let filter = XorFilter16::new(&targets);
        
        // Verify all targets found
        let mut missing = 0;
        for hash in &targets {
            if !filter.contains(hash) {
                missing += 1;
            }
        }
        
        assert_eq!(missing, 0, "Should have zero false negatives");
        
        println!("Large set: {} MB for {} keys", 
            filter.memory_bytes() / 1_000_000,
            size);
    }
}
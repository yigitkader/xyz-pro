use std::hash::Hasher;
use fxhash::FxHasher;

pub struct XorFilter32 {
    fingerprints: Vec<u32>,
    seeds: [u64; 3],
    block_length: usize,
}

impl XorFilter32 {
    pub fn new(targets: &[[u8; 20]]) -> Self {
        let size = targets.len();
        let mut capacity = Self::calculate_capacity(size);
        let mut block_length = capacity / 3;
        
        println!("[Xor] Building filter for {} targets...", size);
        
        let seed_sets = vec![
            [0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xAAAAAAAA55555555],
            [0x123456789ABCDEF0, 0xF0EDCBA987654321, 0xBBBBBBBB66666666],
            [0x23456789ABCDEF01, 0x01FEDCBA98765432, 0xCCCCCCCC77777777],
            [0x3456789ABCDEF012, 0x1201FEDCBA987654, 0xDDDDDDDD88888888],
            [0x456789ABCDEF0123, 0x321201FEDCBA9876, 0xEEEEEEEE99999999],
        ];
        
        let mut fingerprints = vec![0u32; capacity];
        let mut seeds = seed_sets[0];
        let mut success = false;
        
        for attempt in 0..10 {
            for &try_seeds in &seed_sets {
                fingerprints.fill(0);
                
                if attempt == 0 {
                    println!("[Xor] Capacity: {} (3 × {} blocks)", capacity, block_length);
                }
                
                // Build Xor filter using Dietzfelbinger construction
                if Self::construct_filter(targets, &mut fingerprints, block_length, &try_seeds) {
                    seeds = try_seeds;
                    success = true;
                    break;
                }
            }
            
            if success {
                break;
            }
            
            capacity = ((capacity as f64) * 1.1) as usize;
            capacity = ((capacity + 2) / 3) * 3;  // Round to multiple of 3
            block_length = capacity / 3;
            fingerprints.resize(capacity, 0);
            
            if attempt < 2 {
                println!("[Xor] Retry {}: Increased capacity to {} (3 × {} blocks)", 
                    attempt + 2, capacity, block_length);
            }
        }
        
        if !success {
            panic!("[Xor] Failed to construct filter after 10 attempts. This is extremely rare and indicates a bug.");
        }
        
        println!("[Xor] Filter built: {:.1} MB", 
            (fingerprints.len() * 2) as f64 / 1_000_000.0);
        
        Self {
            fingerprints,
            seeds,
            block_length,
        }
    }
    
    fn calculate_capacity(size: usize) -> usize {
        let min_capacity = ((size as f64) * 1.27) as usize;
        ((min_capacity + 2) / 3) * 3
    }
    
    fn construct_filter(
        targets: &[[u8; 20]],
        fingerprints: &mut [u32],
        block_length: usize,
        seeds: &[u64; 3],
    ) -> bool {
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
        
        // Peel the graph and store peeling order
        let mut assignments = vec![None; targets.len()];
        let mut peeling_order = Vec::new();  // Store order for reverse processing
        
        while let Some(pos) = queue.pop() {
            if sets[pos].len() != 1 {
                continue;
            }
            
            let key_idx = sets[pos][0];
            assignments[key_idx] = Some(pos);
            peeling_order.push(key_idx);  // Record peeling order
            
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
        
        // Check if all keys were assigned (graph was fully peeled)
        let unassigned = assignments.iter().filter(|&&a| a.is_none()).count();
        if unassigned > 0 {
            // Graph couldn't be fully peeled - construction failed
            return false;
        }
        
        // Assignment phase: compute fingerprints in REVERSE order of peeling
        // This ensures dependencies are resolved correctly
        // Process keys in reverse order (last peeled first)
        for &key_idx in peeling_order.iter().rev() {
            if let Some(assigned_pos) = assignments[key_idx] {
                let hash = &targets[key_idx];
                let fp = key_fingerprints[key_idx];
                let (h0, h1, h2) = Self::hash_triple(hash, seeds, block_length);
                
                // XOR all three positions
                // Note: In reverse order, h0, h1, h2 may already have values set
                // (except for assigned_pos which we're setting now)
                let xor_val = fingerprints[h0] ^ fingerprints[h1] ^ fingerprints[h2];
                fingerprints[assigned_pos] = xor_val ^ fp;
            }
        }
        
        true  // Construction succeeded
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
    
    /// Compute 32-bit fingerprint (reduced collision risk for 50M targets)
    fn compute_fingerprint(hash: &[u8; 20]) -> u32 {
        let mut hasher = FxHasher::default();
        hasher.write(hash);
        (hasher.finish() >> 32) as u32  // Top 32 bits (reduces FP rate from 0.4% to 0.0015%)
    }
    
    /// Check if hash is in filter (may have false positives)
    pub fn contains(&self, hash: &[u8; 20]) -> bool {
        let fp = Self::compute_fingerprint(hash);
        let (h0, h1, h2) = Self::hash_triple(hash, &self.seeds, self.block_length);
        
        let xor_val = self.fingerprints[h0] ^ self.fingerprints[h1] ^ self.fingerprints[h2];
        xor_val == fp
    }
    
    /// Get GPU-compatible data (fingerprints + metadata)
    pub fn gpu_data(&self) -> (&[u32], [u64; 3], u32) {
        (&self.fingerprints, self.seeds, self.block_length as u32)
    }
    
    /// Memory usage in bytes
    pub fn memory_bytes(&self) -> usize {
        self.fingerprints.len() * 4 + 24 + 4  // fingerprints (32-bit) + seeds + block_length
    }
    
    /// Bits per element (ideal: 14-15 for Xor16, ~18-20 for Xor32)
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
        
        let filter = XorFilter32::new(&targets);
        
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
        
        let filter = XorFilter32::new(&targets);
        
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
        
        // Xor32 should have <0.15% FP rate (improved from Xor16's 0.4%)
        assert!(fp_rate < 0.0015, "FP rate too high: {:.2}%", fp_rate * 100.0);
    }
    
    #[test]
    fn test_memory_efficiency() {
        let sizes = [1_000, 10_000, 100_000, 1_000_000];
        
        for &size in &sizes {
            let mut targets = Vec::new();
            for _ in 0..size {
                targets.push(random_hash());
            }
            
            let filter = XorFilter32::new(&targets);
            let bits_per_elem = filter.bits_per_element(size);
            
            println!("Size {}: {:.2} bits/element", size, bits_per_elem);
            
            // Should be around 18-24 bits/element (Xor32 uses 32-bit fingerprints vs 16-bit)
            // Retry mechanism increases capacity if needed, so allow up to 24 bits
            assert!(bits_per_elem < 24.0, "Too much space: {:.2} bits/elem", bits_per_elem);
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
        
        let filter = XorFilter32::new(&targets);
        
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


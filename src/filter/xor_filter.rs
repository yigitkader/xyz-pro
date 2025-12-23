use std::hash::Hasher;
use fxhash::FxHasher;
use rayon::prelude::*;

/// XorFilter32 - Probabilistic set membership filter
/// False positive rate: ~0.0015% (1 in 65536)
/// Memory: ~40 bits per element
pub struct XorFilter32 {
    fingerprints: Vec<u32>,
    seed: u64,
    block_length: usize,
    prefix_table: Vec<u32>,
}

impl XorFilter32 {
    pub fn new(targets: &[[u8; 20]]) -> Self {
        let size = targets.len();
        // 1.35x capacity for reliable construction (1.23 is theoretical minimum)
        let capacity = (((size as f64) * 1.35) as usize / 3) * 3;
        let block_length = capacity / 3;
        
        println!("[Xor] Building filter for {} targets...", size);
        println!("[Xor] Capacity: {} (3 × {} blocks)", capacity, block_length);
        
        let mut fingerprints = vec![0u32; capacity];
        let mut seed = 0x517cc1b727220a95_u64;
        let mut success = false;
        
        for attempt in 0..20 {
            fingerprints.fill(0);
            if Self::construct(&targets, &mut fingerprints, block_length, seed) {
                success = true;
                break;
            }
            seed = seed.wrapping_mul(0x5851f42d4c957f2d).wrapping_add(attempt as u64);
            if attempt > 0 && attempt % 5 == 0 {
                println!("[Xor] Retry {} with new seed...", attempt);
            }
        }
        
        if !success {
            panic!("[Xor] Construction failed after 20 attempts");
        }
        
        // Build sorted prefix table (parallel)
        let mut prefixes: Vec<u32> = targets.par_iter()
            .map(|h| u32::from_be_bytes([h[0], h[1], h[2], h[3]]))
            .collect();
        prefixes.par_sort_unstable();
        prefixes.dedup();
        
        println!("[Xor] Built: {:.1} MB filter | {} prefixes ({:.1} MB)",
            (fingerprints.len() * 4) as f64 / 1e6,
            prefixes.len(),
            (prefixes.len() * 4) as f64 / 1e6);
        
        Self { fingerprints, seed, block_length, prefix_table: prefixes }
    }
    
    fn construct(
        targets: &[[u8; 20]],
        fingerprints: &mut [u32],
        block_length: usize,
        seed: u64,
    ) -> bool {
        let n = targets.len();
        let m = fingerprints.len();
        
        // Step 1: Parallel hash computation
        let hashes: Vec<(u32, u32, u32, u32)> = targets.par_iter()
            .map(|hash| {
                let (h0, h1, h2, fp) = Self::hash_to_positions(hash, seed, block_length);
                (h0, h1, h2, fp)
            })
            .collect();
        
        // Step 2: Build degree counts
        let mut degree = vec![0u32; m];
        for &(h0, h1, h2, _) in &hashes {
            degree[h0 as usize] += 1;
            degree[h1 as usize] += 1;
            degree[h2 as usize] += 1;
        }
        
        // Step 3: Initialize queue with singletons
        let mut queue: Vec<u32> = (0..m as u32)
            .filter(|&i| degree[i as usize] == 1)
            .collect();
        
        // Step 4: Peel graph
        let mut stack = Vec::with_capacity(n);
        let mut removed = vec![false; n];
        
        while let Some(pos) = queue.pop() {
            if degree[pos as usize] != 1 { continue; }
            
            // Find the key that maps to this position
            for (idx, &(h0, h1, h2, _)) in hashes.iter().enumerate() {
                if removed[idx] { continue; }
                if h0 == pos || h1 == pos || h2 == pos {
                    removed[idx] = true;
                    stack.push((idx, pos));
                    
                    // Update degrees
                    degree[h0 as usize] -= 1;
                    degree[h1 as usize] -= 1;
                    degree[h2 as usize] -= 1;
                    
                    if degree[h0 as usize] == 1 { queue.push(h0); }
                    if degree[h1 as usize] == 1 { queue.push(h1); }
                    if degree[h2 as usize] == 1 { queue.push(h2); }
                    break;
                }
            }
        }
        
        if stack.len() != n { return false; }
        
        // Step 5: Assign fingerprints in reverse order
        for (idx, pos) in stack.into_iter().rev() {
            let (h0, h1, h2, fp) = hashes[idx];
            fingerprints[pos as usize] = fp 
                ^ fingerprints[h0 as usize] 
                ^ fingerprints[h1 as usize] 
                ^ fingerprints[h2 as usize];
        }
        
        true
    }
    
    #[inline]
    fn hash_to_positions(data: &[u8; 20], seed: u64, block_length: usize) -> (u32, u32, u32, u32) {
        // Use 128-bit hash for 4 independent values
        let mut h1 = FxHasher::default();
        h1.write_u64(seed);
        h1.write(data);
        let hash1 = h1.finish();
        
        let mut h2 = FxHasher::default();
        h2.write_u64(seed ^ 0xc3a5c85c97cb3127);
        h2.write(data);
        let hash2 = h2.finish();
        
        let p0 = ((hash1 as usize) % block_length) as u32;
        let p1 = ((hash1 >> 32) as usize % block_length + block_length) as u32;
        let p2 = ((hash2 as usize) % block_length + 2 * block_length) as u32;
        let fp = (hash2 >> 32) as u32;
        
        (p0, p1, p2, fp)
    }
    
    pub fn gpu_data(&self) -> (&[u32], [u64; 3], u32) {
        // GPU expects 3 seeds for compatibility
        let seeds = [self.seed, self.seed ^ 0xc3a5c85c97cb3127, 0];
        (&self.fingerprints, seeds, self.block_length as u32)
    }
    
    pub fn prefix_table(&self) -> &[u32] { &self.prefix_table }
    pub fn prefix_count(&self) -> u32 { self.prefix_table.len() as u32 }
    
    pub fn memory_bytes(&self) -> usize {
        self.fingerprints.len() * 4 + 8 + 8 + self.prefix_table.len() * 4
    }
    
    pub fn bits_per_element(&self, num_keys: usize) -> f64 {
        (self.memory_bytes() * 8) as f64 / num_keys as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    
    fn random_hash() -> [u8; 20] {
        let mut h = [0u8; 20];
        rand::thread_rng().fill(&mut h);
        h
    }
    
    #[test]
    fn test_construction() {
        let targets: Vec<_> = (0..10_000).map(|_| random_hash()).collect();
        let filter = XorFilter32::new(&targets);
        assert!(filter.fingerprints.len() > 0);
    }
    
    #[test]
    fn test_no_false_negatives() {
        let targets: Vec<_> = (0..1000).map(|_| random_hash()).collect();
        let filter = XorFilter32::new(&targets);
        
        for hash in &targets {
            assert!(filter.contains(hash), "False negative detected");
        }
    }
    
    #[test]
    fn test_false_positive_rate() {
        let targets: Vec<_> = (0..10_000).map(|_| random_hash()).collect();
        let filter = XorFilter32::new(&targets);
        
        let mut fp = 0;
        for _ in 0..100_000 {
            let r = random_hash();
            if filter.contains(&r) { fp += 1; }
        }
        
        let rate = fp as f64 / 100_000.0;
        println!("FP rate: {:.4}%", rate * 100.0);
        assert!(rate < 0.002, "FP rate too high: {:.4}%", rate * 100.0);
    }
}

impl XorFilter32 {
    pub fn contains(&self, hash: &[u8; 20]) -> bool {
        let (h0, h1, h2, fp) = Self::hash_to_positions(hash, self.seed, self.block_length);
        self.fingerprints[h0 as usize] 
            ^ self.fingerprints[h1 as usize] 
            ^ self.fingerprints[h2 as usize] == fp
    }
}

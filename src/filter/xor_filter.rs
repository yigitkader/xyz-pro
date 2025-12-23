use std::hash::Hasher;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use fxhash::FxHasher;
use rayon::prelude::*;

const CACHE_MAGIC: &[u8; 8] = b"XORFL_01";

/// XorFilter32 - Probabilistic set membership filter
/// False positive rate: ~0.0015% (1 in 65536)
/// Memory: ~40 bits per element
/// 
/// Construction uses XOR-trick peeling algorithm: O(n) instead of O(n²)
pub struct XorFilter32 {
    fingerprints: Vec<u32>,
    seed: u64,
    block_length: usize,
    prefix_table: Vec<u32>,
}

impl XorFilter32 {
    /// Create new filter from targets - uses cache if available
    #[allow(dead_code)]
    pub fn new(targets: &[[u8; 20]]) -> Self {
        Self::new_with_cache(targets, None)
    }
    
    /// Create filter with optional cache path
    pub fn new_with_cache(targets: &[[u8; 20]], cache_path: Option<&str>) -> Self {
        // Try to load from cache first
        if let Some(path) = cache_path {
            if let Some(filter) = Self::load_from_cache(path, targets.len()) {
                println!("[Xor] Loaded from cache: {} ({:.1} MB)", 
                    path, 
                    (filter.fingerprints.len() * 4) as f64 / 1e6);
                return filter;
            }
        }
        
        // Build from scratch
        let filter = Self::build_new(targets);
        
        // Save to cache if path provided
        if let Some(path) = cache_path {
            if let Err(e) = filter.save_to_cache(path) {
                eprintln!("[Xor] Warning: Failed to save cache: {}", e);
            } else {
                println!("[Xor] Cache saved: {}", path);
            }
        }
        
        filter
    }
    
    /// Build filter from targets (no cache)
    fn build_new(targets: &[[u8; 20]]) -> Self {
        let size = targets.len();
        // 1.5x capacity for reliable construction with large datasets (49M+ targets)
        // 1.23 is theoretical minimum, 1.35 causes retries on 49M targets
        // 1.5x ensures single-attempt success while only adding ~15% more memory
        let capacity = (((size as f64) * 1.5) as usize / 3) * 3;
        let block_length = capacity / 3;
        
        println!("[Xor] Building filter for {} targets...", size);
        println!("[Xor] Capacity: {} (3 × {} blocks)", capacity, block_length);
        
        let start = std::time::Instant::now();
        
        let mut fingerprints = vec![0u32; capacity];
        let mut seed = 0x517cc1b727220a95_u64;
        let mut success = false;
        
        for attempt in 0..50 {
            fingerprints.fill(0);
            if Self::construct_optimized(targets, &mut fingerprints, block_length, seed) {
                success = true;
                println!("[Xor] Construction succeeded on attempt {} in {:.2}s", 
                    attempt + 1, start.elapsed().as_secs_f64());
                break;
            }
            seed = seed.wrapping_mul(0x5851f42d4c957f2d).wrapping_add(attempt as u64);
            if attempt > 0 && attempt % 5 == 0 {
                println!("[Xor] Retry {} with new seed...", attempt);
            }
        }
        
        if !success {
            panic!("[Xor] Construction failed after 50 attempts - this should not happen with 1.5x capacity");
        }
        
        // Build sorted prefix table (parallel)
        let mut prefixes: Vec<u32> = targets.par_iter()
            .map(|h| u32::from_be_bytes([h[0], h[1], h[2], h[3]]))
            .collect();
        prefixes.par_sort_unstable();
        prefixes.dedup();
        
        println!("[Xor] Built: {:.1} MB filter | {} prefixes ({:.1} MB) | Total: {:.2}s",
            (fingerprints.len() * 4) as f64 / 1e6,
            prefixes.len(),
            (prefixes.len() * 4) as f64 / 1e6,
            start.elapsed().as_secs_f64());
        
        Self { fingerprints, seed, block_length, prefix_table: prefixes }
    }
    
    /// O(n) Optimized construction using XOR-trick for graph peeling
    /// 
    /// Instead of searching for keys that use a slot, we maintain:
    /// - count[slot]: Number of keys using this slot
    /// - key_xor[slot]: XOR of indices of keys using this slot
    /// 
    /// When count == 1, key_xor directly gives the key index!
    fn construct_optimized(
        targets: &[[u8; 20]],
        fingerprints: &mut [u32],
        block_length: usize,
        seed: u64,
    ) -> bool {
        let n = targets.len();
        let m = fingerprints.len();
        
        // Step 1: Parallel hash computation
        let hashes: Vec<(u32, u32, u32, u32)> = targets.par_iter()
            .map(|hash| Self::hash_to_positions(hash, seed, block_length))
            .collect();
        
        // Step 2: Build slot metadata using XOR-trick
        // count[i] = number of keys that use slot i
        // key_xor[i] = XOR of all key indices that use slot i
        // When count[i] == 1, key_xor[i] is the index of that single key
        let mut count = vec![0u32; m];
        let mut key_xor = vec![0u32; m];
        
        for (idx, &(h0, h1, h2, _)) in hashes.iter().enumerate() {
            let idx32 = idx as u32;
            count[h0 as usize] += 1;
            count[h1 as usize] += 1;
            count[h2 as usize] += 1;
            key_xor[h0 as usize] ^= idx32;
            key_xor[h1 as usize] ^= idx32;
            key_xor[h2 as usize] ^= idx32;
        }
        
        // Step 3: Initialize queue with singleton slots
        let mut queue: Vec<u32> = (0..m as u32)
            .filter(|&i| count[i as usize] == 1)
            .collect();
        
        // Step 4: Peel graph - O(n) total!
        let mut stack = Vec::with_capacity(n);
        
        while let Some(slot) = queue.pop() {
            if count[slot as usize] != 1 { 
                continue; 
            }
            
            // XOR-trick: key_xor directly gives us the key index!
            let key_idx = key_xor[slot as usize] as usize;
            let (h0, h1, h2, _) = hashes[key_idx];
            
            stack.push((key_idx, slot));
            
            // Remove this key from all its slots
            let key_idx32 = key_idx as u32;
            for &slot_pos in &[h0, h1, h2] {
                count[slot_pos as usize] -= 1;
                key_xor[slot_pos as usize] ^= key_idx32;
                
                // If slot becomes singleton, add to queue
                if count[slot_pos as usize] == 1 {
                    queue.push(slot_pos);
                }
            }
        }
        
        // Check if all keys were peeled
        if stack.len() != n { 
            return false; 
        }
        
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
    
    // ========================================================================
    // CACHE SUPPORT
    // ========================================================================
    
    /// Save filter to binary cache file
    /// Format: MAGIC (8) | count (8) | seed (8) | block_length (8) | 
    ///         prefix_count (8) | fingerprints | prefixes
    pub fn save_to_cache(&self, path: &str) -> std::io::Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);
        
        // Header
        writer.write_all(CACHE_MAGIC)?;
        writer.write_all(&(self.fingerprints.len() as u64).to_le_bytes())?;
        writer.write_all(&self.seed.to_le_bytes())?;
        writer.write_all(&(self.block_length as u64).to_le_bytes())?;
        writer.write_all(&(self.prefix_table.len() as u64).to_le_bytes())?;
        
        // Fingerprints (bulk write)
        let fp_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                self.fingerprints.as_ptr() as *const u8,
                self.fingerprints.len() * 4,
            )
        };
        writer.write_all(fp_bytes)?;
        
        // Prefixes (bulk write)
        let prefix_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                self.prefix_table.as_ptr() as *const u8,
                self.prefix_table.len() * 4,
            )
        };
        writer.write_all(prefix_bytes)?;
        
        writer.flush()?;
        Ok(())
    }
    
    /// Load filter from binary cache file
    /// Returns None if cache doesn't exist, is invalid, or target count mismatch
    pub fn load_from_cache(path: &str, expected_target_count: usize) -> Option<Self> {
        let path = Path::new(path);
        if !path.exists() {
            return None;
        }
        
        let file = File::open(path).ok()?;
        let mut reader = BufReader::with_capacity(1024 * 1024, file);
        
        // Read header
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic).ok()?;
        if &magic != CACHE_MAGIC {
            eprintln!("[Xor] Cache version mismatch, rebuilding...");
            return None;
        }
        
        let mut buf8 = [0u8; 8];
        
        reader.read_exact(&mut buf8).ok()?;
        let fingerprint_count = u64::from_le_bytes(buf8) as usize;
        
        reader.read_exact(&mut buf8).ok()?;
        let seed = u64::from_le_bytes(buf8);
        
        reader.read_exact(&mut buf8).ok()?;
        let block_length = u64::from_le_bytes(buf8) as usize;
        
        reader.read_exact(&mut buf8).ok()?;
        let prefix_count = u64::from_le_bytes(buf8) as usize;
        
        // Validate expected capacity
        // capacity = ((target_count * 1.5) / 3) * 3
        let expected_capacity = (((expected_target_count as f64) * 1.5) as usize / 3) * 3;
        if fingerprint_count != expected_capacity {
            eprintln!("[Xor] Cache capacity mismatch (expected {}, got {}), rebuilding...", 
                expected_capacity, fingerprint_count);
            return None;
        }
        
        // Read fingerprints
        let mut fingerprints = vec![0u32; fingerprint_count];
        let fp_bytes: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                fingerprints.as_mut_ptr() as *mut u8,
                fingerprint_count * 4,
            )
        };
        reader.read_exact(fp_bytes).ok()?;
        
        // Read prefixes
        let mut prefix_table = vec![0u32; prefix_count];
        let prefix_bytes: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                prefix_table.as_mut_ptr() as *mut u8,
                prefix_count * 4,
            )
        };
        reader.read_exact(prefix_bytes).ok()?;
        
        Some(Self {
            fingerprints,
            seed,
            block_length,
            prefix_table,
        })
    }
    
    /// Check if cache file exists and appears valid
    #[allow(dead_code)]
    pub fn cache_exists(path: &str) -> bool {
        Path::new(path).exists()
    }
    
    // ========================================================================
    // PUBLIC API
    // ========================================================================
    
    #[allow(dead_code)]
    pub fn contains(&self, hash: &[u8; 20]) -> bool {
        let (h0, h1, h2, fp) = Self::hash_to_positions(hash, self.seed, self.block_length);
        self.fingerprints[h0 as usize] 
            ^ self.fingerprints[h1 as usize] 
            ^ self.fingerprints[h2 as usize] == fp
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
    
    #[test]
    fn test_cache_roundtrip() {
        let targets: Vec<_> = (0..5_000).map(|_| random_hash()).collect();
        let filter = XorFilter32::new(&targets);
        
        let temp_path = std::env::temp_dir().join("test_xor_cache.xor");
        let path_str = temp_path.to_str().unwrap();
        
        // Save
        filter.save_to_cache(path_str).unwrap();
        
        // Load
        let loaded = XorFilter32::load_from_cache(path_str, targets.len()).unwrap();
        
        // Verify
        assert_eq!(filter.seed, loaded.seed);
        assert_eq!(filter.block_length, loaded.block_length);
        assert_eq!(filter.fingerprints, loaded.fingerprints);
        assert_eq!(filter.prefix_table, loaded.prefix_table);
        
        // Test membership
        for hash in &targets {
            assert!(loaded.contains(hash), "False negative after cache load");
        }
        
        let _ = std::fs::remove_file(&temp_path);
    }
    
    #[test]
    fn test_large_construction_performance() {
        // Test that O(n) algorithm is fast even for larger sets
        let targets: Vec<_> = (0..100_000).map(|_| random_hash()).collect();
        
        let start = std::time::Instant::now();
        let filter = XorFilter32::new(&targets);
        let elapsed = start.elapsed();
        
        println!("100K targets built in {:.2}s", elapsed.as_secs_f64());
        assert!(elapsed.as_secs() < 5, "Construction too slow: {:?}", elapsed);
        
        // Verify no false negatives
        for hash in targets.iter().take(1000) {
            assert!(filter.contains(hash));
        }
    }
}

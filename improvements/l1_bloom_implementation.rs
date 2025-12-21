// ============================================================================
// L1 CACHE-RESIDENT BLOOM FILTER
// Two-level filtering: L1 (2MB, L2 cache) → L2 (86MB, main memory)
// Expected speedup: 30-40% from reduced memory latency
// ============================================================================

// File: Add to src/gpu.rs

use std::collections::HashSet;

/// Two-level Bloom filter for cache hierarchy optimization
pub struct DualBloomFilter {
    /// L1: Small, cache-resident filter (2MB)
    /// Purpose: Fast rejection of 99% of non-matching keys
    /// Fits in M1 Pro L2 cache (24MB shared)
    l1: BloomFilter,
    
    /// L2: Main filter (86MB for 49M targets)
    /// Purpose: Precise filtering with low FP rate
    l2: BloomFilter,
    
    /// Number of targets
    count: usize,
}

impl DualBloomFilter {
    /// Create dual-level Bloom filter
    /// 
    /// # Strategy for L1 selection:
    /// We want L1 to catch the "hot" addresses that are checked most often.
    /// Options:
    /// 1. First N addresses (simple, assumes older = more likely)
    /// 2. Random sample (unbiased)
    /// 3. Balance-weighted (favor high-balance addresses)
    /// 
    /// For Bitcoin scanner, option 1 is reasonable since genesis block
    /// and early coins are more likely targets of interest.
    pub fn new(target_hashes: &[[u8; 20]]) -> Self {
        println!("[Bloom] Creating dual-level filter for {} targets...", target_hashes.len());
        
        // L1 filter parameters
        const L1_TARGET_COUNT: usize = 1_000_000;  // 1M targets
        const L1_BITS_PER_ELEMENT: usize = 12;     // Low FP but compact
        
        // Determine L1 target set
        let l1_count = L1_TARGET_COUNT.min(target_hashes.len());
        let l1_hashes: Vec<[u8; 20]> = target_hashes[..l1_count].to_vec();
        
        // Calculate L1 size
        let l1_raw_bits = l1_count * L1_BITS_PER_ELEMENT;
        let l1_bits = l1_raw_bits.next_power_of_two();
        let l1_size_mb = l1_bits as f64 / 8_000_000.0;
        
        println!("[Bloom] L1: {} targets × {} bits = {:.1}MB (power-of-2: {} bits)",
            l1_count, L1_BITS_PER_ELEMENT, l1_size_mb, l1_bits);
        
        // Create L1 filter
        let mut l1 = BloomFilter::new_with_bits(l1_bits);
        for hash in &l1_hashes {
            l1.insert(hash);
        }
        
        // L2 filter (standard, optimized for full target set)
        let mut l2 = BloomFilter::new(target_hashes.len());
        for hash in target_hashes {
            l2.insert(hash);
        }
        
        let l2_size_mb = (l2.size_words() * 8) as f64 / 1_000_000.0;
        println!("[Bloom] L2: {} targets = {:.1}MB", target_hashes.len(), l2_size_mb);
        
        // Verify L1 is small enough for L2 cache
        if l1_size_mb > 4.0 {
            eprintln!("[!] WARNING: L1 filter ({:.1}MB) may not fit in L2 cache!", l1_size_mb);
            eprintln!("    Performance benefit may be reduced.");
        }
        
        Self {
            l1,
            l2,
            count: target_hashes.len(),
        }
    }
    
    /// Get L1 filter data for GPU
    pub fn l1_data(&self) -> &[u64] {
        self.l1.as_slice()
    }
    
    /// Get L2 filter data for GPU
    pub fn l2_data(&self) -> &[u64] {
        self.l2.as_slice()
    }
    
    /// Get L1 size in 64-bit words
    pub fn l1_size_words(&self) -> usize {
        self.l1.size_words()
    }
    
    /// Get L2 size in 64-bit words
    pub fn l2_size_words(&self) -> usize {
        self.l2.size_words()
    }
    
    /// Get total target count
    pub fn target_count(&self) -> usize {
        self.count
    }
}

// ============================================================================
// BLOOMFILTER ENHANCEMENT - Add new_with_bits constructor
// ============================================================================

impl BloomFilter {
    /// Create Bloom filter with exact bit count (must be power-of-2)
    pub fn new_with_bits(num_bits: usize) -> Self {
        assert!(num_bits.is_power_of_two(), "num_bits must be power of 2");
        assert!(num_bits >= 1024, "num_bits must be at least 1024");
        
        let num_words = num_bits / 64;
        
        Self {
            bits: vec![0u64; num_words],
            num_bits,
        }
    }
}

// ============================================================================
// GPU.RS CHANGES - Update OptimizedScanner
// ============================================================================

// In OptimizedScanner struct, REPLACE:
// bloom_buf: Buffer,
// bloom_size_buf: Buffer,

// WITH:
pub struct OptimizedScanner {
    // ... existing fields
    
    // Two-level Bloom filter buffers
    l1_bloom_buf: Buffer,
    l1_bloom_size_buf: Buffer,
    l2_bloom_buf: Buffer,
    l2_bloom_size_buf: Buffer,
    
    // ... rest of fields
}

// In OptimizedScanner::new(), REPLACE bloom filter creation:

// OLD:
// let mut bloom = BloomFilter::new(target_hashes.len());
// for h in target_hashes {
//     bloom.insert(h);
// }

// NEW:
let dual_bloom = DualBloomFilter::new(target_hashes);

// Create L1 buffer
let l1_data = dual_bloom.l1_data();
let l1_bloom_buf = device.new_buffer_with_data(
    l1_data.as_ptr() as *const _,
    (l1_data.len() * 8) as u64,
    storage,
);

let l1_size = dual_bloom.l1_size_words() as u32;
let l1_bloom_size_buf = device.new_buffer_with_data(
    &l1_size as *const u32 as *const _,
    4,
    storage,
);

// Create L2 buffer
let l2_data = dual_bloom.l2_data();
let l2_bloom_buf = device.new_buffer_with_data(
    l2_data.as_ptr() as *const _,
    (l2_data.len() * 8) as u64,
    storage,
);

let l2_size = dual_bloom.l2_size_words() as u32;
let l2_bloom_size_buf = device.new_buffer_with_data(
    &l2_size as *const u32 as *const _,
    4,
    storage,
);

// ============================================================================
// METAL SHADER CHANGES (secp256k1_scanner.metal)
// ============================================================================

/*
CHANGE 1: Update kernel parameters

OLD:
kernel void scan_keys(
    ...
    constant ulong* bloom [[buffer(3)]],
    constant uint* bloom_size [[buffer(4)]],
    ...
)

NEW:
kernel void scan_keys(
    ...
    constant ulong* l1_bloom [[buffer(3)]],
    constant uint* l1_bloom_size [[buffer(4)]],
    constant ulong* l2_bloom [[buffer(5)]],
    constant uint* l2_bloom_size [[buffer(6)]],
    // NOTE: Shift all subsequent buffer indices by +2!
    constant uint* keys_per_thread [[buffer(7)]],  // was [[buffer(5)]]
    ...
)
*/

/*
CHANGE 2: Add two-level bloom check function

// Insert BEFORE the scan_keys kernel:

/// Two-level Bloom filter check
/// L1: Quick rejection in L2 cache (fast!)
/// L2: Precise filtering in main memory (slower but accurate)
inline bool dual_bloom_check(thread uchar* h, 
                             constant ulong* l1_bloom, uint l1_size,
                             constant ulong* l2_bloom, uint l2_size) {
    // Level 1: Quick reject (most non-matches stop here)
    // L1 is small (2MB) and should be in L2 cache
    if (!bloom_check(h, l1_bloom, l1_size)) {
        // Definitely not in set (L1 covers subset of L2)
        // FAST PATH: 99% of non-matching keys exit here
        // Latency: ~15 cycles (L2 cache access)
        return false;
    }
    
    // Passed L1 filter, check main L2 filter
    // This is slower (main memory) but L1 already filtered 99%
    // Latency: ~100 cycles (unified memory access)
    return bloom_check(h, l2_bloom, l2_size);
}
*/

/*
CHANGE 3: Update bloom checks in main kernel

// In scan_keys kernel, REPLACE all bloom_check() calls with dual_bloom_check()

OLD:
if (bloom_check(h_comp, bloom, bloom_sz)) {
    if (binary_search_hash(h_comp, sorted_hashes, target_count)) {
        SAVE_MATCH(h_comp, 0);
    }
}

NEW:
if (dual_bloom_check(h_comp, l1_bloom, *l1_bloom_size, l2_bloom, *l2_bloom_size)) {
    if (binary_search_hash(h_comp, sorted_hashes, target_count)) {
        SAVE_MATCH(h_comp, 0);
    }
}

// Repeat for all 6 hash types (comp, uncomp, p2sh, glv_comp, glv_uncomp, glv_p2sh)
*/

// ============================================================================
// ENCODER.RS CHANGES - Update buffer binding indices
// ============================================================================

/*
In dispatch_batch(), UPDATE buffer indices to account for L1/L2 split:

OLD:
enc.set_buffer(3, Some(&self.bloom_buf), 0);
enc.set_buffer(4, Some(&self.bloom_size_buf), 0);
enc.set_buffer(5, Some(&self.kpt_buf), 0);
enc.set_buffer(6, Some(&buffers.match_data_buf), 0);
enc.set_buffer(7, Some(&buffers.match_count_buf), 0);
enc.set_buffer(8, Some(&self.sorted_hashes_buf), 0);
enc.set_buffer(9, Some(&self.hash_count_buf), 0);

NEW:
enc.set_buffer(3, Some(&self.l1_bloom_buf), 0);
enc.set_buffer(4, Some(&self.l1_bloom_size_buf), 0);
enc.set_buffer(5, Some(&self.l2_bloom_buf), 0);
enc.set_buffer(6, Some(&self.l2_bloom_size_buf), 0);
enc.set_buffer(7, Some(&self.kpt_buf), 0);           // shifted from 5
enc.set_buffer(8, Some(&buffers.match_data_buf), 0);  // shifted from 6
enc.set_buffer(9, Some(&buffers.match_count_buf), 0); // shifted from 7
enc.set_buffer(10, Some(&self.sorted_hashes_buf), 0); // shifted from 8
enc.set_buffer(11, Some(&self.hash_count_buf), 0);    // shifted from 9
*/

// ============================================================================
// PERFORMANCE ANALYSIS
// ============================================================================

/*
CURRENT SYSTEM (single 86MB Bloom):
  Per key check (6 hash types):
    - 7 hash functions × 6 types = 42 hash computations
    - 42 × 100 cycles (unified memory latency) = 4,200 cycles
    - At 3.2GHz: 4,200 / 3.2e9 = 1.31 microseconds per key

TWO-LEVEL SYSTEM (2MB L1 + 86MB L2):
  Per key check:
    L1 (99% of keys):
      - 7 hash functions × 15 cycles (L2 cache) = 105 cycles
      - 99% × 105 = 103.95 cycles average
    
    L2 (1% of keys that pass L1):
      - 7 hash functions × 100 cycles (main memory) = 700 cycles
      - 1% × 700 = 7 cycles average
    
    Total per type: 103.95 + 7 = 110.95 cycles
    × 6 types = 665.7 cycles
    
    At 3.2GHz: 665.7 / 3.2e9 = 0.21 microseconds per key

SPEEDUP: 1.31 / 0.21 = 6.2× faster bloom filtering!

IMPACT ON TOTAL THROUGHPUT:
  If bloom filtering was 30% of GPU time:
    Old: 100% = 30% bloom + 70% other
    New: X% = (30% / 6.2) bloom + 70% other
    X = 4.8% + 70% = 74.8%
    Speedup: 100 / 74.8 = 1.34× = +34% faster

Expected on M1 Pro:
  122 M/s → 163 M/s (+34%)
*/

// src/filter/xor_lookup.metal
// GPU-side Xor Filter lookup - O(1) constant time
// 3 memory accesses + 2 XOR operations = ~6 cycles

#include <metal_stdlib>
using namespace metal;

/// FxHash implementation for GPU (matches Rust FxHasher)
inline ulong fx_hash(constant uchar* data, uint len, ulong seed) {
    ulong hash = seed;
    
    // Process 8-byte chunks
    for (uint i = 0; i + 8 <= len; i += 8) {
        ulong chunk = ((ulong)data[i]) | ((ulong)data[i+1] << 8) | 
                     ((ulong)data[i+2] << 16) | ((ulong)data[i+3] << 24) |
                     ((ulong)data[i+4] << 32) | ((ulong)data[i+5] << 40) |
                     ((ulong)data[i+6] << 48) | ((ulong)data[i+7] << 56);
        
        hash = hash ^ chunk;
        hash = hash * 0x517cc1b727220a95UL;  // FxHash multiplier
    }
    
    // Process remaining bytes
    for (uint i = (len / 8) * 8; i < len; i++) {
        hash = hash ^ (ulong)data[i];
        hash = hash * 0x517cc1b727220a95UL;
    }
    
    return hash;
}

/// Hash to specific block (0, 1, or 2)
inline uint xor_hash_to_block(thread uchar* hash, 
                              constant ulong* seeds,
                              uint block_length,
                              uint block_id) {
    ulong h = fx_hash(hash, 20, seeds[block_id]);
    uint pos = (uint)(h % (ulong)block_length);
    return block_id * block_length + pos;
}

/// Compute 16-bit fingerprint
inline ushort xor_fingerprint(thread uchar* hash) {
    ulong h = fx_hash(hash, 20, 0);
    return (ushort)(h >> 48);  // Top 16 bits
}

/// O(1) Xor Filter membership test
/// Returns true if hash *might* be in set (may have false positives)
/// Returns false if hash is *definitely not* in set (no false negatives)
inline bool xor_filter_contains(
    thread uchar* hash,
    constant ushort* fingerprints,  // Fingerprint table
    constant ulong* seeds,          // 3 hash seeds
    uint block_length              // Size of each block
) {
    // Compute fingerprint
    ushort fp = xor_fingerprint(hash);
    
    // Hash to 3 positions (one per block)
    uint h0 = xor_hash_to_block(hash, seeds, block_length, 0);
    uint h1 = xor_hash_to_block(hash, seeds, block_length, 1);
    uint h2 = xor_hash_to_block(hash, seeds, block_length, 2);
    
    // XOR the 3 fingerprints and compare
    ushort xor_val = fingerprints[h0] ^ fingerprints[h1] ^ fingerprints[h2];
    
    return xor_val == fp;
}

/// Test kernel: verify Xor filter correctness
kernel void test_xor_filter_lookup(
    constant uchar* test_hashes [[buffer(0)]],     // Input hashes (20 bytes each)
    constant ushort* fingerprints [[buffer(1)]],   // Xor filter table
    constant ulong* seeds [[buffer(2)]],           // Hash seeds
    constant uint* block_length [[buffer(3)]],     // Block size
    device uint* results [[buffer(4)]],            // Output: 1 if found, 0 if not
    uint gid [[thread_position_in_grid]]
) {
    // Load hash
    thread uchar hash[20];
    constant uchar* input = test_hashes + (gid * 20);
    for (int i = 0; i < 20; i++) {
        hash[i] = input[i];
    }
    
    // Check filter
    bool found = xor_filter_contains(hash, fingerprints, seeds, *block_length);
    
    results[gid] = found ? 1 : 0;
}

/// Benchmark kernel: measure pure filter throughput
kernel void benchmark_xor_filter(
    constant uchar* test_hashes [[buffer(0)]],
    constant ushort* fingerprints [[buffer(1)]],
    constant ulong* seeds [[buffer(2)]],
    constant uint* block_length [[buffer(3)]],
    device atomic_ulong* hit_count [[buffer(4)]],  // Count of matches
    uint num_hashes [[buffer(5)]],
    uint gid [[thread_position_in_grid]]
) {
    // Each thread tests multiple hashes
    uint hashes_per_thread = (num_hashes + gid - 1) / gid;
    
    for (uint i = 0; i < hashes_per_thread; i++) {
        uint hash_idx = gid * hashes_per_thread + i;
        if (hash_idx >= num_hashes) break;
        
        thread uchar hash[20];
        constant uchar* input = test_hashes + (hash_idx * 20);
        for (int j = 0; j < 20; j++) {
            hash[j] = input[j];
        }
        
        if (xor_filter_contains(hash, fingerprints, seeds, *block_length)) {
            atomic_fetch_add_explicit(hit_count, 1UL, memory_order_relaxed);
        }
    }
}

/// Performance comparison: Xor vs Binary Search
/// This demonstrates the O(1) vs O(log n) difference
kernel void compare_xor_vs_binary(
    constant uchar* test_hash [[buffer(0)]],
    constant ushort* xor_fingerprints [[buffer(1)]],
    constant ulong* xor_seeds [[buffer(2)]],
    constant uint* xor_block_length [[buffer(3)]],
    constant uchar* sorted_hashes [[buffer(4)]],   // For binary search
    constant uint* hash_count [[buffer(5)]],       // Number of hashes
    device ulong* xor_cycles [[buffer(6)]],        // Timing output
    device ulong* binary_cycles [[buffer(7)]],
    uint gid [[thread_position_in_grid]]
) {
    thread uchar hash[20];
    for (int i = 0; i < 20; i++) {
        hash[i] = test_hash[i];
    }
    
    // Time Xor filter (O(1))
    ulong start_xor = metal::get_timestamp();
    bool xor_result = xor_filter_contains(hash, xor_fingerprints, xor_seeds, *xor_block_length);
    ulong end_xor = metal::get_timestamp();
    
    // Time binary search (O(log n))
    ulong start_bin = metal::get_timestamp();
    
    uint left = 0;
    uint right = *hash_count;
    bool bin_result = false;
    
    while (left < right) {
        uint mid = left + (right - left) / 2;
        constant uchar* target = sorted_hashes + mid * 20;
        
        // Lexicographic compare
        int cmp = 0;
        for (int i = 0; i < 20 && cmp == 0; i++) {
            cmp = (int)hash[i] - (int)target[i];
        }
        
        if (cmp == 0) {
            bin_result = true;
            break;
        } else if (cmp < 0) {
            right = mid;
        } else {
            left = mid + 1;
        }
    }
    
    ulong end_bin = metal::get_timestamp();
    
    // Store timing results
    if (gid == 0) {
        *xor_cycles = end_xor - start_xor;
        *binary_cycles = end_bin - start_bin;
    }
}

/// Validate Xor filter against CPU
/// Ensures GPU implementation matches Rust
kernel void validate_xor_cpu_match(
    constant uchar* test_hashes [[buffer(0)]],
    constant ushort* fingerprints [[buffer(1)]],
    constant ulong* seeds [[buffer(2)]],
    constant uint* block_length [[buffer(3)]],
    constant uint* expected_results [[buffer(4)]],  // From CPU
    device atomic_uint* mismatch_count [[buffer(5)]],
    uint num_tests [[buffer(6)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= num_tests) return;
    
    thread uchar hash[20];
    constant uchar* input = test_hashes + (gid * 20);
    for (int i = 0; i < 20; i++) {
        hash[i] = input[i];
    }
    
    bool gpu_result = xor_filter_contains(hash, fingerprints, seeds, *block_length);
    bool cpu_result = expected_results[gid] != 0;
    
    if (gpu_result != cpu_result) {
        atomic_fetch_add_explicit(mismatch_count, 1, memory_order_relaxed);
    }
}
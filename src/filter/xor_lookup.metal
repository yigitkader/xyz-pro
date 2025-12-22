// src/filter/xor_lookup.metal
// GPU-side Xor Filter lookup - O(1) constant time
// 3 memory accesses + 2 XOR operations = ~6 cycles

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


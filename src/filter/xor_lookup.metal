// src/filter/xor_lookup.metal
// GPU-side Xor Filter lookup - O(1) constant time
// 3 memory accesses + 2 XOR operations = ~6 cycles

// ============================================================================
// FxHash implementation for GPU
// CRITICAL: Must EXACTLY match Rust FxHasher from fxhash crate!
//
// Rust FxHasher algorithm:
//   - write_u64(value): single cycle → rotate_left(5) ^ value, then multiply
//   - write(&[u8]): processes in 8-byte, 4-byte, 2-byte, 1-byte chunks
//   - Each chunk is processed as a SINGLE WORD (not byte-by-byte!)
//
// IMPORTANT: The key insight is that FxHasher uses WORD-WISE processing,
// not byte-by-byte. Each u64/u32/u16/u8 chunk is XOR'd as a single value.
// ============================================================================

/// Rotate left helper (matches Rust u64::rotate_left)
inline ulong rotate_left_5(ulong x) {
    return (x << 5) | (x >> 59);
}

/// Process u64 as a single word (matches Rust FxHasher::write_u64)
/// This is ONE cycle: rotate, XOR, multiply
inline ulong fx_hash_u64(ulong value, ulong hash) {
    hash = rotate_left_5(hash) ^ value;
    return hash * 0x517cc1b727220a95UL;
}

/// Process u32 as a single word (matches Rust FxHasher internal)
inline ulong fx_hash_u32(uint value, ulong hash) {
    hash = rotate_left_5(hash) ^ (ulong)value;
    return hash * 0x517cc1b727220a95UL;
}

/// Process u16 as a single word
inline ulong fx_hash_u16(ushort value, ulong hash) {
    hash = rotate_left_5(hash) ^ (ulong)value;
    return hash * 0x517cc1b727220a95UL;
}

/// Process u8 as a single word
inline ulong fx_hash_u8(uchar value, ulong hash) {
    hash = rotate_left_5(hash) ^ (ulong)value;
    return hash * 0x517cc1b727220a95UL;
}

/// FxHash for byte array - matches Rust FxHasher::write()
/// Processes in 8-byte, 4-byte, 2-byte, 1-byte chunks (NOT byte-by-byte!)
/// Overload for thread address space
inline ulong fx_hash_bytes(thread uchar* data, uint len, ulong hash) {
    uint i = 0;
    
    // Process 8-byte chunks as u64 (little-endian)
    while (i + 8 <= len) {
        ulong chunk = ((ulong)data[i]) | 
                     ((ulong)data[i+1] << 8) |
                     ((ulong)data[i+2] << 16) |
                     ((ulong)data[i+3] << 24) |
                     ((ulong)data[i+4] << 32) |
                     ((ulong)data[i+5] << 40) |
                     ((ulong)data[i+6] << 48) |
                     ((ulong)data[i+7] << 56);
        hash = fx_hash_u64(chunk, hash);
        i += 8;
    }
    
    // Process remaining 4 bytes as u32
    if (i + 4 <= len) {
        uint chunk = ((uint)data[i]) |
                    ((uint)data[i+1] << 8) |
                    ((uint)data[i+2] << 16) |
                    ((uint)data[i+3] << 24);
        hash = fx_hash_u32(chunk, hash);
        i += 4;
    }
    
    // Process remaining 2 bytes as u16
    if (i + 2 <= len) {
        ushort chunk = ((ushort)data[i]) |
                      ((ushort)data[i+1] << 8);
        hash = fx_hash_u16(chunk, hash);
        i += 2;
    }
    
    // Process remaining 1 byte as u8
    if (i < len) {
        hash = fx_hash_u8(data[i], hash);
    }
    
    return hash;
}

/// FxHash overload for constant address space
inline ulong fx_hash_bytes(constant uchar* data, uint len, ulong hash) {
    uint i = 0;
    
    // Process 8-byte chunks as u64 (little-endian)
    while (i + 8 <= len) {
        ulong chunk = ((ulong)data[i]) | 
                     ((ulong)data[i+1] << 8) |
                     ((ulong)data[i+2] << 16) |
                     ((ulong)data[i+3] << 24) |
                     ((ulong)data[i+4] << 32) |
                     ((ulong)data[i+5] << 40) |
                     ((ulong)data[i+6] << 48) |
                     ((ulong)data[i+7] << 56);
        hash = fx_hash_u64(chunk, hash);
        i += 8;
    }
    
    // Process remaining 4 bytes as u32
    if (i + 4 <= len) {
        uint chunk = ((uint)data[i]) |
                    ((uint)data[i+1] << 8) |
                    ((uint)data[i+2] << 16) |
                    ((uint)data[i+3] << 24);
        hash = fx_hash_u32(chunk, hash);
        i += 4;
    }
    
    // Process remaining 2 bytes as u16
    if (i + 2 <= len) {
        ushort chunk = ((ushort)data[i]) |
                      ((ushort)data[i+1] << 8);
        hash = fx_hash_u16(chunk, hash);
        i += 2;
    }
    
    // Process remaining 1 byte as u8
    if (i < len) {
        hash = fx_hash_u8(data[i], hash);
    }
    
    return hash;
}

/// Hash to specific block (0, 1, or 2)
/// Matches CPU: FxHasher::default() → write_u64(seed) → write(hash)
inline uint xor_hash_to_block(thread uchar* hash, 
                              constant ulong* seeds,
                              uint block_length,
                              uint block_id) {
    ulong h = 0;  // FxHasher::default()
    
    // Step 1: Process seed as u64 (SINGLE cycle, not 8 bytes!)
    h = fx_hash_u64(seeds[block_id], h);
    
    // Step 2: Process 20-byte hash (2×u64 + 1×u32 = 3 cycles)
    h = fx_hash_bytes(hash, 20, h);
    
    // Step 3: Reduce to block index
    uint pos = (uint)(h % (ulong)block_length);
    return block_id * block_length + pos;
}

/// Compute 32-bit fingerprint
/// Matches CPU: FxHasher::default() → write(hash) → finish() >> 32
inline uint xor_fingerprint(thread uchar* hash) {
    ulong h = fx_hash_bytes(hash, 20, 0);  // Initial = 0 = FxHasher::default()
    return (uint)(h >> 32);  // Top 32 bits
}

/// O(1) Xor Filter membership test
inline bool xor_filter_contains(
    thread uchar* hash,
    constant uint* fingerprints,
    constant ulong* seeds,
    uint block_length
) {
    // Compute fingerprint
    uint fp = xor_fingerprint(hash);
    
    // Hash to 3 positions (one per block)
    uint h0 = xor_hash_to_block(hash, seeds, block_length, 0);
    uint h1 = xor_hash_to_block(hash, seeds, block_length, 1);
    uint h2 = xor_hash_to_block(hash, seeds, block_length, 2);
    
    // XOR the 3 fingerprints and compare
    uint xor_val = fingerprints[h0] ^ fingerprints[h1] ^ fingerprints[h2];
    
    return xor_val == fp;
}

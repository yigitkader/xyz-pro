// src/filter/xor_lookup.metal
// GPU-side Xor Filter lookup - O(1) constant time
// 3 memory accesses + 2 XOR operations = ~6 cycles

// ============================================================================
// FxHash implementation for GPU
// CRITICAL: Must EXACTLY match Rust FxHasher from fxhash crate!
//
// FIX (2025-12-22): Use byte copying instead of bit shifting to avoid
// integer promotion issues on GPU. This ensures exact match with CPU.
// ============================================================================

/// Rotate left helper (matches Rust u64::rotate_left)
inline ulong rotate_left_5(ulong x) {
    return (x << 5) | (x >> 59);
}

/// Process u64 as a single word (matches Rust FxHasher::write_u64)
inline ulong fx_hash_u64(ulong value, ulong hash) {
    hash = rotate_left_5(hash) ^ value;
    return hash * 0x517cc1b727220a95UL;
}

/// Process u32 as a single word
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
/// FIXED: Uses byte copying instead of bit shifting to avoid GPU integer promotion bugs
inline ulong fx_hash_bytes(thread uchar* data, uint len, ulong hash) {
    uint i = 0;
    
    // Process 8-byte chunks - use byte copy for correct endianness
    while (i + 8 <= len) {
        ulong chunk;
        // Copy bytes into chunk (little-endian: first byte = LSB)
        thread uchar* chunk_bytes = (thread uchar*)&chunk;
        chunk_bytes[0] = data[i];
        chunk_bytes[1] = data[i+1];
        chunk_bytes[2] = data[i+2];
        chunk_bytes[3] = data[i+3];
        chunk_bytes[4] = data[i+4];
        chunk_bytes[5] = data[i+5];
        chunk_bytes[6] = data[i+6];
        chunk_bytes[7] = data[i+7];
        
        hash = fx_hash_u64(chunk, hash);
        i += 8;
    }
    
    // Process remaining 4 bytes
    if (i + 4 <= len) {
        uint chunk;
        thread uchar* chunk_bytes = (thread uchar*)&chunk;
        chunk_bytes[0] = data[i];
        chunk_bytes[1] = data[i+1];
        chunk_bytes[2] = data[i+2];
        chunk_bytes[3] = data[i+3];
        
        hash = fx_hash_u32(chunk, hash);
        i += 4;
    }
    
    // Process remaining 2 bytes
    if (i + 2 <= len) {
        ushort chunk;
        thread uchar* chunk_bytes = (thread uchar*)&chunk;
        chunk_bytes[0] = data[i];
        chunk_bytes[1] = data[i+1];
        
        hash = fx_hash_u16(chunk, hash);
        i += 2;
    }
    
    // Process remaining 1 byte
    if (i < len) {
        hash = fx_hash_u8(data[i], hash);
    }
    
    return hash;
}

/// FxHash overload for constant address space
inline ulong fx_hash_bytes(constant uchar* data, uint len, ulong hash) {
    uint i = 0;
    
    // Process 8-byte chunks
    while (i + 8 <= len) {
        ulong chunk;
        thread uchar* chunk_bytes = (thread uchar*)&chunk;
        chunk_bytes[0] = data[i];
        chunk_bytes[1] = data[i+1];
        chunk_bytes[2] = data[i+2];
        chunk_bytes[3] = data[i+3];
        chunk_bytes[4] = data[i+4];
        chunk_bytes[5] = data[i+5];
        chunk_bytes[6] = data[i+6];
        chunk_bytes[7] = data[i+7];
        
        hash = fx_hash_u64(chunk, hash);
        i += 8;
    }
    
    // Process remaining 4 bytes
    if (i + 4 <= len) {
        uint chunk;
        thread uchar* chunk_bytes = (thread uchar*)&chunk;
        chunk_bytes[0] = data[i];
        chunk_bytes[1] = data[i+1];
        chunk_bytes[2] = data[i+2];
        chunk_bytes[3] = data[i+3];
        
        hash = fx_hash_u32(chunk, hash);
        i += 4;
    }
    
    // Process remaining 2 bytes
    if (i + 2 <= len) {
        ushort chunk;
        thread uchar* chunk_bytes = (thread uchar*)&chunk;
        chunk_bytes[0] = data[i];
        chunk_bytes[1] = data[i+1];
        
        hash = fx_hash_u16(chunk, hash);
        i += 2;
    }
    
    // Process remaining 1 byte
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
    
    // Step 1: Process seed as u64 (single cycle)
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
    ulong h = fx_hash_bytes(hash, 20, 0);
    return (uint)(h >> 32);
}

/// O(1) Xor Filter membership test (legacy single-filter mode)
inline bool xor_filter_contains(
    thread uchar* hash,
    constant uint* fingerprints,
    constant ulong* seeds,
    uint block_length
) {
    uint fp = xor_fingerprint(hash);
    
    uint h0 = xor_hash_to_block(hash, seeds, block_length, 0);
    uint h1 = xor_hash_to_block(hash, seeds, block_length, 1);
    uint h2 = xor_hash_to_block(hash, seeds, block_length, 2);
    
    uint xor_val = fingerprints[h0] ^ fingerprints[h1] ^ fingerprints[h2];
    
    return xor_val == fp;
}

// ============================================================================
// SHARDED XOR FILTER (4096 shards)
// 
// Each shard has its own seed and block_length.
// Shard ID = (hash[0] << 4) | (hash[1] >> 4)  (12-bit = 4096 shards)
// 
// Memory layout:
// - shard_info: 4096 entries × (offset:u32, block_len:u32, seed:u64) = 16 bytes each
// - fingerprints: all shard fingerprints concatenated
// ============================================================================

/// Sharded Xor Filter lookup
/// shard_info format: [offset_low, offset_high_and_block_len, seed_low, seed_high] per shard
/// Actually: [offset:u64, block_len:u32, seed:u64] = 20 bytes per shard
inline bool xor_filter_contains_sharded(
    thread uchar* hash,
    constant uint* fingerprints,
    constant uint* shard_info,  // 4096 shards × 5 u32 = 20480 u32s
    uint num_shards             // 4096
) {
    // Calculate shard ID from first 12 bits of hash
    uint shard_id = ((uint)hash[0] << 4) | ((uint)hash[1] >> 4);
    if (shard_id >= num_shards) shard_id = num_shards - 1;  // Safety
    
    // Read shard metadata (5 u32 per shard = 20 bytes)
    uint base_idx = shard_id * 5;
    uint offset_lo = shard_info[base_idx];
    uint offset_hi = shard_info[base_idx + 1];
    uint block_len = shard_info[base_idx + 2];
    uint seed_lo = shard_info[base_idx + 3];
    uint seed_hi = shard_info[base_idx + 4];
    
    ulong offset = ((ulong)offset_hi << 32) | (ulong)offset_lo;
    ulong seed = ((ulong)seed_hi << 32) | (ulong)seed_lo;
    
    // Empty shard check
    if (block_len == 0) return false;
    
    // Compute fingerprint
    uint fp = xor_fingerprint(hash);
    
    // Compute 3 hash positions within this shard
    // seeds[0] = seed, seeds[1] = seed ^ 0xc3a5c85c97cb3127
    ulong seeds[3] = { seed, seed ^ 0xc3a5c85c97cb3127UL, 0 };
    
    // Hash to block positions (within shard)
    ulong h = fx_hash_u64(seeds[0], 0);
    h = fx_hash_bytes(hash, 20, h);
    uint h0 = (uint)(h % (ulong)block_len);
    
    h = fx_hash_u64(seeds[1], 0);
    h = fx_hash_bytes(hash, 20, h);
    uint h1 = block_len + (uint)(h % (ulong)block_len);
    
    h = fx_hash_u64(seeds[2], 0);
    h = fx_hash_bytes(hash, 20, h);
    uint h2 = 2 * block_len + (uint)(h % (ulong)block_len);
    
    // Add shard offset to get global fingerprint index
    uint shard_offset = (uint)offset;  // offset is in u32 units
    uint xor_val = fingerprints[shard_offset + h0] ^ 
                   fingerprints[shard_offset + h1] ^ 
                   fingerprints[shard_offset + h2];
    
    return xor_val == fp;
}

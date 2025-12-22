// src/filter/xor_lookup.metal
// GPU-side Xor Filter lookup - O(1) constant time
// 3 memory accesses + 2 XOR operations = ~6 cycles

// ============================================================================
// FxHash implementation for GPU
// CRITICAL: Must EXACTLY match Rust FxHasher from fxhash crate!
//
// Rust FxHasher algorithm:
//   hash = hash.rotate_left(5) ^ word;
//   hash = hash.wrapping_mul(0x517cc1b727220a95);
//
// CRITICAL BUG FIX (2025-12-22):
//   Previous: GPU used single XOR for u64 seed (h ^ seed)
//   Correct: Process u64 as 8 BYTES in little-endian order
//   Impact: 99.9% of matches were missed due to wrong Xor positions!
// ============================================================================

/// Rotate left helper (matches Rust u64::rotate_left)
inline ulong rotate_left_5(ulong x) {
    return (x << 5) | (x >> 59);  // 64-bit rotate left by 5
}

/// NEW: Process u64 as 8 bytes (matches Rust FxHasher::write_u64)
/// CRITICAL: Rust processes u64 as 8 BYTES in LITTLE-ENDIAN order, not single XOR!
inline ulong fx_hash_u64(ulong value, ulong initial) {
    ulong hash = initial;
    
    // Process each byte in little-endian order
    // This matches: hasher.write(&seed.to_le_bytes())
    for (int i = 0; i < 8; i++) {
        ulong byte = (value >> (i * 8)) & 0xFF;
        hash = rotate_left_5(hash) ^ byte;
        hash = hash * 0x517cc1b727220a95UL;
    }
    
    return hash;
}

/// FxHash implementation matching Rust FxHasher EXACTLY
/// CRITICAL: Must process remaining bytes in 4, 2, 1 byte chunks (not all at once!)
///
/// Rust FxHasher::write() algorithm:
///   while bytes.len() >= 8: process 8 bytes
///   if bytes.len() >= 4: process 4 bytes
///   if bytes.len() >= 2: process 2 bytes  
///   if bytes.len() >= 1: process 1 byte
///
/// Overload for constant address space (kernel parameters)
inline ulong fx_hash(constant uchar* data, uint len, ulong initial) {
    ulong hash = initial;
    uint i = 0;
    
    // Process 8-byte chunks (little-endian)
    while (i + 8 <= len) {
        ulong chunk = ((ulong)data[i]) | ((ulong)data[i+1] << 8) | 
                     ((ulong)data[i+2] << 16) | ((ulong)data[i+3] << 24) |
                     ((ulong)data[i+4] << 32) | ((ulong)data[i+5] << 40) |
                     ((ulong)data[i+6] << 48) | ((ulong)data[i+7] << 56);
        
        hash = rotate_left_5(hash) ^ chunk;
        hash = hash * 0x517cc1b727220a95UL;
        i += 8;
    }
    
    // Process remaining 4 bytes (if any)
    if (i + 4 <= len) {
        ulong chunk = ((ulong)data[i]) | ((ulong)data[i+1] << 8) | 
                     ((ulong)data[i+2] << 16) | ((ulong)data[i+3] << 24);
        hash = rotate_left_5(hash) ^ chunk;
        hash = hash * 0x517cc1b727220a95UL;
        i += 4;
    }
    
    // Process remaining 2 bytes (if any)
    if (i + 2 <= len) {
        ulong chunk = ((ulong)data[i]) | ((ulong)data[i+1] << 8);
        hash = rotate_left_5(hash) ^ chunk;
        hash = hash * 0x517cc1b727220a95UL;
        i += 2;
    }
    
    // Process remaining 1 byte (if any)
    if (i < len) {
        ulong chunk = (ulong)data[i];
        hash = rotate_left_5(hash) ^ chunk;
        hash = hash * 0x517cc1b727220a95UL;
    }
    
    return hash;
}

/// FxHash overload for thread address space (local computed hashes)
inline ulong fx_hash(thread uchar* data, uint len, ulong initial) {
    ulong hash = initial;
    uint i = 0;
    
    // Process 8-byte chunks (little-endian)
    while (i + 8 <= len) {
        ulong chunk = ((ulong)data[i]) | ((ulong)data[i+1] << 8) | 
                     ((ulong)data[i+2] << 16) | ((ulong)data[i+3] << 24) |
                     ((ulong)data[i+4] << 32) | ((ulong)data[i+5] << 40) |
                     ((ulong)data[i+6] << 48) | ((ulong)data[i+7] << 56);
        
        hash = rotate_left_5(hash) ^ chunk;
        hash = hash * 0x517cc1b727220a95UL;
        i += 8;
    }
    
    // Process remaining 4 bytes (if any)
    if (i + 4 <= len) {
        ulong chunk = ((ulong)data[i]) | ((ulong)data[i+1] << 8) | 
                     ((ulong)data[i+2] << 16) | ((ulong)data[i+3] << 24);
        hash = rotate_left_5(hash) ^ chunk;
        hash = hash * 0x517cc1b727220a95UL;
        i += 4;
    }
    
    // Process remaining 2 bytes (if any)
    if (i + 2 <= len) {
        ulong chunk = ((ulong)data[i]) | ((ulong)data[i+1] << 8);
        hash = rotate_left_5(hash) ^ chunk;
        hash = hash * 0x517cc1b727220a95UL;
        i += 2;
    }
    
    // Process remaining 1 byte (if any)
    if (i < len) {
        ulong chunk = (ulong)data[i];
        hash = rotate_left_5(hash) ^ chunk;
        hash = hash * 0x517cc1b727220a95UL;
    }
    
    return hash;
}

/// Hash to specific block (0, 1, or 2)
/// FIXED: CPU does hasher.write_u64(seed) then hasher.write(hash)
/// This means seed is processed AS 8 BYTES, not as single XOR!
inline uint xor_hash_to_block(thread uchar* hash, 
                              constant ulong* seeds,
                              uint block_length,
                              uint block_id) {
    // Match CPU: FxHasher::default() then write_u64(seed) then write(hash)
    // FxHasher::default() initializes to 0
    // write_u64(seed) processes seed as 8 bytes (FIXED!)
    // write(hash) processes hash as 20 bytes
    
    ulong h = 0;  // FxHasher::default()
    
    // FIXED: Process seed as 8 bytes (match Rust FxHasher::write_u64)
    // Previous bug: h = h ^ seeds[block_id] (single XOR)
    // Correct: Process each byte separately
    ulong seed = seeds[block_id];
    h = fx_hash_u64(seed, h);  // ← NEW: Process as 8 bytes!
    
    // Then process hash (write) - reuse fx_hash logic
    h = fx_hash(hash, 20, h);  // Continue from current hash state
    
    uint pos = (uint)(h % (ulong)block_length);
    return block_id * block_length + pos;
}

/// Compute 32-bit fingerprint (reduced collision risk for large target sets)
/// CRITICAL: CPU does hasher.write(hash) only - no seed
inline uint xor_fingerprint(thread uchar* hash) {
    // Match CPU: FxHasher::default() then write(hash)
    ulong h = fx_hash(hash, 20, 0);  // Initial = 0 = default
    return (uint)(h >> 32);  // Top 32 bits
}

/// O(1) Xor Filter membership test
/// Returns true if hash *might* be in set (may have false positives)
/// Returns false if hash is *definitely not* in set (no false negatives)
inline bool xor_filter_contains(
    thread uchar* hash,
    constant uint* fingerprints,  // Fingerprint table (32-bit for lower collision risk)
    constant ulong* seeds,          // 3 hash seeds
    uint block_length              // Size of each block
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

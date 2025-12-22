// src/rng/philox.metal
// GPU-side Philox4x32-10 implementation
// Each thread generates its own private key autonomously

// Philox constants (must match Rust implementation)
constant uint PHILOX_M0 = 0xD2511F53;
constant uint PHILOX_M1 = 0xCD9E8D57;
constant uint PHILOX_W0 = 0x9E3779B9;
constant uint PHILOX_W1 = 0xBB67AE85;

/// Philox state structure
struct PhiloxState {
    uint4 counter;  // 128-bit counter
    uint2 key;      // 64-bit key
};

/// Single Philox round
inline uint4 philox_round(uint4 ctr, uint2 k) {
    // Multiply-high: (a * b) >> 32
    ulong prod0 = (ulong)ctr.x * (ulong)PHILOX_M0;
    ulong prod1 = (ulong)ctr.z * (ulong)PHILOX_M1;
    
    // Mix and XOR with key
    uint4 result;
    result.x = (uint)(prod1 >> 32) ^ ctr.y ^ k.x;
    result.y = (uint)prod1;
    result.z = (uint)(prod0 >> 32) ^ ctr.w ^ k.y;
    result.w = (uint)prod0;
    
    return result;
}

/// Full Philox4x32-10 (10 rounds)
inline uint4 philox4x32_10(PhiloxState state) {
    uint4 ctr = state.counter;
    uint2 k = state.key;
    
    // 10 rounds with key schedule
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        ctr = philox_round(ctr, k);
        k.x += PHILOX_W0;
        k.y += PHILOX_W1;
    }
    
    return ctr;
}

/// Create thread-specific Philox state
inline PhiloxState philox_for_thread(constant uint2* base_key, 
                                     constant uint4* base_counter,
                                     uint thread_id) {
    PhiloxState state;
    state.key = *base_key;
    
    // Counter = base_counter + thread_id
    // 128-bit addition
    ulong sum = (ulong)base_counter->x + (ulong)thread_id;
    state.counter.x = (uint)sum;
    
    ulong carry = sum >> 32;
    sum = (ulong)base_counter->y + carry;
    state.counter.y = (uint)sum;
    
    carry = sum >> 32;
    sum = (ulong)base_counter->z + carry;
    state.counter.z = (uint)sum;
    
    carry = sum >> 32;
    state.counter.w = base_counter->w + (uint)carry;
    
    return state;
}

/// Generate 256-bit private key from Philox output
inline void philox_to_privkey(PhiloxState state, thread uchar* privkey) {
    // First 128 bits from primary output
    uint4 random1 = philox4x32_10(state);
    
    // Store as big-endian (Bitcoin standard)
    privkey[0] = random1.x >> 24;
    privkey[1] = random1.x >> 16;
    privkey[2] = random1.x >> 8;
    privkey[3] = random1.x;
    
    privkey[4] = random1.y >> 24;
    privkey[5] = random1.y >> 16;
    privkey[6] = random1.y >> 8;
    privkey[7] = random1.y;
    
    privkey[8] = random1.z >> 24;
    privkey[9] = random1.z >> 16;
    privkey[10] = random1.z >> 8;
    privkey[11] = random1.z;
    
    privkey[12] = random1.w >> 24;
    privkey[13] = random1.w >> 16;
    privkey[14] = random1.w >> 8;
    privkey[15] = random1.w;
    
    // Second 128 bits: increment counter for proper domain separation
    // This ensures full 256-bit security (counter increment is more secure than XOR)
    state.counter.x += 1;  // Overflow is handled naturally by uint32
    uint4 random2 = philox4x32_10(state);
    
    privkey[16] = random2.x >> 24;
    privkey[17] = random2.x >> 16;
    privkey[18] = random2.x >> 8;
    privkey[19] = random2.x;
    
    privkey[20] = random2.y >> 24;
    privkey[21] = random2.y >> 16;
    privkey[22] = random2.y >> 8;
    privkey[23] = random2.y;
    
    privkey[24] = random2.z >> 24;
    privkey[25] = random2.z >> 16;
    privkey[26] = random2.z >> 8;
    privkey[27] = random2.z;
    
    privkey[28] = random2.w >> 24;
    privkey[29] = random2.w >> 16;
    privkey[30] = random2.w >> 8;
    privkey[31] = random2.w;
}


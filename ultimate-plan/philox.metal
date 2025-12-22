// src/rng/philox.metal
// GPU-side Philox4x32-10 implementation
// Each thread generates its own private key autonomously

#include <metal_stdlib>
using namespace metal;

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
    
    // Second 128 bits: domain-separated output
    state.counter.x ^= 0xDEADBEEF;
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

/// Test kernel: generate keys and verify determinism
kernel void test_philox_generation(
    constant uint2* base_key [[buffer(0)]],
    constant uint4* base_counter [[buffer(1)]],
    device uchar* output_keys [[buffer(2)]],    // 32 bytes per thread
    device uint4* debug_randoms [[buffer(3)]],  // For verification
    uint gid [[thread_position_in_grid]]
) {
    // Generate thread-specific state
    PhiloxState state = philox_for_thread(base_key, base_counter, gid);
    
    // Generate private key
    thread uchar privkey[32];
    philox_to_privkey(state, privkey);
    
    // Write to output
    device uchar* out = output_keys + (gid * 32);
    for (int i = 0; i < 32; i++) {
        out[i] = privkey[i];
    }
    
    // Store raw random for debugging
    debug_randoms[gid] = philox4x32_10(state);
}

/// Validate against CPU reference
/// This kernel compares GPU output with CPU-generated keys
kernel void validate_philox_cpu_match(
    constant uint2* base_key [[buffer(0)]],
    constant uint4* base_counter [[buffer(1)]],
    constant uchar* cpu_keys [[buffer(2)]],     // Expected from CPU
    device uint* mismatch_count [[buffer(3)]],  // Atomic counter
    uint gid [[thread_position_in_grid]]
) {
    PhiloxState state = philox_for_thread(base_key, base_counter, gid);
    
    thread uchar gpu_key[32];
    philox_to_privkey(state, gpu_key);
    
    // Compare with CPU key
    constant uchar* cpu_key = cpu_keys + (gid * 32);
    
    for (int i = 0; i < 32; i++) {
        if (gpu_key[i] != cpu_key[i]) {
            atomic_fetch_add_explicit((device atomic_uint*)mismatch_count, 1, memory_order_relaxed);
            return;  // Early exit on first mismatch
        }
    }
}

/// Performance benchmark kernel
/// Measures pure Philox throughput (keys/sec)
kernel void benchmark_philox(
    constant uint2* base_key [[buffer(0)]],
    constant uint4* base_counter [[buffer(1)]],
    device ulong* output_count [[buffer(2)]],  // Total keys generated
    uint iterations [[buffer(3)]],             // Keys per thread
    uint gid [[thread_position_in_grid]]
) {
    PhiloxState state = philox_for_thread(base_key, base_counter, gid);
    
    // Generate many keys (compiler should optimize loop)
    #pragma unroll 4
    for (uint i = 0; i < iterations; i++) {
        thread uchar key[32];
        philox_to_privkey(state, key);
        
        // Increment counter for next key
        state.counter.x++;
        if (state.counter.x == 0) {
            state.counter.y++;
            if (state.counter.y == 0) {
                state.counter.z++;
                if (state.counter.z == 0) {
                    state.counter.w++;
                }
            }
        }
    }
    
    // Report count (atomic add)
    atomic_fetch_add_explicit((device atomic_ulong*)output_count, iterations, memory_order_relaxed);
}
#include <metal_stdlib>
using namespace metal;

// SHA256 Constants
constant uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Initial hash values
constant uint H_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

inline uint rotr(uint x, uint n) {
    return (x >> n) | (x << (32 - n));
}

inline uint Ch(uint x, uint y, uint z) {
    return (x & y) ^ (~x & z);
}

inline uint Maj(uint x, uint y, uint z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint Sigma0(uint x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint Sigma1(uint x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint sigma0(uint x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint sigma1(uint x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

inline uint load_be32(device const uchar* ptr) {
    return (uint(ptr[0]) << 24) | (uint(ptr[1]) << 16) |
           (uint(ptr[2]) << 8) | uint(ptr[3]);
}

inline void store_be32(device uchar* ptr, uint val) {
    ptr[0] = val >> 24;
    ptr[1] = val >> 16;
    ptr[2] = val >> 8;
    ptr[3] = val;
}

// SHA256 for 33-byte compressed public keys
kernel void sha256_hash(
    device const uchar* input [[buffer(0)]],
    device uchar* output [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
)
{
    device const uchar* pubkey = input + (gid * 33);
    uint w[64];

    // Load first 8 words (32 bytes)
    w[0] = load_be32(pubkey);
    w[1] = load_be32(pubkey + 4);
    w[2] = load_be32(pubkey + 8);
    w[3] = load_be32(pubkey + 12);
    w[4] = load_be32(pubkey + 16);
    w[5] = load_be32(pubkey + 20);
    w[6] = load_be32(pubkey + 24);
    w[7] = load_be32(pubkey + 28);

    // Word 8: byte 32 + padding bit
    w[8] = (uint(pubkey[32]) << 24) | 0x00800000;

    // Words 9-14: zeros (padding)
    w[9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;

    // Word 15: message length in bits (33 * 8 = 264)
    w[15] = 264;

    // Message schedule extension
    #pragma unroll
    for (uint i = 16; i < 64; i++) {
        w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
    }

    // Initialize working variables
    uint a = H_INIT[0];
    uint b = H_INIT[1];
    uint c = H_INIT[2];
    uint d = H_INIT[3];
    uint e = H_INIT[4];
    uint f = H_INIT[5];
    uint g = H_INIT[6];
    uint h = H_INIT[7];

    // Main compression loop
    #pragma unroll
    for (uint i = 0; i < 64; i++) {
        uint T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + w[i];
        uint T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // Add to hash value
    uint h0 = H_INIT[0] + a;
    uint h1 = H_INIT[1] + b;
    uint h2 = H_INIT[2] + c;
    uint h3 = H_INIT[3] + d;
    uint h4 = H_INIT[4] + e;
    uint h5 = H_INIT[5] + f;
    uint h6 = H_INIT[6] + g;
    uint h7 = H_INIT[7] + h;

    // Output hash
    device uchar* out = output + (gid * 32);
    store_be32(out, h0);
    store_be32(out + 4, h1);
    store_be32(out + 8, h2);
    store_be32(out + 12, h3);
    store_be32(out + 16, h4);
    store_be32(out + 20, h5);
    store_be32(out + 24, h6);
    store_be32(out + 28, h7);
}


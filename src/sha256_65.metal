#include <metal_stdlib>
using namespace metal;

// SHA256 for 65-byte uncompressed public keys (0x04 || x || y)

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

constant uint H_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

inline uint rotr(uint x, uint n) { return (x >> n) | (x << (32 - n)); }
inline uint Ch(uint x, uint y, uint z) { return (x & y) ^ (~x & z); }
inline uint Maj(uint x, uint y, uint z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint Sigma0(uint x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint Sigma1(uint x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
inline uint sigma0(uint x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
inline uint sigma1(uint x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

inline uint load_be32(device const uchar* p) {
    return (uint(p[0]) << 24) | (uint(p[1]) << 16) | (uint(p[2]) << 8) | uint(p[3]);
}

inline void store_be32(device uchar* p, uint v) {
    p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

kernel void sha256_hash_65(
    device const uchar* input [[buffer(0)]],
    device uchar* output [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    device const uchar* data = input + (gid * 65);
    uint w[64];

    // Block 1: bytes 0-63
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        w[i] = load_be32(data + i * 4);
    }

    #pragma unroll
    for (uint i = 16; i < 64; i++) {
        w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
    }

    uint a = H_INIT[0], b = H_INIT[1], c = H_INIT[2], d = H_INIT[3];
    uint e = H_INIT[4], f = H_INIT[5], g = H_INIT[6], h = H_INIT[7];

    #pragma unroll
    for (uint i = 0; i < 64; i++) {
        uint T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + w[i];
        uint T2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    uint h0 = H_INIT[0] + a, h1 = H_INIT[1] + b;
    uint h2 = H_INIT[2] + c, h3 = H_INIT[3] + d;
    uint h4 = H_INIT[4] + e, h5 = H_INIT[5] + f;
    uint h6 = H_INIT[6] + g, h7 = H_INIT[7] + h;

    // Block 2: byte 64 + padding + length
    w[0] = (uint(data[64]) << 24) | 0x00800000;
    #pragma unroll
    for (int i = 1; i < 15; i++) w[i] = 0;
    w[15] = 520; // 65 * 8 bits

    #pragma unroll
    for (uint i = 16; i < 64; i++) {
        w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
    }

    a = h0; b = h1; c = h2; d = h3;
    e = h4; f = h5; g = h6; h = h7;

    #pragma unroll
    for (uint i = 0; i < 64; i++) {
        uint T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + w[i];
        uint T2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    h0 += a; h1 += b; h2 += c; h3 += d;
    h4 += e; h5 += f; h6 += g; h7 += h;

    device uchar* out = output + (gid * 32);
    store_be32(out, h0);      store_be32(out + 4, h1);
    store_be32(out + 8, h2);  store_be32(out + 12, h3);
    store_be32(out + 16, h4); store_be32(out + 20, h5);
    store_be32(out + 24, h6); store_be32(out + 28, h7);
}


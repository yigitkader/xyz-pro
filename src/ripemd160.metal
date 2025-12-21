#include <metal_stdlib>
using namespace metal;

// RIPEMD-160 Constants
constant uint KL[5] = { 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
constant uint KR[5] = { 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

constant uchar RL[80] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
};

constant uchar RR[80] = {
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};

constant uchar SL[80] = {
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};

constant uchar SR[80] = {
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

constant uint H_INIT[5] = {
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
};

inline uint rotl(uint x, uint n) {
    return (x << n) | (x >> (32 - n));
}

inline uint f0(uint x, uint y, uint z) { return x ^ y ^ z; }
inline uint f1(uint x, uint y, uint z) { return (x & y) | (~x & z); }
inline uint f2(uint x, uint y, uint z) { return (x | ~y) ^ z; }
inline uint f3(uint x, uint y, uint z) { return (x & z) | (y & ~z); }
inline uint f4(uint x, uint y, uint z) { return x ^ (y | ~z); }

inline uint load_le32(device const uchar* ptr) {
    return uint(ptr[0]) | (uint(ptr[1]) << 8) |
           (uint(ptr[2]) << 16) | (uint(ptr[3]) << 24);
}

inline void store_le32(device uchar* ptr, uint val) {
    ptr[0] = val;
    ptr[1] = val >> 8;
    ptr[2] = val >> 16;
    ptr[3] = val >> 24;
}

// RIPEMD160 for 32-byte input (SHA256 output)
kernel void ripemd160_hash(
    device const uchar* input [[buffer(0)]],
    device uchar* output [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    device const uchar* data = input + (gid * 32);

    uint w[16];
    w[0] = load_le32(data);
    w[1] = load_le32(data + 4);
    w[2] = load_le32(data + 8);
    w[3] = load_le32(data + 12);
    w[4] = load_le32(data + 16);
    w[5] = load_le32(data + 20);
    w[6] = load_le32(data + 24);
    w[7] = load_le32(data + 28);

    // Padding
    w[8] = 0x00000080;
    w[9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 256; // 32 * 8 bits
    w[15] = 0;

    uint al = H_INIT[0], bl = H_INIT[1], cl = H_INIT[2], dl = H_INIT[3], el = H_INIT[4];
    uint ar = H_INIT[0], br = H_INIT[1], cr = H_INIT[2], dr = H_INIT[3], er = H_INIT[4];

    // Round 0 (j = 0-15)
    #pragma unroll
    for (uint j = 0; j < 16; j++) {
        uint fl = f0(bl, cl, dl);
        uint tl = rotl(al + fl + w[RL[j]] + KL[0], SL[j]) + el;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = tl;

        uint fr = f4(br, cr, dr);
        uint tr = rotl(ar + fr + w[RR[j]] + KR[0], SR[j]) + er;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = tr;
    }

    // Round 1 (j = 16-31)
    #pragma unroll
    for (uint j = 16; j < 32; j++) {
        uint fl = f1(bl, cl, dl);
        uint tl = rotl(al + fl + w[RL[j]] + KL[1], SL[j]) + el;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = tl;

        uint fr = f3(br, cr, dr);
        uint tr = rotl(ar + fr + w[RR[j]] + KR[1], SR[j]) + er;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = tr;
    }

    // Round 2 (j = 32-47)
    #pragma unroll
    for (uint j = 32; j < 48; j++) {
        uint fl = f2(bl, cl, dl);
        uint tl = rotl(al + fl + w[RL[j]] + KL[2], SL[j]) + el;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = tl;

        uint fr = f2(br, cr, dr);
        uint tr = rotl(ar + fr + w[RR[j]] + KR[2], SR[j]) + er;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = tr;
    }

    // Round 3 (j = 48-63)
    #pragma unroll
    for (uint j = 48; j < 64; j++) {
        uint fl = f3(bl, cl, dl);
        uint tl = rotl(al + fl + w[RL[j]] + KL[3], SL[j]) + el;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = tl;

        uint fr = f1(br, cr, dr);
        uint tr = rotl(ar + fr + w[RR[j]] + KR[3], SR[j]) + er;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = tr;
    }

    // Round 4 (j = 64-79)
    #pragma unroll
    for (uint j = 64; j < 80; j++) {
        uint fl = f4(bl, cl, dl);
        uint tl = rotl(al + fl + w[RL[j]] + KL[4], SL[j]) + el;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = tl;

        uint fr = f0(br, cr, dr);
        uint tr = rotl(ar + fr + w[RR[j]] + KR[4], SR[j]) + er;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = tr;
    }

    // Final addition
    uint t = H_INIT[1] + cl + dr;
    uint h1 = H_INIT[2] + dl + er;
    uint h2 = H_INIT[3] + el + ar;
    uint h3 = H_INIT[4] + al + br;
    uint h4 = H_INIT[0] + bl + cr;
    uint h0 = t;

    device uchar* out = output + (gid * 20);
    store_le32(out, h0);
    store_le32(out + 4, h1);
    store_le32(out + 8, h2);
    store_le32(out + 12, h3);
    store_le32(out + 16, h4);
}


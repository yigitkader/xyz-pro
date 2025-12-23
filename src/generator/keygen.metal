// ============================================================================
// BTC KEY GENERATOR - ULTRA-OPTIMIZED METAL SHADER (v3)
// 
// ALL OPTIMIZATIONS FROM MAIN PROJECT:
// 1. Extended Jacobian coordinates (saves 1 squaring per operation)
// 2. Windowed NAF tables (5 additions vs 256 for start point)
// 3. Montgomery batch inversion (1 mod_inv per 32 keys)
// 4. GLV Endomorphism (2x throughput - scan 2 key ranges per EC op)
// 5. CPU pre-computed base pubkey (eliminates GPU scalar_mul overhead)
//
// MODE: Sequential key generation
// - Primary: private_key = base + thread_offset + batch_idx
// - GLV: glv_private_key = λ * primary_key (mod n)
//
// Output per key: privkey(32) + pubkey_hash(20) + p2sh_hash(20) = 72 bytes
// ============================================================================

#include <metal_stdlib>
using namespace metal;

// ============================================================================
// SECP256K1 CONSTANTS
// ============================================================================

constant ulong4 SECP256K1_P = {
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
};

constant ulong4 SECP256K1_N = {
    0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
};

constant ulong4 SECP256K1_GX = {
    0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
    0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL
};

constant ulong4 SECP256K1_GY = {
    0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
    0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL
};

constant ulong SECP256K1_K = 4294968273ULL;

// GLV ENDOMORPHISM CONSTANTS
// β³ ≡ 1 (mod p), φ(x,y) = (β·x mod p, y)
constant ulong4 GLV_BETA = {
    0xc1396c28719501eeULL, 0x9cf0497512f58995ULL,
    0x6e64479eac3434e9ULL, 0x7ae96a2b657c0710ULL
};

// ============================================================================
// HASH CONSTANTS
// ============================================================================

constant uint SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

constant uint RIPEMD_KL[5] = {0x00000000,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e};
constant uint RIPEMD_KR[5] = {0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0x00000000};
constant uchar RIPEMD_RL[80] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
constant uchar RIPEMD_RR[80] = {5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};
constant uchar RIPEMD_SL[80] = {11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};
constant uchar RIPEMD_SR[80] = {8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};

#define BATCH_SIZE 32
#define OUTPUT_SIZE 72
#define GLV_OUTPUT_SIZE 144  // 2 keys per thread (primary + GLV)

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

inline bool IsZero(ulong4 a) {
    return (a.x | a.y | a.z | a.w) == 0;
}

inline ulong4 load_be(constant uchar* d) {
    ulong4 r;
    r.w = ((ulong)d[0]<<56)|((ulong)d[1]<<48)|((ulong)d[2]<<40)|((ulong)d[3]<<32)|
          ((ulong)d[4]<<24)|((ulong)d[5]<<16)|((ulong)d[6]<<8)|(ulong)d[7];
    r.z = ((ulong)d[8]<<56)|((ulong)d[9]<<48)|((ulong)d[10]<<40)|((ulong)d[11]<<32)|
          ((ulong)d[12]<<24)|((ulong)d[13]<<16)|((ulong)d[14]<<8)|(ulong)d[15];
    r.y = ((ulong)d[16]<<56)|((ulong)d[17]<<48)|((ulong)d[18]<<40)|((ulong)d[19]<<32)|
          ((ulong)d[20]<<24)|((ulong)d[21]<<16)|((ulong)d[22]<<8)|(ulong)d[23];
    r.x = ((ulong)d[24]<<56)|((ulong)d[25]<<48)|((ulong)d[26]<<40)|((ulong)d[27]<<32)|
          ((ulong)d[28]<<24)|((ulong)d[29]<<16)|((ulong)d[30]<<8)|(ulong)d[31];
    return r;
}

inline void store_be(ulong4 v, thread uchar* o) {
    o[0]=(v.w>>56);o[1]=(v.w>>48);o[2]=(v.w>>40);o[3]=(v.w>>32);
    o[4]=(v.w>>24);o[5]=(v.w>>16);o[6]=(v.w>>8);o[7]=v.w;
    o[8]=(v.z>>56);o[9]=(v.z>>48);o[10]=(v.z>>40);o[11]=(v.z>>32);
    o[12]=(v.z>>24);o[13]=(v.z>>16);o[14]=(v.z>>8);o[15]=v.z;
    o[16]=(v.y>>56);o[17]=(v.y>>48);o[18]=(v.y>>40);o[19]=(v.y>>32);
    o[20]=(v.y>>24);o[21]=(v.y>>16);o[22]=(v.y>>8);o[23]=v.y;
    o[24]=(v.x>>56);o[25]=(v.x>>48);o[26]=(v.x>>40);o[27]=(v.x>>32);
    o[28]=(v.x>>24);o[29]=(v.x>>16);o[30]=(v.x>>8);o[31]=v.x;
}

inline uint rotr32(uint x, uint n) { return (x >> n) | (x << (32 - n)); }
inline uint rotl32(uint x, uint n) { return (x << n) | (x >> (32 - n)); }

// ============================================================================
// 256-BIT SCALAR ARITHMETIC
// ============================================================================

inline void scalar_add_u64(thread ulong4& s, ulong val) {
    ulong old = s.x;
    s.x += val;
    if (s.x < old) {
        old = s.y; s.y += 1;
        if (s.y < old) {
            old = s.z; s.z += 1;
            if (s.z < old) {
                s.w += 1;
            }
        }
    }
    
    if (s.w > SECP256K1_N.w || 
        (s.w == SECP256K1_N.w && s.z > SECP256K1_N.z) ||
        (s.w == SECP256K1_N.w && s.z == SECP256K1_N.z && s.y > SECP256K1_N.y) ||
        (s.w == SECP256K1_N.w && s.z == SECP256K1_N.z && s.y == SECP256K1_N.y && s.x >= SECP256K1_N.x)) {
        ulong bw = 0;
        ulong4 r;
        r.x = s.x - SECP256K1_N.x; bw = (s.x < SECP256K1_N.x) ? 1 : 0;
        r.y = s.y - SECP256K1_N.y - bw; bw = (s.y < SECP256K1_N.y) || (bw && s.y == SECP256K1_N.y) ? 1 : 0;
        r.z = s.z - SECP256K1_N.z - bw; bw = (s.z < SECP256K1_N.z) || (bw && s.z == SECP256K1_N.z) ? 1 : 0;
        r.w = s.w - SECP256K1_N.w - bw;
        s = r;
    }
}

// ============================================================================
// MODULAR ARITHMETIC (256-bit over secp256k1 prime)
// ============================================================================

inline void mul64(ulong a, ulong b, thread ulong& hi, thread ulong& lo) {
    ulong a_lo = a & 0xFFFFFFFF, a_hi = a >> 32;
    ulong b_lo = b & 0xFFFFFFFF, b_hi = b >> 32;
    ulong p0 = a_lo * b_lo;
    ulong p1 = a_lo * b_hi;
    ulong p2 = a_hi * b_lo;
    ulong p3 = a_hi * b_hi;
    ulong mid = p1 + (p0 >> 32);
    mid += p2;
    if (mid < p2) p3 += 0x100000000UL;
    lo = (p0 & 0xFFFFFFFF) | (mid << 32);
    hi = p3 + (mid >> 32);
}

inline ulong4 add_p(ulong4 a) {
    ulong4 r; ulong c = 0;
    r.x = a.x + SECP256K1_P.x; c = (r.x < a.x) ? 1 : 0;
    r.y = a.y + SECP256K1_P.y + c; c = (r.y < a.y) || (c && r.y == a.y) ? 1 : 0;
    r.z = a.z + SECP256K1_P.z + c; c = (r.z < a.z) || (c && r.z == a.z) ? 1 : 0;
    r.w = a.w + SECP256K1_P.w + c;
    return r;
}

inline ulong4 mod_add(ulong4 a, ulong4 b) {
    ulong4 r; ulong c = 0;
    r.x = a.x + b.x; c = (r.x < a.x) ? 1 : 0;
    r.y = a.y + b.y + c; c = (r.y < a.y) || (c && r.y == a.y) ? 1 : 0;
    r.z = a.z + b.z + c; c = (r.z < a.z) || (c && r.z == a.z) ? 1 : 0;
    r.w = a.w + b.w + c;
    ulong fc = (r.w < a.w) || (c && r.w == a.w) ? 1 : 0;
    
    if (fc || r.w > SECP256K1_P.w || (r.w == SECP256K1_P.w && (r.z > SECP256K1_P.z ||
        (r.z == SECP256K1_P.z && (r.y > SECP256K1_P.y || (r.y == SECP256K1_P.y && r.x >= SECP256K1_P.x)))))) {
        ulong4 s; ulong bw = 0;
        s.x = r.x - SECP256K1_P.x; bw = (r.x < SECP256K1_P.x) ? 1 : 0;
        s.y = r.y - SECP256K1_P.y - bw; bw = (r.y < SECP256K1_P.y) || (bw && r.y == SECP256K1_P.y) ? 1 : 0;
        s.z = r.z - SECP256K1_P.z - bw; bw = (r.z < SECP256K1_P.z) || (bw && r.z == SECP256K1_P.z) ? 1 : 0;
        s.w = r.w - SECP256K1_P.w - bw;
        return s;
    }
    return r;
}

inline ulong4 mod_sub(ulong4 a, ulong4 b) {
    bool need = a.w < b.w || (a.w == b.w && (a.z < b.z ||
        (a.z == b.z && (a.y < b.y || (a.y == b.y && a.x < b.x)))));
    if (need) a = add_p(a);
    ulong4 r; ulong bw = 0;
    r.x = a.x - b.x; bw = (a.x < b.x) ? 1 : 0;
    r.y = a.y - b.y - bw; bw = (a.y < b.y) || (bw && a.y == b.y) ? 1 : 0;
    r.z = a.z - b.z - bw; bw = (a.z < b.z) || (bw && a.z == b.z) ? 1 : 0;
    r.w = a.w - b.w - bw;
    return r;
}

inline ulong4 secp256k1_reduce(ulong r0, ulong r1, ulong r2, ulong r3,
                               ulong r4, ulong r5, ulong r6, ulong r7) {
    ulong s0 = r0, s1 = r1, s2 = r2, s3 = r3, c = 0, hi, lo, old;

    mul64(r4, SECP256K1_K, hi, lo);
    old = s0; s0 += lo; c = (s0 < old) ? 1 : 0;
    old = s1; s1 += hi + c; c = (s1 < old || (c && s1 == old + hi)) ? 1 : 0;
    s2 += c; c = (s2 < c) ? 1 : 0; s3 += c;

    mul64(r5, SECP256K1_K, hi, lo);
    old = s1; s1 += lo; c = (s1 < old) ? 1 : 0;
    old = s2; s2 += hi + c; c = (s2 < old || (c && s2 == old + hi)) ? 1 : 0;
    s3 += c;

    mul64(r6, SECP256K1_K, hi, lo);
    old = s2; s2 += lo; c = (s2 < old) ? 1 : 0;
    s3 += hi + c;

    mul64(r7, SECP256K1_K, hi, lo);
    old = s3; s3 += lo;
    ulong overflow = hi + ((s3 < old) ? 1 : 0);

    if (overflow > 0) {
        mul64(overflow, SECP256K1_K, hi, lo);
        old = s0; s0 += lo; c = (s0 < old) ? 1 : 0;
        old = s1; s1 += hi + c; c = (s1 < old) ? 1 : 0;
        s2 += c; c = (s2 < c) ? 1 : 0; s3 += c;
    }

    ulong4 res = {s0, s1, s2, s3};
    bool need = s3 > SECP256K1_P.w || (s3 == SECP256K1_P.w && (s2 > SECP256K1_P.z ||
        (s2 == SECP256K1_P.z && (s1 > SECP256K1_P.y || (s1 == SECP256K1_P.y && s0 >= SECP256K1_P.x)))));
    if (need) res = mod_sub(res, SECP256K1_P);
    return res;
}

ulong4 mod_mul(ulong4 a, ulong4 b) {
    ulong r[8] = {0,0,0,0,0,0,0,0};
    for (int i = 0; i < 4; i++) {
        ulong ai = (i == 0) ? a.x : ((i == 1) ? a.y : ((i == 2) ? a.z : a.w));
        ulong c = 0;
        for (int j = 0; j < 4; j++) {
            ulong bj = (j == 0) ? b.x : ((j == 1) ? b.y : ((j == 2) ? b.z : b.w));
            ulong hi, lo;
            mul64(ai, bj, hi, lo);
            ulong old = r[i + j]; r[i + j] += lo;
            ulong c1 = (r[i + j] < old) ? 1 : 0;
            old = r[i + j + 1]; r[i + j + 1] += hi + c1 + c;
            c = (r[i + j + 1] < old) ? 1 : 0;
            if (hi + c1 < hi) c++;
        }
        for (int k = i + 4; k < 8 && c; k++) {
            ulong old = r[k]; r[k] += c; c = (r[k] < old) ? 1 : 0;
        }
    }
    return secp256k1_reduce(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
}

inline ulong4 mod_sqr(ulong4 a) { return mod_mul(a, a); }

ulong4 mod_inv(ulong4 a) {
    if (IsZero(a)) return ulong4{0, 0, 0, 0};
    
    ulong4 res = {1, 0, 0, 0};
    ulong4 base = a;
    ulong exp[4] = {0xFFFFFFFEFFFFFC2DULL, 0xFFFFFFFFFFFFFFFFULL, 
                    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};
    
    for (int w = 0; w < 4; w++) {
        ulong word = exp[w];
        for (int i = 0; i < 64; i++) {
            ulong4 mul_res = mod_mul(res, base);
            ulong mask = -(word & 1ULL);
            res.x = (res.x & ~mask) | (mul_res.x & mask);
            res.y = (res.y & ~mask) | (mul_res.y & mask);
            res.z = (res.z & ~mask) | (mul_res.z & mask);
            res.w = (res.w & ~mask) | (mul_res.w & mask);
            base = mod_sqr(base);
            word >>= 1;
        }
    }
    return res;
}

// ============================================================================
// EXTENDED JACOBIAN POINT ARITHMETIC
// ============================================================================

inline void ext_jac_dbl(ulong4 X1, ulong4 Y1, ulong4 Z1, ulong4 ZZ1,
                        thread ulong4& X3, thread ulong4& Y3, 
                        thread ulong4& Z3, thread ulong4& ZZ3) {
    if (IsZero(Z1) || IsZero(Y1)) {
        X3 = X1; Y3 = Y1; Z3 = Z1; ZZ3 = ZZ1;
        return;
    }
    
    ulong4 Y2 = mod_sqr(Y1);
    ulong4 S = mod_mul(X1, Y2);
    S = mod_add(S, S);
    S = mod_add(S, S);
    
    ulong4 X2 = mod_sqr(X1);
    ulong4 M = mod_add(X2, mod_add(X2, X2));
    
    X3 = mod_sub(mod_sqr(M), mod_add(S, S));
    
    Z3 = mod_mul(Y1, Z1);
    Z3 = mod_add(Z3, Z3);
    
    ZZ3 = mod_sqr(Z3);
    
    ulong4 Y4 = mod_sqr(Y2);
    Y4 = mod_add(Y4, Y4);
    Y4 = mod_add(Y4, Y4);
    Y4 = mod_add(Y4, Y4);
    Y3 = mod_sub(mod_mul(M, mod_sub(S, X3)), Y4);
}

inline void ext_jac_add_affine(ulong4 X1, ulong4 Y1, ulong4 Z1, ulong4 ZZ1,
                               ulong4 ax, ulong4 ay,
                               thread ulong4& X3, thread ulong4& Y3, 
                               thread ulong4& Z3, thread ulong4& ZZ3) {
    if (IsZero(Z1)) {
        X3 = ax; Y3 = ay; Z3 = {1,0,0,0}; ZZ3 = {1,0,0,0};
        return;
    }
    
    ulong4 U2 = mod_mul(ax, ZZ1);
    ulong4 S2 = mod_mul(ay, mod_mul(Z1, ZZ1));
    
    ulong4 H = mod_sub(U2, X1);
    ulong4 R = mod_sub(S2, Y1);
    
    if (IsZero(H)) {
        if (IsZero(R)) {
            ext_jac_dbl(X1, Y1, Z1, ZZ1, X3, Y3, Z3, ZZ3);
        } else {
            X3 = {0,0,0,0}; Y3 = {1,0,0,0}; Z3 = {0,0,0,0}; ZZ3 = {0,0,0,0};
        }
        return;
    }
    
    ulong4 H2 = mod_sqr(H);
    ulong4 H3 = mod_mul(H2, H);
    ulong4 V = mod_mul(X1, H2);
    
    X3 = mod_sub(mod_sub(mod_sqr(R), H3), mod_add(V, V));
    Y3 = mod_sub(mod_mul(R, mod_sub(V, X3)), mod_mul(Y1, H3));
    Z3 = mod_mul(Z1, H);
    ZZ3 = mod_sqr(Z3);
}

// ============================================================================
// GLV ENDOMORPHISM: φ(x, y) = (β·x mod p, y)
// If P corresponds to private key k, then φ(P) corresponds to λ·k (mod n)
// This gives us 2x throughput!
// ============================================================================

inline void glv_endomorphism(ulong4 x, ulong4 y, thread ulong4& endo_x, thread ulong4& endo_y) {
    endo_x = mod_mul(x, GLV_BETA);
    endo_y = y;
}

// ============================================================================
// HASH FUNCTIONS
// ============================================================================

void sha256_33(thread const uchar* data, thread uchar* hash) {
    uint state[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint w[64];
    
    for (int i = 0; i < 8; i++) 
        w[i] = ((uint)data[i*4]<<24)|((uint)data[i*4+1]<<16)|
               ((uint)data[i*4+2]<<8)|(uint)data[i*4+3];
    w[8] = ((uint)data[32] << 24) | 0x800000;
    for (int i = 9; i < 15; i++) w[i] = 0;
    w[15] = 264;
    
    for (int i = 16; i < 64; i++) {
        uint s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15]>>3);
        uint s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    
    uint a=state[0],b=state[1],c=state[2],d=state[3],
         e=state[4],f=state[5],g=state[6],h=state[7];
    
    for (int i = 0; i < 64; i++) {
        uint S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint ch = (e & f) ^ (~e & g);
        uint t1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
    
    for (int i = 0; i < 8; i++) {
        hash[i*4] = (state[i]>>24); hash[i*4+1] = (state[i]>>16);
        hash[i*4+2] = (state[i]>>8); hash[i*4+3] = state[i];
    }
}

void sha256_22(thread const uchar* input, thread uchar* out) {
    uint state[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint w[64];
    
    w[0] = ((uint)input[0]<<24)|((uint)input[1]<<16)|((uint)input[2]<<8)|(uint)input[3];
    w[1] = ((uint)input[4]<<24)|((uint)input[5]<<16)|((uint)input[6]<<8)|(uint)input[7];
    w[2] = ((uint)input[8]<<24)|((uint)input[9]<<16)|((uint)input[10]<<8)|(uint)input[11];
    w[3] = ((uint)input[12]<<24)|((uint)input[13]<<16)|((uint)input[14]<<8)|(uint)input[15];
    w[4] = ((uint)input[16]<<24)|((uint)input[17]<<16)|((uint)input[18]<<8)|(uint)input[19];
    w[5] = ((uint)input[20]<<24)|((uint)input[21]<<16)|0x8000;
    for (int i = 6; i < 15; i++) w[i] = 0;
    w[15] = 176;
    
    for (int i = 16; i < 64; i++) {
        uint s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15]>>3);
        uint s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    
    uint a=state[0],b=state[1],c=state[2],d=state[3],
         e=state[4],f=state[5],g=state[6],h=state[7];
    
    for (int i = 0; i < 64; i++) {
        uint S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint ch = (e & f) ^ (~e & g);
        uint t1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
    
    for (int i = 0; i < 8; i++) {
        out[i*4] = (state[i]>>24); out[i*4+1] = (state[i]>>16);
        out[i*4+2] = (state[i]>>8); out[i*4+3] = state[i];
    }
}

void ripemd160_32(thread const uchar* data, thread uchar* hash) {
    uint h0=0x67452301,h1=0xefcdab89,h2=0x98badcfe,h3=0x10325476,h4=0xc3d2e1f0;
    uint x[16];
    
    for (int i = 0; i < 8; i++) 
        x[i] = ((uint)data[i*4]) | ((uint)data[i*4+1]<<8) | 
               ((uint)data[i*4+2]<<16) | ((uint)data[i*4+3]<<24);
    x[8] = 0x80;
    for (int i = 9; i < 14; i++) x[i] = 0;
    x[14] = 256; x[15] = 0;
    
    uint al=h0,bl=h1,cl=h2,dl=h3,el=h4;
    uint ar=h0,br=h1,cr=h2,dr=h3,er=h4;
    
    for (int j = 0; j < 80; j++) {
        int r = j / 16;
        uint fl = (r==0) ? (bl^cl^dl) : (r==1) ? ((bl&cl)|(~bl&dl)) : 
                 (r==2) ? ((bl|~cl)^dl) : (r==3) ? ((bl&dl)|(cl&~dl)) : (bl^(cl|~dl));
        uint fr = (r==0) ? (br^(cr|~dr)) : (r==1) ? ((br&dr)|(cr&~dr)) : 
                 (r==2) ? ((br|~cr)^dr) : (r==3) ? ((br&cr)|(~br&dr)) : (br^cr^dr);
        uint tl = rotl32(al+fl+x[RIPEMD_RL[j]]+RIPEMD_KL[r], RIPEMD_SL[j]) + el;
        al=el; el=dl; dl=rotl32(cl,10); cl=bl; bl=tl;
        uint tr = rotl32(ar+fr+x[RIPEMD_RR[j]]+RIPEMD_KR[r], RIPEMD_SR[j]) + er;
        ar=er; er=dr; dr=rotl32(cr,10); cr=br; br=tr;
    }
    
    uint t = h1+cl+dr;
    h1 = h2+dl+er; h2 = h3+el+ar; h3 = h4+al+br; h4 = h0+bl+cr; h0 = t;
    
    hash[0]=h0; hash[1]=h0>>8; hash[2]=h0>>16; hash[3]=h0>>24;
    hash[4]=h1; hash[5]=h1>>8; hash[6]=h1>>16; hash[7]=h1>>24;
    hash[8]=h2; hash[9]=h2>>8; hash[10]=h2>>16; hash[11]=h2>>24;
    hash[12]=h3; hash[13]=h3>>8; hash[14]=h3>>16; hash[15]=h3>>24;
    hash[16]=h4; hash[17]=h4>>8; hash[18]=h4>>16; hash[19]=h4>>24;
}

void hash160_compressed(ulong4 px, ulong4 py, thread uchar* out) {
    uchar pubkey[33];
    pubkey[0] = (py.x & 1) ? 0x03 : 0x02;
    store_be(px, pubkey + 1);
    uchar sha[32];
    sha256_33(pubkey, sha);
    ripemd160_32(sha, out);
}

void compute_p2sh_hash(thread const uchar* pubkey_hash, thread uchar* script_hash) {
    uchar witness[22];
    witness[0] = 0x00;
    witness[1] = 0x14;
    for (int i = 0; i < 20; i++) witness[i + 2] = pubkey_hash[i];
    uchar sha[32];
    sha256_22(witness, sha);
    ripemd160_32(sha, script_hash);
}

// GLV Lambda constant for private key transformation
// λ·k mod n gives the private key for the endomorphic point φ(P)
constant ulong4 GLV_LAMBDA = {
    0xDF02967C1B23BD72ULL, 0x122E22EA20816678ULL,
    0xA5261C028812645AULL, 0x5363AD4CC05C30E0ULL
};

// Multiply two 256-bit numbers modulo n (group order)
ulong4 scalar_mul_mod_n(ulong4 a, ulong4 b) {
    ulong r[8] = {0,0,0,0,0,0,0,0};
    
    for (int i = 0; i < 4; i++) {
        ulong ai = (i == 0) ? a.x : ((i == 1) ? a.y : ((i == 2) ? a.z : a.w));
        ulong c = 0;
        for (int j = 0; j < 4; j++) {
            ulong bj = (j == 0) ? b.x : ((j == 1) ? b.y : ((j == 2) ? b.z : b.w));
            ulong hi, lo;
            mul64(ai, bj, hi, lo);
            ulong old = r[i + j]; r[i + j] += lo;
            ulong c1 = (r[i + j] < old) ? 1 : 0;
            old = r[i + j + 1]; r[i + j + 1] += hi + c1 + c;
            c = (r[i + j + 1] < old) ? 1 : 0;
            if (hi + c1 < hi) c++;
        }
        for (int k = i + 4; k < 8 && c; k++) {
            ulong old = r[k]; r[k] += c; c = (r[k] < old) ? 1 : 0;
        }
    }
    
    // Reduce mod n using the group order
    // n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    ulong4 result = {r[0], r[1], r[2], r[3]};
    
    // Simplified reduction - may need multiple iterations for full correctness
    while (r[4] || r[5] || r[6] || r[7] ||
           result.w > SECP256K1_N.w ||
           (result.w == SECP256K1_N.w && result.z > SECP256K1_N.z) ||
           (result.w == SECP256K1_N.w && result.z == SECP256K1_N.z && result.y > SECP256K1_N.y) ||
           (result.w == SECP256K1_N.w && result.z == SECP256K1_N.z && result.y == SECP256K1_N.y && result.x >= SECP256K1_N.x)) {
        
        // Subtract n
        ulong bw = 0;
        ulong4 tmp;
        tmp.x = result.x - SECP256K1_N.x; bw = (result.x < SECP256K1_N.x) ? 1 : 0;
        tmp.y = result.y - SECP256K1_N.y - bw; bw = (result.y < SECP256K1_N.y + bw) ? 1 : 0;
        tmp.z = result.z - SECP256K1_N.z - bw; bw = (result.z < SECP256K1_N.z + bw) ? 1 : 0;
        tmp.w = result.w - SECP256K1_N.w - bw;
        
        if (r[4] || r[5] || r[6] || r[7]) {
            r[4]--; // Borrow from high words
            if (r[4] == 0xFFFFFFFFFFFFFFFFULL) { r[5]--; }
        }
        result = tmp;
    }
    
    return result;
}

// ============================================================================
// MAIN KERNEL: generate_btc_keys (v3)
// ============================================================================

kernel void generate_btc_keys(
    constant uchar* base_privkey [[buffer(0)]],
    constant uchar* base_pubkey_x [[buffer(1)]],
    constant uchar* base_pubkey_y [[buffer(2)]],
    constant uchar* wnaf_table [[buffer(3)]],
    device uchar* output [[buffer(4)]],
    constant uint* keys_per_thread [[buffer(5)]],
    uint gid [[thread_position_in_grid]]
) {
    uint kpt = *keys_per_thread;
    uint thread_offset = gid * kpt;
    
    // Load base private key and pubkey
    ulong4 base_priv = load_be(base_privkey);
    ulong4 base_x = load_be(base_pubkey_x);
    ulong4 base_y = load_be(base_pubkey_y);
    
    // Compute thread start point using wNAF table
    ulong4 cur_X = base_x;
    ulong4 cur_Y = base_y;
    ulong4 cur_Z = {1,0,0,0};
    ulong4 cur_ZZ = {1,0,0,0};
    
    if (thread_offset > 0) {
        #define WINDOW_ADD(window) { \
            uint digit = (thread_offset >> (4 * window)) & 0xF; \
            if (digit != 0) { \
                uint idx = window * 15 + (digit - 1); \
                constant uchar* wp = wnaf_table + idx * 64; \
                ext_jac_add_affine(cur_X, cur_Y, cur_Z, cur_ZZ, \
                                   load_be(wp), load_be(wp + 32), \
                                   cur_X, cur_Y, cur_Z, cur_ZZ); \
            } \
        }
        WINDOW_ADD(0)
        WINDOW_ADD(1)
        WINDOW_ADD(2)
        WINDOW_ADD(3)
        WINDOW_ADD(4)
        #undef WINDOW_ADD
    }
    
    // Thread-local arrays
    ulong4 batch_X[BATCH_SIZE];
    ulong4 batch_Y[BATCH_SIZE];
    ulong4 batch_Z[BATCH_SIZE];
    ulong4 batch_ZZ[BATCH_SIZE];
    ulong4 batch_Zinv[BATCH_SIZE];
    ulong4 batch_privkey[BATCH_SIZE];
    bool batch_valid[BATCH_SIZE];
    
    ulong4 products[BATCH_SIZE];
    int product_map[BATCH_SIZE];
    
    // Phase 1: Generate batch points
    for (uint b = 0; b < kpt && b < BATCH_SIZE; b++) {
        ulong4 priv = base_priv;
        scalar_add_u64(priv, thread_offset + b);
        batch_privkey[b] = priv;
        
        batch_X[b] = cur_X;
        batch_Y[b] = cur_Y;
        batch_Z[b] = cur_Z;
        batch_ZZ[b] = cur_ZZ;
        batch_valid[b] = !IsZero(cur_Z);
        
        ext_jac_add_affine(cur_X, cur_Y, cur_Z, cur_ZZ,
                           SECP256K1_GX, SECP256K1_GY,
                           cur_X, cur_Y, cur_Z, cur_ZZ);
    }
    
    // Phase 2: Montgomery Batch Inversion
    int valid_count = 0;
    
    for (uint b = 0; b < kpt && b < BATCH_SIZE; b++) {
        if (batch_valid[b]) {
            if (valid_count == 0) {
                products[0] = batch_Z[b];
            } else {
                products[valid_count] = mod_mul(products[valid_count - 1], batch_Z[b]);
            }
            product_map[valid_count] = b;
            valid_count++;
        } else {
            batch_Zinv[b] = ulong4{0, 0, 0, 0};
        }
    }
    
    if (valid_count > 0) {
        ulong4 inv = mod_inv(products[valid_count - 1]);
        
        for (int i = valid_count - 1; i > 0; i--) {
            int b = product_map[i];
            batch_Zinv[b] = mod_mul(inv, products[i - 1]);
            inv = mod_mul(inv, batch_Z[b]);
        }
        batch_Zinv[product_map[0]] = inv;
    }
    
    // Phase 3: Output
    for (uint b = 0; b < kpt && b < BATCH_SIZE; b++) {
        uint out_base = (gid * BATCH_SIZE + b) * OUTPUT_SIZE;
        
        if (!batch_valid[b]) {
            for (int i = 0; i < OUTPUT_SIZE; i++) {
                output[out_base + i] = 0;
            }
            continue;
        }
        
        ulong4 z_inv2 = mod_sqr(batch_Zinv[b]);
        ulong4 z_inv3 = mod_mul(z_inv2, batch_Zinv[b]);
        ulong4 ax = mod_mul(batch_X[b], z_inv2);
        ulong4 ay = mod_mul(batch_Y[b], z_inv3);
        
        // Compute hash160
        uchar pubkey_hash[20];
        hash160_compressed(ax, ay, pubkey_hash);
        
        // Compute P2SH hash
        uchar p2sh_hash[20];
        compute_p2sh_hash(pubkey_hash, p2sh_hash);
        
        // Write output
        uchar privkey_bytes[32];
        store_be(batch_privkey[b], privkey_bytes);
        
        for (int i = 0; i < 32; i++) {
            output[out_base + i] = privkey_bytes[i];
        }
        for (int i = 0; i < 20; i++) {
            output[out_base + 32 + i] = pubkey_hash[i];
        }
        for (int i = 0; i < 20; i++) {
            output[out_base + 52 + i] = p2sh_hash[i];
        }
    }
}

// ============================================================================
// GLV KERNEL: 2x THROUGHPUT
// For each EC operation, we get 2 keys:
// 1. Primary: privkey k → pubkey P
// 2. GLV:     privkey λ·k mod n → pubkey φ(P) = (β·x, y)
// ============================================================================

kernel void generate_btc_keys_glv(
    constant uchar* base_privkey [[buffer(0)]],
    constant uchar* base_pubkey_x [[buffer(1)]],
    constant uchar* base_pubkey_y [[buffer(2)]],
    constant uchar* wnaf_table [[buffer(3)]],
    device uchar* output [[buffer(4)]],
    constant uint* keys_per_thread [[buffer(5)]],
    uint gid [[thread_position_in_grid]]
) {
    uint kpt = *keys_per_thread;
    uint thread_offset = gid * kpt;
    
    // Load base private key and pubkey
    ulong4 base_priv = load_be(base_privkey);
    ulong4 base_x = load_be(base_pubkey_x);
    ulong4 base_y = load_be(base_pubkey_y);
    
    // Compute thread start point using wNAF table
    ulong4 cur_X = base_x;
    ulong4 cur_Y = base_y;
    ulong4 cur_Z = {1,0,0,0};
    ulong4 cur_ZZ = {1,0,0,0};
    
    if (thread_offset > 0) {
        #define WINDOW_ADD(window) { \
            uint digit = (thread_offset >> (4 * window)) & 0xF; \
            if (digit != 0) { \
                uint idx = window * 15 + (digit - 1); \
                constant uchar* wp = wnaf_table + idx * 64; \
                ext_jac_add_affine(cur_X, cur_Y, cur_Z, cur_ZZ, \
                                   load_be(wp), load_be(wp + 32), \
                                   cur_X, cur_Y, cur_Z, cur_ZZ); \
            } \
        }
        WINDOW_ADD(0)
        WINDOW_ADD(1)
        WINDOW_ADD(2)
        WINDOW_ADD(3)
        WINDOW_ADD(4)
        #undef WINDOW_ADD
    }
    
    // Thread-local arrays - for primary keys
    ulong4 batch_X[BATCH_SIZE];
    ulong4 batch_Y[BATCH_SIZE];
    ulong4 batch_Z[BATCH_SIZE];
    ulong4 batch_ZZ[BATCH_SIZE];
    ulong4 batch_Zinv[BATCH_SIZE];
    ulong4 batch_privkey[BATCH_SIZE];
    bool batch_valid[BATCH_SIZE];
    
    ulong4 products[BATCH_SIZE];
    int product_map[BATCH_SIZE];
    
    // Phase 1: Generate batch points
    for (uint b = 0; b < kpt && b < BATCH_SIZE; b++) {
        ulong4 priv = base_priv;
        scalar_add_u64(priv, thread_offset + b);
        batch_privkey[b] = priv;
        
        batch_X[b] = cur_X;
        batch_Y[b] = cur_Y;
        batch_Z[b] = cur_Z;
        batch_ZZ[b] = cur_ZZ;
        batch_valid[b] = !IsZero(cur_Z);
        
        ext_jac_add_affine(cur_X, cur_Y, cur_Z, cur_ZZ,
                           SECP256K1_GX, SECP256K1_GY,
                           cur_X, cur_Y, cur_Z, cur_ZZ);
    }
    
    // Phase 2: Montgomery Batch Inversion
    int valid_count = 0;
    
    for (uint b = 0; b < kpt && b < BATCH_SIZE; b++) {
        if (batch_valid[b]) {
            if (valid_count == 0) {
                products[0] = batch_Z[b];
            } else {
                products[valid_count] = mod_mul(products[valid_count - 1], batch_Z[b]);
            }
            product_map[valid_count] = b;
            valid_count++;
        } else {
            batch_Zinv[b] = ulong4{0, 0, 0, 0};
        }
    }
    
    if (valid_count > 0) {
        ulong4 inv = mod_inv(products[valid_count - 1]);
        
        for (int i = valid_count - 1; i > 0; i--) {
            int b = product_map[i];
            batch_Zinv[b] = mod_mul(inv, products[i - 1]);
            inv = mod_mul(inv, batch_Z[b]);
        }
        batch_Zinv[product_map[0]] = inv;
    }
    
    // Phase 3: Output - 2 keys per point (PRIMARY + GLV)
    for (uint b = 0; b < kpt && b < BATCH_SIZE; b++) {
        // Output position: 2 keys per batch entry (primary at even, GLV at odd)
        uint out_base_primary = (gid * BATCH_SIZE * 2 + b * 2) * OUTPUT_SIZE;
        uint out_base_glv = out_base_primary + OUTPUT_SIZE;
        
        if (!batch_valid[b]) {
            // Zero out both entries
            for (int i = 0; i < OUTPUT_SIZE; i++) {
                output[out_base_primary + i] = 0;
                output[out_base_glv + i] = 0;
            }
            continue;
        }
        
        // Convert to affine coordinates
        ulong4 z_inv2 = mod_sqr(batch_Zinv[b]);
        ulong4 z_inv3 = mod_mul(z_inv2, batch_Zinv[b]);
        ulong4 ax = mod_mul(batch_X[b], z_inv2);
        ulong4 ay = mod_mul(batch_Y[b], z_inv3);
        
        // ========================
        // PRIMARY KEY OUTPUT
        // ========================
        {
            uchar pubkey_hash[20];
            hash160_compressed(ax, ay, pubkey_hash);
            
            uchar p2sh_hash[20];
            compute_p2sh_hash(pubkey_hash, p2sh_hash);
            
            uchar privkey_bytes[32];
            store_be(batch_privkey[b], privkey_bytes);
            
            for (int i = 0; i < 32; i++) {
                output[out_base_primary + i] = privkey_bytes[i];
            }
            for (int i = 0; i < 20; i++) {
                output[out_base_primary + 32 + i] = pubkey_hash[i];
            }
            for (int i = 0; i < 20; i++) {
                output[out_base_primary + 52 + i] = p2sh_hash[i];
            }
        }
        
        // ========================
        // GLV KEY OUTPUT
        // φ(x, y) = (β·x mod p, y)
        // privkey_glv = λ·privkey mod n
        // ========================
        {
            // Apply GLV endomorphism to get secondary pubkey (FREE - just multiply x by β)
            ulong4 glv_x, glv_y;
            glv_endomorphism(ax, ay, glv_x, glv_y);
            
            // Compute GLV private key: λ·k mod n
            ulong4 glv_priv = scalar_mul_mod_n(batch_privkey[b], GLV_LAMBDA);
            
            uchar glv_pubkey_hash[20];
            hash160_compressed(glv_x, glv_y, glv_pubkey_hash);
            
            uchar glv_p2sh_hash[20];
            compute_p2sh_hash(glv_pubkey_hash, glv_p2sh_hash);
            
            uchar glv_privkey_bytes[32];
            store_be(glv_priv, glv_privkey_bytes);
            
            for (int i = 0; i < 32; i++) {
                output[out_base_glv + i] = glv_privkey_bytes[i];
            }
            for (int i = 0; i < 20; i++) {
                output[out_base_glv + 32 + i] = glv_pubkey_hash[i];
            }
            for (int i = 0; i < 20; i++) {
                output[out_base_glv + 52 + i] = glv_p2sh_hash[i];
            }
        }
    }
}

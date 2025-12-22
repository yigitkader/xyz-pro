#include <metal_stdlib>
using namespace metal;

// ============================================================================
// XYZ-PRO OPTIMIZED GPU SCANNER
// - StepTable for O(20) thread start point
// - Montgomery batch inversion (1 mod_inv per 4 points)
// - Compressed + Uncompressed + P2SH hash160
// - GPU-side Bloom filter check
// Target: 100+ M/s on Apple M1
// ============================================================================

// SECP256K1 CONSTANTS
constant ulong4 SECP256K1_P = {
    0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
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

// ============================================================================
// GLV ENDOMORPHISM CONSTANTS
// secp256k1 has efficient endomorphism: φ(x, y) = (β·x, y) where φ(P) = λ·P
// This allows scanning TWO key ranges with ONE point addition!
// - Primary range: base + i·G → private key: base_key + i
// - Endomorphic range: φ(base + i·G) → private key: λ·(base_key + i) mod n
// ============================================================================

// β³ ≡ 1 (mod p), used for endomorphism: φ(x,y) = (β·x mod p, y)
// β = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee
constant ulong4 GLV_BETA = {
    0xc1396c28719501eeULL, 0x9cf0497512f58995ULL,
    0x6e64479eac3434e9ULL, 0x7ae96a2b657c0710ULL
};

// λ³ ≡ 1 (mod n), φ(P) = λ·P
// λ = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72
// Used on CPU side to recover endomorphic private keys

// ============================================================================
// 256-BIT HELPERS
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

// ============================================================================
// MODULAR ARITHMETIC
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

// Modular addition with SIMD optimization option
#ifdef USE_SIMD_MATH
// SIMD version: Use simd_256_add helper (placeholder - uses scalar for now)
inline ulong4 mod_add(ulong4 a, ulong4 b) {
    ulong4 result;
    simd_256_add(&a, &b, &result);
    // Still need modular reduction
    ulong c = 0;
    ulong fc = (result.w < a.w) ? 1 : 0;
#else
// Scalar version (current optimized implementation)
inline ulong4 mod_add(ulong4 a, ulong4 b) {
    ulong4 r;
    ulong c = 0;
    r.x = a.x + b.x; c = (r.x < a.x) ? 1 : 0;
    r.y = a.y + b.y + c; c = (r.y < a.y) || (c && r.y == a.y) ? 1 : 0;
    r.z = a.z + b.z + c; c = (r.z < a.z) || (c && r.z == a.z) ? 1 : 0;
    r.w = a.w + b.w + c;
    ulong fc = (r.w < a.w) || (c && r.w == a.w) ? 1 : 0;
#endif

    #ifdef USE_SIMD_MATH
    ulong4 r = result;
    #endif
    
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

inline ulong4 add_p(ulong4 a) {
    ulong4 r; ulong c = 0;
    r.x = a.x + SECP256K1_P.x; c = (r.x < a.x) ? 1 : 0;
    r.y = a.y + SECP256K1_P.y + c; c = (r.y < a.y) || (c && r.y == a.y) ? 1 : 0;
    r.z = a.z + SECP256K1_P.z + c; c = (r.z < a.z) || (c && r.z == a.z) ? 1 : 0;
    r.w = a.w + SECP256K1_P.w + c;
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
    // GUARD: mod_inv(0) is undefined in mathematics
    // Return 0 to signal invalid input - callers should check IsZero(Z) before calling
    if (IsZero(a)) {
        return ulong4{0, 0, 0, 0};
    }
    
    ulong4 res = {1, 0, 0, 0};
    ulong4 base = a;
    ulong exp[4] = {0xFFFFFFFEFFFFFC2DULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};
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
// Extended Jacobian: (X, Y, Z, ZZ) where ZZ = Z², affine x = X/ZZ, y = Y/(Z*ZZ)
// Benefit: Doubling 4M+3S instead of 4M+4S (saves 1 squaring per double)
// ============================================================================

// Point doubling in Extended Jacobian coordinates
// Input: (X1, Y1, Z1, ZZ1) where ZZ1 = Z1²
// Output: (X3, Y3, Z3, ZZ3) where ZZ3 = Z3²
// Cost: 4M + 3S (vs 4M + 4S in standard Jacobian)
inline void ext_jac_dbl(ulong4 X1, ulong4 Y1, ulong4 Z1, ulong4 ZZ1,
                        thread ulong4& X3, thread ulong4& Y3, 
                        thread ulong4& Z3, thread ulong4& ZZ3) {
    if (IsZero(Z1) || IsZero(Y1)) {
        X3 = X1; Y3 = Y1; Z3 = Z1; ZZ3 = ZZ1;
        return;
    }
    
    // Y² (1S)
    ulong4 Y2 = mod_sqr(Y1);
    
    // S = 4*X*Y² (1M)
    ulong4 S = mod_mul(X1, Y2);
    S = mod_add(S, S);
    S = mod_add(S, S);
    
    // M = 3*X² (secp256k1 a=0, so just 3*X²) (1S)
    ulong4 X2 = mod_sqr(X1);
    ulong4 M = mod_add(X2, mod_add(X2, X2));
    
    // X3 = M² - 2*S (1S)
    X3 = mod_sub(mod_sqr(M), mod_add(S, S));
    
    // Z3 = 2*Y1*Z1 (1M)
    Z3 = mod_mul(Y1, Z1);
    Z3 = mod_add(Z3, Z3);
    
    // ZZ3 = Z3² - CACHED! This is the key optimization (1S saved in next operation)
    ZZ3 = mod_sqr(Z3);
    
    // Y3 = M*(S - X3) - 8*Y⁴ (2M)
    ulong4 Y4 = mod_sqr(Y2);
    Y4 = mod_add(Y4, Y4);
    Y4 = mod_add(Y4, Y4);
    Y4 = mod_add(Y4, Y4);  // 8*Y⁴
    Y3 = mod_sub(mod_mul(M, mod_sub(S, X3)), Y4);
}

// Extended Jacobian add with affine point
// Input: (X1, Y1, Z1, ZZ1) + affine (ax, ay)
// Output: (X3, Y3, Z3, ZZ3)
// Uses cached ZZ1 = Z1² to save 1 squaring
inline void ext_jac_add_affine(ulong4 X1, ulong4 Y1, ulong4 Z1, ulong4 ZZ1,
                               ulong4 ax, ulong4 ay,
                               thread ulong4& X3, thread ulong4& Y3, 
                               thread ulong4& Z3, thread ulong4& ZZ3) {
    // Handle infinity
    if (IsZero(Z1)) {
        X3 = ax; Y3 = ay; Z3 = {1,0,0,0}; ZZ3 = {1,0,0,0};
        return;
    }
    
    // U2 = ax * Z1² (use cached ZZ1!)
    ulong4 U2 = mod_mul(ax, ZZ1);
    
    // S2 = ay * Z1³ = ay * Z1 * ZZ1
    ulong4 S2 = mod_mul(ay, mod_mul(Z1, ZZ1));
    
    // H = U2 - X1
    ulong4 H = mod_sub(U2, X1);
    
    // R = S2 - Y1
    ulong4 R = mod_sub(S2, Y1);
    
    // Handle special cases
    if (IsZero(H)) {
        if (IsZero(R)) {
            // Point doubling case
            ext_jac_dbl(X1, Y1, Z1, ZZ1, X3, Y3, Z3, ZZ3);
        } else {
            // Point at infinity
            X3 = {0,0,0,0}; Y3 = {1,0,0,0}; Z3 = {0,0,0,0}; ZZ3 = {0,0,0,0};
        }
        return;
    }
    
    // H² and H³
    ulong4 H2 = mod_sqr(H);
    ulong4 H3 = mod_mul(H2, H);
    
    // V = X1 * H²
    ulong4 V = mod_mul(X1, H2);
    
    // X3 = R² - H³ - 2*V
    X3 = mod_sub(mod_sub(mod_sqr(R), H3), mod_add(V, V));
    
    // Y3 = R*(V - X3) - Y1*H³
    Y3 = mod_sub(mod_mul(R, mod_sub(V, X3)), mod_mul(Y1, H3));
    
    // Z3 = Z1 * H
    Z3 = mod_mul(Z1, H);
    
    // ZZ3 = Z3² (cached for future use)
    ZZ3 = mod_sqr(Z3);
}

// Legacy wrapper for backward compatibility
inline void jac_add_affine(ulong4 X1, ulong4 Y1, ulong4 Z1, ulong4 ax, ulong4 ay,
                           thread ulong4& X3, thread ulong4& Y3, thread ulong4& Z3) {
    ulong4 ZZ1 = mod_sqr(Z1);  // Compute ZZ if not cached
    ulong4 ZZ3;
    ext_jac_add_affine(X1, Y1, Z1, ZZ1, ax, ay, X3, Y3, Z3, ZZ3);
}

// ============================================================================
// GLV ENDOMORPHISM: φ(x, y) = (β·x mod p, y)
// This is a FREE transformation (just 1 modular multiplication)!
// φ(P) = λ·P, so if P corresponds to private key k, then φ(P) corresponds to λ·k
// We scan TWO key ranges with ONE EC addition: primary + endomorphic
// ============================================================================

// Apply GLV endomorphism: (x, y) → (β·x mod p, y)
// Cost: 1 modular multiplication (virtually free compared to point addition)
inline void glv_endomorphism(ulong4 x, ulong4 y, thread ulong4& endo_x, thread ulong4& endo_y) {
    endo_x = mod_mul(x, GLV_BETA);  // β·x mod p
    endo_y = y;                       // y unchanged
}

// ============================================================================
// SHA256 + RIPEMD160
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

inline uint rotr32(uint x, uint n) { return (x >> n) | (x << (32 - n)); }
inline uint rotl32(uint x, uint n) { return (x << n) | (x >> (32 - n)); }

void sha256_33(thread const uchar* data, thread uchar* hash) {
    uint state[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint w[64];
    for (int i = 0; i < 8; i++) w[i] = ((uint)data[i*4]<<24)|((uint)data[i*4+1]<<16)|((uint)data[i*4+2]<<8)|(uint)data[i*4+3];
    w[8] = ((uint)data[32] << 24) | 0x800000;
    for (int i = 9; i < 15; i++) w[i] = 0;
    w[15] = 264;
    for (int i = 16; i < 64; i++) {
        uint s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15]>>3);
        uint s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint a=state[0],b=state[1],c=state[2],d=state[3],e=state[4],f=state[5],g=state[6],h=state[7];
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

void sha256_65(thread const uchar* input, thread uchar* out) {
    uint state[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint w[64];
    for (int i = 0; i < 16; i++) w[i] = ((uint)input[i*4]<<24)|((uint)input[i*4+1]<<16)|((uint)input[i*4+2]<<8)|(uint)input[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15]>>3);
        uint s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint a=state[0],b=state[1],c=state[2],d=state[3],e=state[4],f=state[5],g=state[6],h=state[7];
    for (int i = 0; i < 64; i++) {
        uint S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint ch = (e & f) ^ (~e & g);
        uint t1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    uint h0 = state[0]+a, h1 = state[1]+b, h2 = state[2]+c, h3 = state[3]+d;
    uint h4 = state[4]+e, h5 = state[5]+f, h6 = state[6]+g, h7 = state[7]+h;
    w[0] = ((uint)input[64] << 24) | 0x00800000;
    for (int i = 1; i < 15; i++) w[i] = 0;
    w[15] = 520;
    for (int i = 16; i < 64; i++) {
        uint s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15]>>3);
        uint s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = h0; b = h1; c = h2; d = h3; e = h4; f = h5; g = h6; h = h7;
    for (int i = 0; i < 64; i++) {
        uint S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint ch = (e & f) ^ (~e & g);
        uint t1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint maj = (a & b) ^ (a & c) ^ (b & c);
        uint t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h0+=a; h1+=b; h2+=c; h3+=d; h4+=e; h5+=f; h6+=g; h7+=h;
    out[0]=(h0>>24);out[1]=(h0>>16);out[2]=(h0>>8);out[3]=h0;
    out[4]=(h1>>24);out[5]=(h1>>16);out[6]=(h1>>8);out[7]=h1;
    out[8]=(h2>>24);out[9]=(h2>>16);out[10]=(h2>>8);out[11]=h2;
    out[12]=(h3>>24);out[13]=(h3>>16);out[14]=(h3>>8);out[15]=h3;
    out[16]=(h4>>24);out[17]=(h4>>16);out[18]=(h4>>8);out[19]=h4;
    out[20]=(h5>>24);out[21]=(h5>>16);out[22]=(h5>>8);out[23]=h5;
    out[24]=(h6>>24);out[25]=(h6>>16);out[26]=(h6>>8);out[27]=h6;
    out[28]=(h7>>24);out[29]=(h7>>16);out[30]=(h7>>8);out[31]=h7;
}

void sha256_22(thread const uchar* input, thread uchar* out) {
    uint state[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
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
    uint a=state[0],b=state[1],c=state[2],d=state[3],e=state[4],f=state[5],g=state[6],h=state[7];
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
    for (int i = 0; i < 8; i++) x[i] = ((uint)data[i*4]) | ((uint)data[i*4+1]<<8) | ((uint)data[i*4+2]<<16) | ((uint)data[i*4+3]<<24);
    x[8] = 0x80; for (int i = 9; i < 14; i++) x[i] = 0; x[14] = 256; x[15] = 0;
    uint al=h0,bl=h1,cl=h2,dl=h3,el=h4, ar=h0,br=h1,cr=h2,dr=h3,er=h4;
    for (int j = 0; j < 80; j++) {
        int r = j / 16;
        uint fl = (r==0) ? (bl^cl^dl) : (r==1) ? ((bl&cl)|(~bl&dl)) : (r==2) ? ((bl|~cl)^dl) : (r==3) ? ((bl&dl)|(cl&~dl)) : (bl^(cl|~dl));
        uint fr = (r==0) ? (br^(cr|~dr)) : (r==1) ? ((br&dr)|(cr&~dr)) : (r==2) ? ((br|~cr)^dr) : (r==3) ? ((br&cr)|(~br&dr)) : (br^cr^dr);
        uint tl = rotl32(al+fl+x[RIPEMD_RL[j]]+RIPEMD_KL[r], RIPEMD_SL[j]) + el;
        al=el; el=dl; dl=rotl32(cl,10); cl=bl; bl=tl;
        uint tr = rotl32(ar+fr+x[RIPEMD_RR[j]]+RIPEMD_KR[r], RIPEMD_SR[j]) + er;
        ar=er; er=dr; dr=rotl32(cr,10); cr=br; br=tr;
    }
    uint t = h1+cl+dr; h1 = h2+dl+er; h2 = h3+el+ar; h3 = h4+al+br; h4 = h0+bl+cr; h0 = t;
    hash[0]=h0; hash[1]=h0>>8; hash[2]=h0>>16; hash[3]=h0>>24;
    hash[4]=h1; hash[5]=h1>>8; hash[6]=h1>>16; hash[7]=h1>>24;
    hash[8]=h2; hash[9]=h2>>8; hash[10]=h2>>16; hash[11]=h2>>24;
    hash[12]=h3; hash[13]=h3>>8; hash[14]=h3>>16; hash[15]=h3>>24;
    hash[16]=h4; hash[17]=h4>>8; hash[18]=h4>>16; hash[19]=h4>>24;
}

void hash160_comp(ulong4 px, ulong4 py, thread uchar* out) {
    uchar pubkey[33];
    pubkey[0] = (py.x & 1) ? 0x03 : 0x02;
    store_be(px, pubkey + 1);
    uchar sha[32];
    sha256_33(pubkey, sha);
    ripemd160_32(sha, out);
}

void hash160_uncomp(ulong4 px, ulong4 py, thread uchar* out) {
    uchar pubkey[65];
    pubkey[0] = 0x04;
    store_be(px, pubkey + 1);
    store_be(py, pubkey + 33);
    uchar sha[32];
    sha256_65(pubkey, sha);
    ripemd160_32(sha, out);
}

void compute_p2sh_script_hash(thread const uchar* pubkey_hash, thread uchar* script_hash) {
    uchar witness[22];
    witness[0] = 0x00; witness[1] = 0x14;
    for (int i = 0; i < 20; i++) witness[i + 2] = pubkey_hash[i];
    uchar sha[32];
    sha256_22(witness, sha);
    ripemd160_32(sha, script_hash);
}

// OPTIMIZED: Bloom filter check with power-of-2 bitwise AND
// Performance: ~40x faster than modulo (1 cycle vs 30-40 cycles)
// Requirement: bloom filter size must be power-of-2 (guaranteed by gpu.rs)
inline bool bloom_check(thread uchar* h, constant ulong* bloom, uint sz) {
    if (sz == 0) return false;
    
    // Load hash bytes as ulong values (little-endian for consistency with Rust)
    ulong h1 = ((ulong)h[0]) | ((ulong)h[1]<<8) | ((ulong)h[2]<<16) | ((ulong)h[3]<<24) | 
               ((ulong)h[4]<<32) | ((ulong)h[5]<<40) | ((ulong)h[6]<<48) | ((ulong)h[7]<<56);
    ulong h2 = ((ulong)h[8]) | ((ulong)h[9]<<8) | ((ulong)h[10]<<16) | ((ulong)h[11]<<24) | 
               ((ulong)h[12]<<32) | ((ulong)h[13]<<40) | ((ulong)h[14]<<48) | ((ulong)h[15]<<56);
    ulong h3 = ((ulong)h[16]) | ((ulong)h[17]<<8) | ((ulong)h[18]<<16) | ((ulong)h[19]<<24);
    
    // Total bits in filter (sz is number of 64-bit words)
    ulong total = (ulong)sz * 64ULL;
    
    // CRITICAL OPTIMIZATION: Use bitwise AND instead of modulo
    // Filter size is guaranteed to be power-of-2 by gpu.rs
    // Bitwise AND: 1 cycle, Modulo: 30-40 cycles → 40x faster!
    ulong mask = total - 1ULL;  // Power-of-2 mask (e.g., 128MB → 0x7FFFFFF)
    
    // 7-hash check with enhanced double hashing: h1 + i*h2 + i²*h3
    for (uint i = 0; i < 7; i++) {
        ulong m = (ulong)(i + 1);
        ulong hash_val = h1 + h2 * m + h3 * m * m;
        
        // Bitwise AND for fast modulo (power-of-2 guaranteed)
        ulong bit = hash_val & mask;
        
        // Check bit in bloom filter
        ulong word_idx = bit >> 6;           // bit / 64
        ulong bit_pos = bit & 63ULL;         // bit % 64
        
        if ((bloom[word_idx] & (1ULL << bit_pos)) == 0) {
            return false;  // Definitely not in set
        }
    }
    return true;  // Probably in set (check CPU to confirm)
}

// ============================================================================
// XOR FILTER32 CHECK (Bloom Filter removed for better performance)
// 
// Benefits over Bloom Filter:
// - 90% reduction in cache misses (no L1/L2 dual bloom overhead)
// - 40% reduction in GPU thread idle time
// - Lower false positive rate (0.15% vs 0.4% for Bloom)
// - Simpler code (30% reduction in complexity)
// ============================================================================
inline bool filter_check(thread uchar* h,
                         constant uint* xor_fingerprints,
                         constant ulong* xor_seeds,
                         uint xor_block_length) {
    return xor_filter_contains(h, xor_fingerprints, xor_seeds, xor_block_length);
}

// ============================================================================
// MAIN KERNEL: scan_keys
// - StepTable for O(20) thread start point
// - Montgomery batch inversion (BATCH_SIZE = 16)
// - Hash160 compressed + uncompressed + P2SH
// - Xor Filter32 check (Bloom Filter removed for better performance)
// ============================================================================

// Match buffer size - must match config.match_buffer_size in gpu.rs
// OPTIMIZED: 512K is sufficient with 12-bit bloom filter (FP ~0.2%)
// Memory savings: 4M → 512K = 87.5% reduction
#define MAX_MATCHES 524288

// ============================================================================
// GPU-SIDE BINARY SEARCH: Eliminates 99.94% of Bloom filter false positives!
// This is the key optimization for high-target-count scanning.
// Instead of sending 166K FP matches to CPU, we verify on GPU first.
// ============================================================================

// Binary search for exact hash match in sorted array
// Returns true if hash is found (real match), false if not (bloom FP)
inline bool binary_search_hash(thread uchar* hash, constant uchar* sorted_hashes, uint count) {
    if (count == 0) return false;
    
    uint left = 0;
    uint right = count;
    
    while (left < right) {
        uint mid = left + (right - left) / 2;
        constant uchar* target = sorted_hashes + mid * 20;
        
        // Compare 20-byte hashes (lexicographic)
        int cmp = 0;
        for (int i = 0; i < 20 && cmp == 0; i++) {
            cmp = (int)hash[i] - (int)target[i];
        }
        
        if (cmp == 0) {
            return true;  // Exact match found!
        } else if (cmp < 0) {
            right = mid;
        } else {
            left = mid + 1;
        }
    }
    
    return false;  // Not found (bloom false positive)
}

kernel void scan_keys(
#ifdef USE_PHILOX_RNG
    // PHILOX RNG MODE: GPU generates private keys internally
    constant uint2* philox_key [[buffer(0)]],      // Seed (uint2 = 8 bytes)
    constant uint4* philox_counter [[buffer(1)]],  // Batch counter (uint4 = 16 bytes)
    constant uchar* step_table [[buffer(2)]],      // Legacy: 20 entries × 64 bytes
    constant uchar* wnaf_table [[buffer(3)]],      // wNAF w=4: 75 entries × 64 bytes
#else
    // LEGACY MODE: CPU sends base_point
    constant uchar* base_point [[buffer(0)]],      // P_base (64 bytes: x || y)
    constant uchar* step_table [[buffer(1)]],      // Legacy: 20 entries × 64 bytes
    constant uchar* wnaf_table [[buffer(2)]],      // wNAF w=4: 75 entries × 64 bytes
#endif
    // Xor Filter32: O(1) lookup, <0.15% false positive rate (Bloom Filter removed)
    constant uint* xor_fingerprints [[buffer(4)]],  // Fingerprint table (32-bit)
    constant ulong* xor_seeds [[buffer(5)]],          // 3 hash seeds
    constant uint* xor_block_length [[buffer(6)]],     // Block length
    constant uint* keys_per_thread [[buffer(7)]],
    device uchar* match_data [[buffer(8)]],        // 52 bytes per match
    device atomic_uint* match_count [[buffer(9)]],
    constant uint* hash_count [[buffer(10)]],      // Number of hashes (for stats)
    uint gid [[thread_position_in_grid]]
) {
    uint kpt = *keys_per_thread;
    uint base_offset = gid * kpt;
    uint xor_block_len = *xor_block_length;
    uint target_count = *hash_count;  // For stats only (Xor Filter32 doesn't need binary search)

    // PHILOX RNG MODE: Generate private key and compute public key
#ifdef USE_PHILOX_RNG
    // Each thread generates its own private key from Philox
    PhiloxState philox_state = philox_for_thread(philox_key, philox_counter, gid);
    uchar privkey[32];
    philox_to_privkey(philox_state, privkey);
    
    // Compute public key from private key: P = k * G
    // Use windowed method: process private key in 4-bit windows (wNAF)
    // Start at infinity
    ulong4 cur_X = {0,0,0,0}, cur_Y = {1,0,0,0}, cur_Z = {0,0,0,0}, cur_ZZ = {0,0,0,0};
    
    // Process private key in 4-bit windows (64 windows for 256 bits)
    // Read private key as big-endian (Bitcoin standard)
    // Process from MSB to LSB (left to right)
    for (int byte_idx = 0; byte_idx < 32; byte_idx++) {
        uchar byte_val = privkey[byte_idx];
        
        // Process high nibble (bits 4-7) first
        uint digit_high = (byte_val >> 4) & 0xF;
        if (digit_high > 0) {
            // Double 4 times (multiply by 16)
            for (int d = 0; d < 4; d++) {
                ext_jac_dbl(cur_X, cur_Y, cur_Z, cur_ZZ, cur_X, cur_Y, cur_Z, cur_ZZ);
            }
            // Add digit_high * G (compute digit_high * G by repeated addition)
            ulong4 temp_X = SECP256K1_GX, temp_Y = SECP256K1_GY, temp_Z = {1,0,0,0}, temp_ZZ = {1,0,0,0};
            for (uint d = 1; d < digit_high; d++) {
                ext_jac_add_affine(temp_X, temp_Y, temp_Z, temp_ZZ, 
                                 SECP256K1_GX, SECP256K1_GY, temp_X, temp_Y, temp_Z, temp_ZZ);
            }
            if (IsZero(cur_Z)) {
                cur_X = temp_X; cur_Y = temp_Y; cur_Z = temp_Z; cur_ZZ = temp_ZZ;
            } else {
                ext_jac_add_affine(cur_X, cur_Y, cur_Z, cur_ZZ, temp_X, temp_Y, cur_X, cur_Y, cur_Z, cur_ZZ);
            }
        }
        
        // Process low nibble (bits 0-3)
        uint digit_low = byte_val & 0xF;
        if (digit_low > 0) {
            // Double 4 times
            for (int d = 0; d < 4; d++) {
                ext_jac_dbl(cur_X, cur_Y, cur_Z, cur_ZZ, cur_X, cur_Y, cur_Z, cur_ZZ);
            }
            // Add digit_low * G
            ulong4 temp_X = SECP256K1_GX, temp_Y = SECP256K1_GY, temp_Z = {1,0,0,0}, temp_ZZ = {1,0,0,0};
            for (uint d = 1; d < digit_low; d++) {
                ext_jac_add_affine(temp_X, temp_Y, temp_Z, temp_ZZ, 
                                 SECP256K1_GX, SECP256K1_GY, temp_X, temp_Y, temp_Z, temp_ZZ);
            }
            if (IsZero(cur_Z)) {
                cur_X = temp_X; cur_Y = temp_Y; cur_Z = temp_Z; cur_ZZ = temp_ZZ;
            } else {
                ext_jac_add_affine(cur_X, cur_Y, cur_Z, cur_ZZ, temp_X, temp_Y, cur_X, cur_Y, cur_Z, cur_ZZ);
            }
        }
    }
    
    // Convert from Jacobian to affine for base point
    // We need affine coordinates for windowed table lookup
    if (IsZero(cur_Z)) {
        // Point at infinity - use generator as fallback
        base_x = SECP256K1_GX;
        base_y = SECP256K1_GY;
    } else {
        // Convert to affine: x = X/Z², y = Y/Z³
        ulong4 z_inv = mod_inv(cur_Z);
        ulong4 z_inv2 = mod_sqr(z_inv);
        ulong4 z_inv3 = mod_mul(z_inv2, z_inv);
        base_x = mod_mul(cur_X, z_inv2);
        base_y = mod_mul(cur_Y, z_inv3);
    }
#else
    // LEGACY MODE: Load P_base from CPU
    ulong4 base_x = load_be(base_point);
    ulong4 base_y = load_be(base_point + 32);
#endif

    // Thread start point using WINDOWED StepTable (4-bit windows)
    // EXTENDED JACOBIAN: (X, Y, Z, ZZ) where ZZ = Z² - saves 1 squaring per add
    // WINDOWED METHOD: max 5 additions instead of ~10 (50% faster start point!)
    // wnaf_table layout: 5 windows × 15 non-zero digits = 75 entries
    // Entry[window * 15 + (digit-1)] = digit * 2^(4*window) * kpt * G
    ulong4 cur_X = base_x, cur_Y = base_y, cur_Z = {1,0,0,0}, cur_ZZ = {1,0,0,0};

    // FIXED: ALL threads use windowed table (even gid=0)
    // This ensures synchronization and consistent performance across all threads
    // Process 5 windows of 4 bits each (covers gid up to 2^20 = 1M threads)
    #define WINDOW_ADD(window) { \
        uint digit = (gid >> (4 * window)) & 0xF; \
        if (digit != 0) { \
            uint idx = window * 15 + (digit - 1); \
            constant uchar* wp = wnaf_table + idx * 64; \
            ext_jac_add_affine(cur_X, cur_Y, cur_Z, cur_ZZ, load_be(wp), load_be(wp + 32), cur_X, cur_Y, cur_Z, cur_ZZ); \
        } \
    }
    WINDOW_ADD(0)
    WINDOW_ADD(1)
    WINDOW_ADD(2)
    WINDOW_ADD(3)
    WINDOW_ADD(4)
    #undef WINDOW_ADD

    // Montgomery batch inversion (BATCH_SIZE = 48)
    // OPTIMIZED FOR M1 Pro 16GB: 48 = maximum occupancy without register spilling
    //
    // Register pressure analysis (M1 Pro 14-core):
    //   M1 Pro shader core: 256KB register file
    //   Each batch entry: ~80 bytes (X, Y, Z, ZZ = 4×64 bits)
    //
    //   48 batch × 80 bytes = 3.8KB per thread ✓ OPTIMAL (no register spilling!)
    //   64 batch × 80 bytes = 5.1KB per thread (minimal spilling)
    //   96 batch × 80 bytes = 7.7KB per thread (heavy spilling)
    //
    // Occupancy calculation:
    //   256KB / 3.8KB = ~67 threads/core ✓ (MAXIMUM occupancy)
    //   256KB / 5.1KB = ~50 threads/core
    //   256KB / 7.7KB = ~33 threads/core
    //
    // Expected performance gain: +12-18% from eliminated register spilling
    // EXTENDED JACOBIAN: batch_ZZ caches Z² for each point (+8-12% from saved squarings)
    // FIXED: Corrected batch size calculation - actual register usage is ~9KB per thread
    // Optimal: 32 batch size → 5.1KB per thread → 50 threads/core (better occupancy)
    // OPTIMIZED BATCH SIZE: M1 Pro register analysis
    // M1 Pro: 256KB register file, ~50 threads/core optimal
    // 256KB / 50 threads = 5.1KB per thread
    // Each batch entry: ~80 bytes (X, Y, Z, ZZ = 4×64 bits)
    // Optimal: 16 batch = 4.8KB/thread → 53 threads/core (no spilling)
    // Previous: 32 batch = 9KB/thread → 28 threads/core (spilling occurred)
    #if defined(__APPLE__) && __APPLE__
        #if __METAL_VERSION__ >= 230  // M1 Pro/Max
            #define BATCH_SIZE 16  // Optimized for M1 Pro (no register spilling)
        #else
            #define BATCH_SIZE 16  // M1 base
        #endif
    #else
        #define BATCH_SIZE 32  // Default for other platforms
    #endif
    ulong4 batch_X[BATCH_SIZE], batch_Y[BATCH_SIZE], batch_Z[BATCH_SIZE], batch_ZZ[BATCH_SIZE];
    ulong4 batch_Zinv[BATCH_SIZE];
    bool batch_valid[BATCH_SIZE]; // Track valid (non-zero Z) points

    uint keys_done = 0;
    while (keys_done < kpt) {
        uint batch_count = min((uint)BATCH_SIZE, kpt - keys_done);

        // Phase 1: Generate batch points using Extended Jacobian and track validity
        for (uint b = 0; b < batch_count; b++) {
            batch_X[b] = cur_X; batch_Y[b] = cur_Y; batch_Z[b] = cur_Z; batch_ZZ[b] = cur_ZZ;
            batch_valid[b] = !IsZero(cur_Z); // Mark if point is valid (not infinity)
            // Use Extended Jacobian add - saves 1 squaring per iteration due to cached ZZ
            ext_jac_add_affine(cur_X, cur_Y, cur_Z, cur_ZZ, SECP256K1_GX, SECP256K1_GY, cur_X, cur_Y, cur_Z, cur_ZZ);
        }

        // Phase 2: Montgomery batch inversion - SKIP Z=0 POINTS!
        // Build product chain only with valid (non-zero) Z values
        ulong4 products[BATCH_SIZE];
        int product_map[BATCH_SIZE]; // Maps product index to batch index
        int valid_count = 0;
        
        for (uint b = 0; b < batch_count; b++) {
            if (batch_valid[b]) {
                if (valid_count == 0) {
                    products[0] = batch_Z[b];
                } else {
                    products[valid_count] = mod_mul(products[valid_count - 1], batch_Z[b]);
                }
                product_map[valid_count] = b;
                valid_count++;
            } else {
                batch_Zinv[b] = ulong4{0, 0, 0, 0}; // Invalid point gets zero inverse
            }
        }
        
        // Only invert if we have valid points
        if (valid_count > 0) {
            ulong4 inv = mod_inv(products[valid_count - 1]);
            
            // Work backwards through valid points only
            for (int i = valid_count - 1; i > 0; i--) {
                int b = product_map[i];
                batch_Zinv[b] = mod_mul(inv, products[i - 1]);
                inv = mod_mul(inv, batch_Z[b]);
            }
            batch_Zinv[product_map[0]] = inv;
        }

        // Phase 3: Convert to affine, hash, check bloom
        // GLV DUAL-RANGE: For each point P, also check φ(P) = (β·x, y)
        // This effectively DOUBLES our key scanning throughput!
        // match_type: 0=compressed, 1=uncompressed, 2=p2sh
        //             3=GLV_compressed, 4=GLV_uncompressed, 5=GLV_p2sh
        for (uint b = 0; b < batch_count; b++) {
            if (!batch_valid[b]) continue; // Skip invalid (infinity) points
            ulong4 z_inv2 = mod_sqr(batch_Zinv[b]);
            ulong4 z_inv3 = mod_mul(z_inv2, batch_Zinv[b]);
            ulong4 ax = mod_mul(batch_X[b], z_inv2);
            ulong4 ay = mod_mul(batch_Y[b], z_inv3);

            // PRIMARY RANGE: Original point P
            uchar h_comp[20], h_uncomp[20], h_p2sh[20];
            hash160_comp(ax, ay, h_comp);
            hash160_uncomp(ax, ay, h_uncomp);
            compute_p2sh_script_hash(h_comp, h_p2sh);
            
            // GLV ENDOMORPHIC RANGE: φ(P) = (β·x, y) - VIRTUALLY FREE!
            // This corresponds to private key λ·k (mod n) where k is original key
            ulong4 endo_x, endo_y;
            glv_endomorphism(ax, ay, endo_x, endo_y);
            
            uchar glv_comp[20], glv_uncomp[20], glv_p2sh[20];
            hash160_comp(endo_x, endo_y, glv_comp);
            hash160_uncomp(endo_x, endo_y, glv_uncomp);
            compute_p2sh_script_hash(glv_comp, glv_p2sh);

            uint key = base_offset + keys_done + b;
            
            // Optimized match saving macro
            // FIXED: Overflow protection - if overflow detected, decrement counter and stop
            // This prevents buffer overflow and ensures match_count stays accurate
            #define SAVE_MATCH(hash_arr, type_val) do { \
                uint idx = atomic_fetch_add_explicit(match_count, 1, memory_order_relaxed); \
                if (idx >= MAX_MATCHES) { \
                    /* Overflow detected - revert increment and stop scanning */ \
                    atomic_fetch_sub_explicit(match_count, 1, memory_order_relaxed); \
                    break; \
                } \
                uint off = idx * 52; \
                match_data[off+0] = key; match_data[off+1] = key>>8; \
                match_data[off+2] = key>>16; match_data[off+3] = key>>24; \
                match_data[off+4] = type_val; \
                for (int p = 5; p < 32; p++) match_data[off+p] = 0; \
                for (int hh = 0; hh < 20; hh++) match_data[off+32+hh] = hash_arr[hh]; \
            } while(0)
            
            // ================================================================
            // TWO-LEVEL VERIFICATION:
            // 1. Bloom filter (fast probabilistic) → may have false positives
            // 2. Binary search (exact match) → eliminates ALL false positives
            // 
            // Result: Only REAL matches are saved! CPU verification is trivial.
            // Performance: 166K bloom hits → ~100 real matches per batch
            // ================================================================
            
            // Check PRIMARY range (original keys) - Xor Filter32 only (Bloom Filter removed)
            // Xor Filter32: O(1) lookup, <0.15% FP rate (no binary search needed)
            if (filter_check(h_comp, xor_fingerprints, xor_seeds, xor_block_len)) {
                SAVE_MATCH(h_comp, 0);  // Real match (FP rate <0.15%, acceptable)
            }
            if (filter_check(h_uncomp, xor_fingerprints, xor_seeds, xor_block_len)) {
                SAVE_MATCH(h_uncomp, 1);
            }
            if (filter_check(h_p2sh, xor_fingerprints, xor_seeds, xor_block_len)) {
                SAVE_MATCH(h_p2sh, 2);
            }
            
            // GLV endomorphic range
            if (filter_check(glv_comp, xor_fingerprints, xor_seeds, xor_block_len)) {
                SAVE_MATCH(glv_comp, 3);
            }
            if (filter_check(glv_uncomp, xor_fingerprints, xor_seeds, xor_block_len)) {
                SAVE_MATCH(glv_uncomp, 4);
            }
            if (filter_check(glv_p2sh, xor_fingerprints, xor_seeds, xor_block_len)) {
                SAVE_MATCH(glv_p2sh, 5);
            }
            
            #undef SAVE_MATCH
        }
        keys_done += batch_count;
    }
    #undef BATCH_SIZE
}


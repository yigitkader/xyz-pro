# XYZ-PRO: Bitcoin Key Scanner - Technical Architecture

## 📋 Table of Contents
1. [Project Purpose](#1-project-purpose)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Algorithm Flow](#3-algorithm-flow)
4. [Core Components](#4-core-components)
5. [Cryptographic Primitives](#5-cryptographic-primitives)
6. [GPU Optimization Techniques](#6-gpu-optimization-techniques)
7. [Data Structures](#7-data-structures)
8. [Pipeline Architecture](#8-pipeline-architecture)
9. [Memory Layout](#9-memory-layout)
10. [Performance Characteristics](#10-performance-characteristics)

---

## 1. Project Purpose

XYZ-PRO is a high-performance Bitcoin private key scanner that uses **Apple Metal GPU** to search for private keys corresponding to a database of known Bitcoin addresses.

### 1.1 What It Does
```
┌─────────────────────────────────────────────────────────────────────────┐
│                        XYZ-PRO KEY SCANNER                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   INPUT:                           OUTPUT:                              │
│   ┌──────────────────┐            ┌──────────────────┐                 │
│   │ Target Addresses │            │ Matched Keys     │                 │
│   │ (50M addresses)  │  ──────▶   │ + WIF Format     │                 │
│   └──────────────────┘            └──────────────────┘                 │
│                                                                         │
│   PROCESS:                                                              │
│   1. Generate random 256-bit private keys (Philox RNG)                 │
│   2. Compute public key (secp256k1 elliptic curve)                     │
│   3. Hash public key → Hash160 (SHA256 + RIPEMD160)                    │
│   4. Check if Hash160 exists in target database (Xor Filter)           │
│   5. If match found → Output private key in WIF format                 │
│                                                                         │
│   SPEED: ~6-30 Million keys/second on Apple M1 Pro                     │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Key Features
- **GPU-Accelerated**: Apple Metal compute shaders for parallel key generation and hashing
- **Probabilistic Filtering**: Xor Filter32 for O(1) target lookup with <0.15% false positive rate
- **GLV Endomorphism**: Scan 2 key ranges with 1 point addition (2× throughput)
- **Triple Buffering**: GPU never waits for CPU verification
- **Thermal Management**: PID controller prevents GPU throttling

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              MAIN THREAD                                │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ 1. Load targets.bin (49M addresses → FxHashMap)                 │   │
│  │ 2. Build XorFilter32 (probabilistic set membership)             │   │
│  │ 3. Initialize GPU (Metal pipeline, buffers)                     │   │
│  │ 4. Run self-tests (verify CPU/GPU consistency)                  │   │
│  │ 5. Start GPU thread + Verification thread                       │   │
│  │ 6. Display stats loop                                           │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                │                                    │
                ▼                                    ▼
┌───────────────────────────────┐    ┌───────────────────────────────────┐
│         GPU THREAD            │    │     VERIFICATION THREAD           │
│  ┌─────────────────────────┐  │    │  ┌─────────────────────────────┐  │
│  │ Triple-Buffered Loop:   │  │    │  │ Rayon Parallel Processing:  │  │
│  │                         │  │    │  │                             │  │
│  │ while !shutdown {       │  │    │  │ for (base_key, matches) {   │  │
│  │   base_key = next_key() │──┼────┼──│   matches.par_iter()        │  │
│  │   dispatch_batch(key)   │  │    │  │     .for_each(|m| {         │  │
│  │   collect_matches()     │──┼────┼─▶│       verify_match(m)       │  │
│  │ }                       │  │    │  │     });                     │  │
│  └─────────────────────────┘  │    │  │ }                           │  │
└───────────────────────────────┘    │  └─────────────────────────────┘  │
                                     └───────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         METAL GPU KERNEL                                │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ kernel void scan_keys(thread_id, base_key, philox_state, ...)   │   │
│  │ {                                                                │   │
│  │   // Phase 1: Generate starting point using windowed NAF        │   │
│  │   point = base_pubkey + thread_id × G                           │   │
│  │                                                                  │   │
│  │   // Phase 2: Batch point additions (BATCH_SIZE=20)             │   │
│  │   for (i = 0; i < keys_per_thread; i += 20) {                   │   │
│  │     batch_X[0..20] = point.x + (0..20) × G.x                    │   │
│  │     batch_Y[0..20] = point.y + (0..20) × G.y                    │   │
│  │                                                                  │   │
│  │     // Montgomery batch inversion (1 mod_inv per 20 points!)    │   │
│  │     batch_invert(batch_Z[0..20])                                │   │
│  │                                                                  │   │
│  │     // Phase 3: Hash and check                                  │   │
│  │     for each point in batch {                                   │   │
│  │       hash_comp = Hash160(compressed_pubkey)                    │   │
│  │       hash_uncomp = Hash160(uncompressed_pubkey)                │   │
│  │       hash_p2sh = Hash160(P2SH_script(hash_comp))               │   │
│  │                                                                  │   │
│  │       // GLV: Get second point for FREE!                        │   │
│  │       glv_point = (β × point.x, point.y)  // λ·k mod n          │   │
│  │       glv_hash_comp = Hash160(glv_compressed)                   │   │
│  │       ...                                                        │   │
│  │                                                                  │   │
│  │       // Check Xor Filter + Prefix Table                        │   │
│  │       if (xor_contains(hash) && prefix_exists(hash)) {          │   │
│  │         save_match(key_index, hash, type)                       │   │
│  │       }                                                          │   │
│  │     }                                                            │   │
│  │   }                                                              │   │
│  │ }                                                                │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Algorithm Flow

### 3.1 Startup Sequence

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           STARTUP SEQUENCE                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. LOAD TARGETS                                                        │
│     ├─ Check if targets.bin exists (binary cache)                      │
│     ├─ If not, parse targets.json and create binary cache              │
│     ├─ Load into FxHashMap<Hash160, AddressType>                       │
│     └─ ~49M entries, ~1.2GB memory                                      │
│                                                                         │
│  2. BUILD XOR FILTER32                                                  │
│     ├─ Extract all Hash160 values (20 bytes each)                      │
│     ├─ Construct Xor filter using Dietzfelbinger algorithm             │
│     ├─ Build prefix table (first 4 bytes, sorted, deduplicated)        │
│     └─ ~250MB for filter + ~195MB for prefix table                     │
│                                                                         │
│  3. INITIALIZE GPU                                                      │
│     ├─ Detect Metal device and optimal configuration                   │
│     ├─ Compile Metal shaders (secp256k1_scanner.metal)                 │
│     ├─ Allocate triple-buffered command queues                         │
│     ├─ Upload Xor filter, prefix table, wNAF table to GPU              │
│     └─ Initialize Philox RNG with random seed                          │
│                                                                         │
│  4. SELF-TESTS                                                          │
│     ├─ Verify known test vectors (key → address)                       │
│     ├─ Test GLV endomorphism constants (λ³ ≡ 1 mod n)                  │
│     ├─ Test WIF encoding (compressed/uncompressed)                     │
│     ├─ Test GPU hash calculation matches CPU                           │
│     └─ Test Xor Filter false positive rate                             │
│                                                                         │
│  5. START SCANNING                                                      │
│     ├─ Spawn GPU thread (scan_pipelined)                               │
│     ├─ Spawn verification thread (Rayon parallel)                      │
│     └─ Main thread: stats display + memory monitoring                  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Key Generation Flow (Philox4x32-10 RNG)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    PHILOX4x32-10 KEY GENERATION                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Global State:                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ seed: u64 = random()              // Initial seed                │  │
│  │ counter: AtomicU64 = 0            // Batch counter               │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Per-Batch State (sent to GPU):                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ counter[0..3]: u32[4]  // 128-bit counter                        │  │
│  │ key[0..1]: u32[2]      // 64-bit key (from seed)                 │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  GPU Thread i generates key:                                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ thread_counter = base_counter + thread_id                        │  │
│  │                                                                   │  │
│  │ // First 128 bits                                                │  │
│  │ random[0..3] = philox4x32_10(thread_counter, key)                │  │
│  │                                                                   │  │
│  │ // Second 128 bits (domain separation)                           │  │
│  │ thread_counter.x ^= 0xDEADBEEF   // CRITICAL: Must match CPU!   │  │
│  │ random[4..7] = philox4x32_10(thread_counter, key)                │  │
│  │                                                                   │  │
│  │ private_key[0..31] = concatenate(random[0..7])                   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Properties:                                                            │
│  • Counter-based: Deterministic given (seed, counter)                  │
│  • Parallel-safe: Each thread has unique counter                       │
│  • Cryptographic: 10 rounds of Philox mixing                           │
│  • No state sharing: Perfect for GPU                                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Elliptic Curve Operations

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   SECP256K1 ELLIPTIC CURVE OPERATIONS                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Curve: y² = x³ + 7 (mod p)                                            │
│  p = 2²⁵⁶ - 2³² - 977                                                  │
│  n = curve order (number of points)                                    │
│  G = generator point                                                    │
│                                                                         │
│  ═══════════════════════════════════════════════════════════════════   │
│                                                                         │
│  PUBLIC KEY COMPUTATION: P = k × G                                     │
│                                                                         │
│  Naive approach: k scalar multiplications (very slow!)                 │
│                                                                         │
│  Optimized approach (used in XYZ-PRO):                                 │
│                                                                         │
│  1. WINDOWED NAF PRE-COMPUTATION (CPU, once per batch)                 │
│     ┌──────────────────────────────────────────────────────────────┐   │
│     │ base_pubkey = base_key × G                                   │   │
│     │ wNAF table: [±1×G, ±3×G, ±5×G, ..., ±15×G] for 5 windows     │   │
│     └──────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  2. THREAD STARTING POINT (GPU, per-thread)                            │
│     ┌──────────────────────────────────────────────────────────────┐   │
│     │ thread_offset = thread_id × keys_per_thread                  │   │
│     │ start_point = base_pubkey + thread_offset × G                │   │
│     │                                                               │   │
│     │ // Use wNAF table for fast multiplication                    │   │
│     │ for window in 0..5 {                                         │   │
│     │   digit = (thread_offset >> (4*window)) & 0xF                │   │
│     │   if digit is odd: start_point += wNAF[window][digit]        │   │
│     │ }                                                             │   │
│     └──────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  3. BATCH POINT ADDITIONS (GPU, per-thread)                            │
│     ┌──────────────────────────────────────────────────────────────┐   │
│     │ // Extended Jacobian coordinates: (X:Y:Z:ZZ) where ZZ = Z²   │   │
│     │ // Saves one mod_mul per point addition!                     │   │
│     │                                                               │   │
│     │ for batch in 0..keys_per_thread/BATCH_SIZE {                 │   │
│     │   for i in 0..BATCH_SIZE {                                   │   │
│     │     batch_point[i] = current_point + i × G                   │   │
│     │   }                                                           │   │
│     │   current_point += BATCH_SIZE × G                            │   │
│     │ }                                                             │   │
│     └──────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  4. MONTGOMERY BATCH INVERSION (GPU, per-batch)                        │
│     ┌──────────────────────────────────────────────────────────────┐   │
│     │ // Convert from Jacobian (X:Y:Z) to Affine (x,y)             │   │
│     │ // Need: x = X/Z², y = Y/Z³                                  │   │
│     │ // Naive: 20 mod_inv operations (EXPENSIVE!)                 │   │
│     │ // Montgomery: 1 mod_inv + 60 mod_mul (3× per point)         │   │
│     │                                                               │   │
│     │ products[0] = Z[0]                                           │   │
│     │ for i in 1..BATCH_SIZE:                                      │   │
│     │   products[i] = products[i-1] × Z[i]                         │   │
│     │                                                               │   │
│     │ inv = mod_inv(products[BATCH_SIZE-1])  // Single inversion!  │   │
│     │                                                               │   │
│     │ for i in BATCH_SIZE-1..0:                                    │   │
│     │   Zinv[i] = inv × products[i-1]                              │   │
│     │   inv = inv × Z[i]                                           │   │
│     │ Zinv[0] = inv                                                │   │
│     └──────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.4 GLV Endomorphism (2× Throughput)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       GLV ENDOMORPHISM OPTIMIZATION                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  secp256k1 has special property: φ(P) = (β·x, y) where φ(P) = λ·P      │
│                                                                         │
│  Constants:                                                             │
│  β = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee│
│  λ = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72│
│                                                                         │
│  Property: β³ ≡ 1 (mod p), λ³ ≡ 1 (mod n)                              │
│                                                                         │
│  ═══════════════════════════════════════════════════════════════════   │
│                                                                         │
│  For each point P = k × G computed, we get φ(P) = λk × G for FREE!     │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                                                                   │  │
│  │   Original Point P(x, y):        Endomorphic Point φ(P):         │  │
│  │   └─ Private key: k               └─ Private key: λ·k mod n     │  │
│  │   └─ Hash variants:               └─ Hash variants:              │  │
│  │      • Compressed                    • GLV Compressed            │  │
│  │      • Uncompressed                  • GLV Uncompressed          │  │
│  │      • P2SH                          • GLV P2SH                  │  │
│  │                                                                   │  │
│  │   Cost: Full EC point addition    Cost: 1 mod_mul (β × x)        │  │
│  │                                                                   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Match Types:                                                           │
│  0 = Compressed (primary)      3 = GLV Compressed (endomorphic)        │
│  1 = Uncompressed (primary)    4 = GLV Uncompressed (endomorphic)      │
│  2 = P2SH (primary)            5 = GLV P2SH (endomorphic)              │
│                                                                         │
│  Private Key Recovery (CPU side):                                       │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ if match_type < 3:                                               │  │
│  │   private_key = base_key + key_index    // Normal                │  │
│  │ else:                                                             │  │
│  │   private_key = λ × (base_key + key_index) mod n  // GLV         │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  Result: 6 hash checks per point addition = 2× throughput!             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.5 Hash160 Computation

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      HASH160 COMPUTATION PIPELINE                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Hash160 = RIPEMD160(SHA256(public_key))                               │
│                                                                         │
│  ═══════════════════════════════════════════════════════════════════   │
│                                                                         │
│  COMPRESSED PUBLIC KEY (33 bytes):                                      │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ [0x02 or 0x03] [X-coordinate: 32 bytes]                         │   │
│  │  └─ 0x02 if Y is even, 0x03 if Y is odd                         │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  UNCOMPRESSED PUBLIC KEY (65 bytes):                                    │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ [0x04] [X-coordinate: 32 bytes] [Y-coordinate: 32 bytes]        │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  P2SH SCRIPT HASH (nested SegWit):                                      │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ witness_script = [OP_0=0x00] [PUSH20=0x14] [pubkey_hash: 20b]   │   │
│  │ script_hash = Hash160(witness_script)                           │   │
│  │ P2SH address = Base58Check(0x05 || script_hash)                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  GPU Optimization:                                                      │
│  • SHA256: Custom Metal implementation (sha256_33.metal, sha256_65)    │
│  • RIPEMD160: Custom Metal implementation (ripemd160.metal)            │
│  • P2SH reuses compressed hash (saves 1 SHA256 computation)            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Core Components

### 4.1 File Structure

```
xyz-pro/
├── src/
│   ├── main.rs                    # Entry point, orchestration
│   ├── gpu.rs                     # GPU management, buffer allocation
│   ├── types.rs                   # Hash160, AddressType definitions
│   ├── address.rs                 # WIF encoding, P2SH script hash
│   ├── error.rs                   # Error types
│   ├── lib.rs                     # Library exports
│   │
│   ├── crypto/
│   │   └── mod.rs                 # hash160, is_valid_private_key
│   │
│   ├── rng/
│   │   ├── mod.rs                 # Philox module exports
│   │   ├── philox.rs              # Philox4x32-10 CPU implementation
│   │   └── philox.metal           # Philox4x32-10 GPU implementation
│   │
│   ├── filter/
│   │   ├── mod.rs                 # Filter module exports
│   │   ├── xor_filter.rs          # XorFilter32 construction
│   │   └── xor_lookup.metal       # GPU Xor filter lookup
│   │
│   ├── targets/
│   │   └── mod.rs                 # Target database (binary/JSON)
│   │
│   ├── thermal/
│   │   ├── mod.rs                 # Thermal module exports
│   │   ├── pid_controller.rs      # PID thermal controller
│   │   └── hardware_monitor.rs    # Temperature reading
│   │
│   ├── scanner/
│   │   ├── mod.rs                 # Scanner module exports
│   │   └── zero_copy.rs           # Zero-copy match reading
│   │
│   ├── math/
│   │   ├── mod.rs                 # Math module exports
│   │   ├── field_ops.metal        # Modular arithmetic primitives
│   │   └── simd_bigint.metal      # SIMD 256-bit operations
│   │
│   ├── secp256k1_scanner.metal    # Main GPU kernel
│   ├── sha256_33.metal            # SHA256 for 33-byte input
│   ├── sha256_65.metal            # SHA256 for 65-byte input
│   └── ripemd160.metal            # RIPEMD160 implementation
│
├── tests/
│   ├── integration.rs             # Integration test module
│   └── integration/
│       ├── correctness.rs         # CPU/GPU consistency tests
│       ├── optimizations.rs       # Performance optimization tests
│       ├── edge_cases.rs          # Edge case tests
│       └── cpu_gpu_xor.rs         # Xor filter integration tests
│
├── Cargo.toml                     # Dependencies and features
└── targets.json / targets.bin     # Target address database
```

### 4.2 Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `main.rs` | Entry point, thread spawning, stats display, self-tests |
| `gpu.rs` | GPU initialization, buffer management, dispatch/collect |
| `rng/philox.rs` | Counter-based RNG state management |
| `filter/xor_filter.rs` | Probabilistic set membership filter |
| `targets/mod.rs` | Address database loading and lookup |
| `thermal/*` | GPU temperature monitoring and throttling |
| `secp256k1_scanner.metal` | GPU kernel for key scanning |

---

## 5. Cryptographic Primitives

### 5.1 Philox4x32-10 RNG

```rust
// Constants (maximally equidistributed)
const PHILOX_M0: u32 = 0xD2511F53;
const PHILOX_M1: u32 = 0xCD9E8D57;
const PHILOX_W0: u32 = 0x9E3779B9;  // Golden ratio
const PHILOX_W1: u32 = 0xBB67AE85;  // sqrt(3) - 1

// State: 128-bit counter + 64-bit key
struct PhiloxState {
    counter: [u32; 4],  // 128-bit counter
    key: [u32; 2],      // 64-bit key (from seed)
}

// Round function
fn philox_round(ctr: [u32; 4], key: [u32; 2]) -> [u32; 4] {
    let prod0 = (ctr[0] as u64) * (PHILOX_M0 as u64);
    let prod1 = (ctr[2] as u64) * (PHILOX_M1 as u64);
    
    [
        (prod1 >> 32) as u32 ^ ctr[1] ^ key[0],
        prod1 as u32,
        (prod0 >> 32) as u32 ^ ctr[3] ^ key[1],
        prod0 as u32,
    ]
}

// Full Philox4x32-10 (10 rounds)
fn philox4x32_10(state: &PhiloxState) -> [u32; 4] {
    let mut ctr = state.counter;
    let mut key = state.key;
    
    for _ in 0..10 {
        ctr = philox_round(ctr, key);
        key[0] = key[0].wrapping_add(PHILOX_W0);
        key[1] = key[1].wrapping_add(PHILOX_W1);
    }
    ctr
}
```

### 5.2 Xor Filter32

```rust
struct XorFilter32 {
    fingerprints: Vec<u32>,     // 32-bit fingerprints
    seeds: [u64; 3],            // Hash seeds for 3 blocks
    block_length: usize,        // Capacity / 3
    prefix_table: Vec<u32>,     // Sorted 4-byte prefixes
}

// Membership check: O(1)
fn contains(&self, hash: &[u8; 20]) -> bool {
    let fp = compute_fingerprint(hash);
    let (h0, h1, h2) = hash_triple(hash, &self.seeds, self.block_length);
    
    self.fingerprints[h0] ^ self.fingerprints[h1] ^ self.fingerprints[h2] == fp
}

// Properties:
// - False Positive Rate: ~2^-32 ≈ 0.00000002% per query
// - Space: ~1.27n × 32 bits = 40.6 bits/element
// - No false negatives (all inserted elements found)
```

### 5.3 Address Types

| Type | Format | Prefix | Hash Used |
|------|--------|--------|-----------|
| P2PKH | Base58Check | `1...` | Hash160(compressed_pubkey) |
| P2SH | Base58Check | `3...` | Hash160(witness_script) |
| P2WPKH | Bech32 | `bc1q...` | Hash160(compressed_pubkey) |

---

## 6. GPU Optimization Techniques

### 6.1 Windowed NAF Table

```
Pre-compute: G, 3G, 5G, ..., 15G for each of 5 windows
Total: 5 × 8 = 40 pre-computed points

Thread starting point calculation:
  offset = thread_id × keys_per_thread
  
  for window in 0..5:
    digit = (offset >> (4 × window)) & 0xF
    if digit is odd:
      point += wNAF_table[window][digit/2]
    
Result: ~8 point additions instead of full scalar multiplication
Speedup: ~50% faster thread initialization
```

### 6.2 Extended Jacobian Coordinates

```
Standard Jacobian: (X:Y:Z) where x = X/Z², y = Y/Z³
Extended Jacobian: (X:Y:Z:ZZ) where ZZ = Z²

Point Addition:
  Standard: 16M + 4S (M=multiplication, S=squaring)
  Extended: 14M + 5S (save 2M at cost of 1S)
  
Since M ≈ 1.5S, Extended saves ~1.5 multiplications per addition
For BATCH_SIZE=20: saves 30 multiplications per batch!
```

### 6.3 Montgomery Batch Inversion

```
Input: Z[0], Z[1], ..., Z[n-1]
Output: Z⁻¹[0], Z⁻¹[1], ..., Z⁻¹[n-1]

Algorithm:
  products[0] = Z[0]
  products[i] = products[i-1] × Z[i]  for i = 1..n-1
  
  inv = mod_inv(products[n-1])  // SINGLE expensive inversion!
  
  for i = n-1..1:
    Z⁻¹[i] = inv × products[i-1]
    inv = inv × Z[i]
  Z⁻¹[0] = inv

Cost: 1 mod_inv + 3(n-1) mod_mul
Naive: n mod_inv

For n=20: 1 inversion vs 20 inversions = 20× faster!
```

### 6.4 Register Pressure Management

```metal
#define BATCH_SIZE 20  // Optimal for M1 Pro

// Thread-local arrays (NOT threadgroup!)
ulong4 batch_X[BATCH_SIZE];     // 20 × 32 bytes = 640 bytes
ulong4 batch_Y[BATCH_SIZE];     // 20 × 32 bytes = 640 bytes
ulong4 batch_Z[BATCH_SIZE];     // 20 × 32 bytes = 640 bytes
ulong4 batch_ZZ[BATCH_SIZE];    // 20 × 32 bytes = 640 bytes
ulong4 batch_Zinv[BATCH_SIZE];  // 20 × 32 bytes = 640 bytes

// Total: ~3.2 KB per thread
// M1 Pro: 32 KB registers per SIMD group (32 threads)
// 32 threads × 3.2 KB = 102.4 KB > 32 KB → spilling!

// BATCH_SIZE=20 instead of 24 reduces to 85 KB → still spilling but less
// Smaller threadgroup (64) = more threadgroups = better occupancy
```

---

## 7. Data Structures

### 7.1 GPU Buffer Layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        GPU BUFFER LAYOUT                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  PER-BUFFER-SET (×3 for triple buffering):                             │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ philox_key_buf:      8 bytes   (u64 seed)                       │   │
│  │ philox_counter_buf:  16 bytes  (u32[4] counter)                 │   │
│  │ base_privkey_buf:    32 bytes  (private key)                    │   │
│  │ base_pubkey_x_buf:   32 bytes  (pre-computed pubkey X)          │   │
│  │ base_pubkey_y_buf:   32 bytes  (pre-computed pubkey Y)          │   │
│  │ match_data_buf:      52 × 524K bytes (~27 MB)                   │   │
│  │ match_count_buf:     4 bytes   (atomic counter)                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  SHARED READ-ONLY BUFFERS:                                              │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ wnaf_table_buf:      75 × 64 = 4.8 KB (windowed NAF points)     │   │
│  │ xor_fingerprints:    ~250 MB (Xor filter)                       │   │
│  │ xor_seeds:           24 bytes (3 × u64)                         │   │
│  │ xor_block_length:    4 bytes                                    │   │
│  │ prefix_table:        ~195 MB (sorted prefixes)                  │   │
│  │ prefix_count:        4 bytes                                    │   │
│  │ kpt_buf:             4 bytes (keys_per_thread)                  │   │
│  │ hash_count_buf:      4 bytes (target count)                     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  TOTAL GPU MEMORY: ~500 MB (mostly Xor filter + prefix table)          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Match Entry Layout (52 bytes)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        MATCH ENTRY (52 bytes)                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Offset  Size  Field                                                    │
│  ──────  ────  ─────────────────────────────────────────────────────   │
│  0       4     key_index: u32 (offset from base_key)                   │
│  4       1     match_type: u8 (0-5, see GLV types)                     │
│  5       27    padding (reserved for future use)                       │
│  32      20    hash160: [u8; 20] (the matched hash)                    │
│                                                                         │
│  match_type values:                                                     │
│  0 = Compressed (primary key)                                          │
│  1 = Uncompressed (primary key)                                        │
│  2 = P2SH (primary key)                                                │
│  3 = GLV Compressed (λ × key mod n)                                    │
│  4 = GLV Uncompressed (λ × key mod n)                                  │
│  5 = GLV P2SH (λ × key mod n)                                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Pipeline Architecture

### 8.1 Triple Buffering

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      TRIPLE BUFFERING TIMELINE                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Time →                                                                 │
│                                                                         │
│  GPU Queue 0: [====Batch 0====][            ][====Batch 3====][    ]   │
│  GPU Queue 1: [    ][====Batch 1====][            ][====Batch 4====]   │
│  GPU Queue 2: [        ][====Batch 2====][            ][====Batch 5]   │
│                                                                         │
│  CPU Read:    [    ][Read 0][Read 1][Read 2][Read 3][Read 4][Read 5]   │
│                                                                         │
│  Rayon:       [        ][Verify 0][Verify 1][Verify 2][Verify 3][  ]   │
│                                                                         │
│  ═══════════════════════════════════════════════════════════════════   │
│                                                                         │
│  Key insight: GPU is NEVER waiting for CPU!                            │
│  • While GPU computes batch N, CPU reads batch N-1                     │
│  • While CPU reads batch N-1, Rayon verifies batch N-2                 │
│                                                                         │
│  Buffer rotation:                                                       │
│  current_buf = (current_buf + 1) % 3                                   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 8.2 Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          DATA FLOW DIAGRAM                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐                                                        │
│  │ Philox RNG  │ seed + counter                                        │
│  │   (CPU)     ├────────────────────────┐                              │
│  └─────────────┘                        │                              │
│                                         ▼                              │
│  ┌─────────────┐    base_key     ┌─────────────┐                       │
│  │ next_key()  ├────────────────▶│ GPU Kernel  │                       │
│  │   (CPU)     │    pubkey_xy    │ scan_keys() │                       │
│  └─────────────┘─────────────────│             │                       │
│                                  │  • Philox   │                       │
│  ┌─────────────┐                 │  • EC add   │                       │
│  │ Xor Filter  │─────────────────│  • Hash160  │                       │
│  │   (GPU)     │  fingerprints   │  • Filter   │                       │
│  └─────────────┘                 │  • GLV      │                       │
│                                  └──────┬──────┘                       │
│                                         │ matches                      │
│                                         ▼                              │
│  ┌─────────────┐                 ┌─────────────┐                       │
│  │ wait_and_   │◀────────────────│ Match Buffer│                       │
│  │ collect()   │    PotentialMatch (GPU)       │                       │
│  └──────┬──────┘                 └─────────────┘                       │
│         │                                                               │
│         ▼                                                               │
│  ┌─────────────┐                 ┌─────────────┐                       │
│  │ Verification│                 │ Target DB   │                       │
│  │   Thread    │────────────────▶│  (FxHash)   │                       │
│  │   (Rayon)   │    hash lookup  │             │                       │
│  └──────┬──────┘                 └─────────────┘                       │
│         │                                                               │
│         ▼                                                               │
│  ┌─────────────┐                                                        │
│  │ Found Keys  │ → WIF encoding → Console output + file                │
│  │   (Vec)     │                                                        │
│  └─────────────┘                                                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Memory Layout

### 9.1 CPU Memory

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CPU MEMORY USAGE                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Component                           Size                               │
│  ─────────────────────────────────   ────────────                      │
│  TargetDatabase (FxHashMap)          ~1.2 GB (49M × ~25 bytes)         │
│    └─ Hash160: 20 bytes                                                 │
│    └─ AddressType: 1 byte                                               │
│    └─ HashMap overhead: ~4 bytes                                        │
│                                                                         │
│  XorFilter32 (fingerprints)          ~250 MB (49M × 1.27 × 4 bytes)    │
│  XorFilter32 (prefix_table)          ~195 MB (48.7M × 4 bytes)         │
│                                                                         │
│  Match buffers (×6 for pool)         ~3 MB (6 × 524K × 1 byte avg)     │
│                                                                         │
│  Rayon thread stacks                 ~64 MB (4 threads × 16 MB)        │
│                                                                         │
│  TOTAL ESTIMATED                     ~1.7 GB                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 9.2 GPU Memory (Unified on Apple Silicon)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         GPU MEMORY USAGE                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Component                           Size                               │
│  ─────────────────────────────────   ────────────                      │
│  Xor Filter fingerprints             ~250 MB                           │
│  Prefix table                        ~195 MB                           │
│  Match buffers (×3)                  ~81 MB (3 × 524K × 52 bytes)      │
│  wNAF table                          ~5 KB                             │
│  Philox state buffers (×3)           ~180 bytes                        │
│                                                                         │
│  TOTAL GPU BUFFERS                   ~500 MB                           │
│                                                                         │
│  Note: Apple Silicon uses unified memory, so GPU buffers               │
│  share physical RAM with CPU. Total system usage ≈ 2.2 GB             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Performance Characteristics

### 10.1 Throughput Analysis

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    THROUGHPUT CALCULATION                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  M1 Pro 14-core GPU configuration:                                      │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Threads: 229,376                                                 │   │
│  │ Keys/thread: 128                                                 │   │
│  │ Keys/batch: 29.36 M                                              │   │
│  │ GLV factor: 2× (6 hashes per point)                              │   │
│  │ Effective keys/batch: 58.72 M                                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Expected throughput:                                                   │
│  • Batch time: ~1-3 seconds (depending on thermal state)               │
│  • Keys/second: ~20-60 Million                                         │
│  • With GLV: ~40-120 Million effective keys/second                     │
│                                                                         │
│  Bottlenecks:                                                           │
│  1. GPU compute (EC point additions, mod_inv)                          │
│  2. Memory bandwidth (Xor filter reads)                                │
│  3. Thermal throttling (sustained load)                                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 10.2 Optimization Impact

| Optimization | Impact | Notes |
|--------------|--------|-------|
| Xor Filter (vs Bloom) | -90% cache misses | O(1) lookup, 3 reads vs 12+ |
| GLV Endomorphism | 2× throughput | 6 hashes per EC addition |
| Montgomery Batch | -95% inversions | 1 inv per 20 points |
| Windowed NAF | -50% init time | 8 adds vs scalar mult |
| Triple Buffering | -33% GPU idle | GPU never waits for CPU |
| Prefix Table | -90% CPU verify | Reduces false positives |
| Extended Jacobian | -10% EC ops | Save 2M per addition |
| Pre-computed wNAF | -10ms startup | lazy_static table |

### 10.3 False Positive Analysis

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    FALSE POSITIVE PIPELINE                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Stage 1: Xor Filter32                                                  │
│  ├─ Input: ~29M hashes per batch                                       │
│  ├─ FP rate: 0.15%                                                      │
│  └─ Output: ~43.5K potential matches                                   │
│                                                                         │
│  Stage 2: Prefix Table (GPU)                                            │
│  ├─ Input: ~43.5K Xor Filter positives                                 │
│  ├─ Reduction: ~93% (only ~7% have matching prefix)                    │
│  └─ Output: ~3K matches sent to CPU                                    │
│                                                                         │
│  Stage 3: CPU Verification (Rayon)                                      │
│  ├─ Input: ~3K potential matches                                       │
│  ├─ Full Hash160 recomputation                                         │
│  ├─ Target database lookup                                              │
│  └─ Output: 0-few true matches (depends on targets)                    │
│                                                                         │
│  Result: CPU only verifies ~0.01% of scanned keys!                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Appendix A: Key Constants

```rust
// Curve parameters
const P: U256 = 2^256 - 2^32 - 977;  // Field modulus
const N: U256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;  // Order
const K: u64 = 4294968273;  // Reduction constant

// GLV constants
const BETA: U256 = 0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee;
const LAMBDA: U256 = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72;

// Philox constants
const M0: u32 = 0xD2511F53;
const M1: u32 = 0xCD9E8D57;
const W0: u32 = 0x9E3779B9;  // Golden ratio
const W1: u32 = 0xBB67AE85;  // sqrt(3) - 1

// Configuration
const BATCH_SIZE: u32 = 20;         // Points per Montgomery batch
const KEYS_PER_THREAD: u32 = 128;   // Keys processed per GPU thread
const MAX_THREADS: usize = 229_376; // M1 Pro 14-core optimal
```

---

## Appendix B: Build & Run

```bash
# Build (release mode with optimizations)
cargo build --release

# Run with default features (all optimizations)
./target/release/xyz-pro

# Run with fast startup (skip heavy tests)
FAST_START=1 ./target/release/xyz-pro
# or
./target/release/xyz-pro --fast

# Run tests
cargo test --release

# Feature flags
cargo build --release --features "all-features"
cargo build --release --features "safe-features"  # No experimental SIMD
cargo build --release --no-default-features       # Legacy mode
```

---

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| **Hash160** | RIPEMD160(SHA256(data)), produces 20-byte hash |
| **P2PKH** | Pay-to-Public-Key-Hash, legacy address format (1...) |
| **P2SH** | Pay-to-Script-Hash, used for nested SegWit (3...) |
| **P2WPKH** | Pay-to-Witness-Public-Key-Hash, native SegWit (bc1q...) |
| **WIF** | Wallet Import Format, Base58Check encoded private key |
| **GLV** | Gallant-Lambert-Vanstone endomorphism optimization |
| **NAF** | Non-Adjacent Form, efficient scalar representation |
| **Jacobian** | Projective coordinates where x=X/Z², y=Y/Z³ |
| **Philox** | Counter-based PRNG suitable for parallel generation |
| **Xor Filter** | Probabilistic set membership with no false negatives |

---

*Document Version: 1.0*
*Last Updated: 2024*
*Target Platform: Apple Silicon (M1/M2/M3 Pro/Max/Ultra)*


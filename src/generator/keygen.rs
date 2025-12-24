//! High-performance private key generation
//! 
//! ## Modes
//! 
//! ### Sequential Mode (GPU-compatible) - DEFAULT
//! Generates keys as `base_privkey + offset`, matching GPU behavior exactly.
//! This is the recommended mode for range scanning.
//! 
//! ### Random Mode (Philox RNG) - LEGACY
//! Uses Philox RNG for pseudo-random key generation.
//! WARNING: Not compatible with GPU mode - searches different key space!
//!
//! ## GLV Endomorphism Support
//! 
//! Both modes support GLV endomorphism for 2x throughput:
//! - k (base key)
//! - λ·k mod n (GLV transformed key)

use std::sync::atomic::{AtomicU64, Ordering};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{Scalar, SecretKey};
use rayon::prelude::*;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use super::RawKeyData;

/// Secp256k1 curve order n - keys must be less than this
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// GLV Lambda constant for endomorphism: λ such that λ·G = φ(G)
/// where φ(x,y) = (β·x, y) is the curve endomorphism
/// 
/// This MUST match the GPU constant in keygen.metal
const GLV_LAMBDA: [u8; 32] = [
    0x53, 0x63, 0xad, 0x4c, 0xc0, 0x5c, 0x30, 0xe0,
    0xa5, 0x26, 0x1c, 0x02, 0x88, 0x12, 0x64, 0x5a,
    0x12, 0x2e, 0x22, 0xea, 0x20, 0x81, 0x66, 0x78,
    0xdf, 0x02, 0x96, 0x7c, 0x1b, 0x23, 0xbd, 0x72,
];

lazy_static::lazy_static! {
    /// Pre-computed GLV Lambda as Scalar for efficient multiplication
    static ref GLV_LAMBDA_SCALAR: Scalar = {
        Scalar::from_repr_vartime(GLV_LAMBDA.into()).expect("GLV_LAMBDA is valid")
    };
    
    /// Pre-computed GLV Lambda Squared for GLV3 mode: λ² mod n
    static ref GLV_LAMBDA_SQ_SCALAR: Scalar = {
        *GLV_LAMBDA_SCALAR * *GLV_LAMBDA_SCALAR
    };
}

// ============================================================================
// SEQUENTIAL KEY GENERATOR (GPU-COMPATIBLE)
// ============================================================================

/// Sequential key generator that matches GPU behavior exactly
/// 
/// Generates keys as: base_privkey + offset
/// This ensures CPU and GPU scan the SAME key space.
/// 
/// ## GPU Compatibility
/// - Uses same offset arithmetic as GPU shader
/// - Supports GLV endomorphism (2x or 3x throughput)
/// - Range scanning works identically between CPU and GPU
pub struct CpuKeyGenerator {
    /// Base private key (256-bit, big-endian)
    base_privkey: [u8; 32],
    /// Current offset from base
    current_offset: AtomicU64,
    /// End offset (for range limiting)
    end_offset: Option<u64>,
    /// GLV mode: 1 (disabled), 2 (GLV2), 3 (GLV3)
    glv_multiplier: usize,
}

impl CpuKeyGenerator {
    /// Create a new sequential generator starting from offset
    /// 
    /// # Arguments
    /// * `start_offset` - Starting offset (must be >= 1)
    /// * `end_offset` - Optional end offset for range limiting
    /// * `glv_multiplier` - 1 (no GLV), 2 (GLV2), or 3 (GLV3)
    pub fn new(start_offset: u64, end_offset: Option<u64>, glv_multiplier: usize) -> Self {
        assert!(start_offset >= 1, "start_offset must be >= 1 (zero is invalid private key)");
        assert!(glv_multiplier >= 1 && glv_multiplier <= 3, "glv_multiplier must be 1, 2, or 3");
        
        // Create base private key from start_offset
        // Layout: 256-bit big-endian, offset in lowest 64 bits
        let mut base_privkey = [0u8; 32];
        base_privkey[24..32].copy_from_slice(&start_offset.to_be_bytes());
        
        Self {
            base_privkey,
            current_offset: AtomicU64::new(0),
            end_offset: end_offset.map(|e| e.saturating_sub(start_offset)),
            glv_multiplier,
        }
    }
    
    /// Backwards-compatible constructor with seed (interpreted as start_offset)
    /// 
    /// For easy migration from PhiloxKeyGenerator.
    /// The 'seed' parameter is now used as start_offset for sequential generation.
    pub fn with_seed(seed: u64) -> Self {
        Self::new(seed.max(1), None, 2)  // GLV2 mode by default
    }
    
    /// Create with explicit base private key (256-bit)
    /// 
    /// For advanced use cases where you need a specific starting point
    /// in the full 256-bit key space.
    pub fn with_base_key(base_privkey: [u8; 32], end_offset: Option<u64>, glv_multiplier: usize) -> Self {
        Self {
            base_privkey,
            current_offset: AtomicU64::new(0),
            end_offset,
            glv_multiplier,
        }
    }
    
    /// Generate a batch of sequential keys
    /// 
    /// Returns keys for offsets [current, current + count)
    /// With GLV enabled, returns glv_multiplier * count keys
    pub fn generate_batch(&self, count: usize) -> Vec<RawKeyData> {
        let start_offset = self.current_offset.fetch_add(count as u64, Ordering::Relaxed);
        
        // Check range limit
        if let Some(end) = self.end_offset {
            if start_offset >= end {
                return Vec::new();
            }
        }
        
        (0..count)
            .into_par_iter()
            .flat_map(|i| {
                let offset = start_offset + i as u64;
                
                // Check range limit per-key
                if let Some(end) = self.end_offset {
                    if offset >= end {
                        return Vec::new();
                    }
                }
                
                self.generate_at_offset(offset)
            })
            .collect()
    }
    
    /// Generate key(s) at specific offset from base
    /// 
    /// Returns 1, 2, or 3 keys depending on GLV mode
    fn generate_at_offset(&self, offset: u64) -> Vec<RawKeyData> {
        let mut results = Vec::with_capacity(self.glv_multiplier);
        
        // Compute private_key = base + offset (256-bit addition)
        let private_key = match self.add_offset_to_base(offset) {
            Some(k) => k,
            None => return results,
        };
        
        // Validate and generate base key
        if !is_valid_private_key(&private_key) {
            return results;
        }
        
        if let Some((pubkey_hash, p2sh_hash)) = compute_pubkey_hash(&private_key) {
            results.push(RawKeyData {
                private_key,
                pubkey_hash,
                p2sh_hash,
            });
        }
        
        // GLV key: λ·k mod n
        if self.glv_multiplier >= 2 {
            if let Some(glv_key) = compute_glv_key(&private_key) {
                if is_valid_private_key(&glv_key) {
                    if let Some((glv_hash, glv_p2sh)) = compute_pubkey_hash(&glv_key) {
                        results.push(RawKeyData {
                            private_key: glv_key,
                            pubkey_hash: glv_hash,
                            p2sh_hash: glv_p2sh,
                        });
                    }
                }
            }
        }
        
        // GLV² key: λ²·k mod n
        if self.glv_multiplier >= 3 {
            if let Some(glv2_key) = compute_glv2_key(&private_key) {
                if is_valid_private_key(&glv2_key) {
                    if let Some((glv2_hash, glv2_p2sh)) = compute_pubkey_hash(&glv2_key) {
                        results.push(RawKeyData {
                            private_key: glv2_key,
                            pubkey_hash: glv2_hash,
                            p2sh_hash: glv2_p2sh,
                        });
                    }
                }
            }
        }
        
        results
    }
    
    /// Add 64-bit offset to 256-bit base private key
    /// 
    /// Matches GPU's scalar_add_u64 behavior exactly
    fn add_offset_to_base(&self, offset: u64) -> Option<[u8; 32]> {
        let mut result = self.base_privkey;
        
        // Add offset to the low 64 bits (bytes 24-31, big-endian)
        let mut carry = offset;
        for i in (0..32).rev() {
            if carry == 0 {
                break;
            }
            let sum = result[i] as u64 + (carry & 0xFF);
            result[i] = sum as u8;
            carry = (carry >> 8) + (sum >> 8);
        }
        
        // Check if we overflowed or exceeded curve order
        // (extremely unlikely for reasonable offsets)
        if carry != 0 {
            return None;
        }
        
        Some(result)
    }
    
    /// Get current offset
    pub fn current_offset(&self) -> u64 {
        self.current_offset.load(Ordering::Relaxed)
    }
    
    /// Check if range is complete
    pub fn is_range_complete(&self) -> bool {
        if let Some(end) = self.end_offset {
            self.current_offset.load(Ordering::Relaxed) >= end
        } else {
            false
        }
    }
    
    /// Get progress percentage (0.0 to 100.0)
    pub fn progress_percent(&self) -> Option<f64> {
        self.end_offset.map(|end| {
            let current = self.current_offset.load(Ordering::Relaxed);
            if end == 0 {
                100.0
            } else {
                (current as f64 / end as f64 * 100.0).min(100.0)
            }
        })
    }
    
    /// Get GLV multiplier
    pub fn glv_multiplier(&self) -> usize {
        self.glv_multiplier
    }
    
    /// Check if GLV mode is enabled (backwards compatibility)
    pub fn is_glv_enabled(&self) -> bool {
        self.glv_multiplier > 1
    }
    
    /// Create without GLV (backwards compatibility)
    pub fn without_glv(start_offset: u64) -> Self {
        Self::new(start_offset.max(1), None, 1)
    }
    
    /// Get current count (backwards compatibility, same as current_offset)
    pub fn current_count(&self) -> u64 {
        self.current_offset.load(Ordering::Relaxed)
    }
    
    /// Get effective keys generated (count * glv_multiplier)
    pub fn effective_keys_generated(&self) -> u64 {
        self.current_offset.load(Ordering::Relaxed) * self.glv_multiplier as u64
    }
}

/// Compute GLV² transformed key: λ²·k mod n
#[inline]
fn compute_glv2_key(private_key: &[u8; 32]) -> Option<[u8; 32]> {
    let k = Scalar::from_repr_vartime((*private_key).into())?;
    let glv2_k = k * *GLV_LAMBDA_SQ_SCALAR;
    let glv2_bytes = glv2_k.to_repr();
    let mut result = [0u8; 32];
    result.copy_from_slice(&glv2_bytes);
    Some(result)
}

// ============================================================================
// LEGACY PHILOX KEY GENERATOR (Random Mode)
// ============================================================================

/// Philox 4x32 constants
const PHILOX_M0: u32 = 0xD2511F53;
const PHILOX_M1: u32 = 0xCD9E8D57;
const PHILOX_W0: u32 = 0x9E3779B9;
const PHILOX_W1: u32 = 0xBB67AE85;

/// LEGACY Philox-based random key generator
/// 
/// WARNING: This generates RANDOM keys using Philox RNG, which is
/// NOT compatible with GPU's sequential mode. Use CpuKeyGenerator
/// for GPU-compatible sequential key generation.
/// 
/// For each base key k, generates two keys:
/// - k (base key)
/// - λ·k mod n (GLV transformed key)
#[deprecated(since = "0.4.0", note = "Use CpuKeyGenerator for GPU-compatible sequential mode")]
pub struct PhiloxKeyGenerator {
    /// Global counter for unique key generation
    counter: AtomicU64,
    /// Seed for RNG
    seed: [u32; 2],
    /// Enable GLV mode (2x keys per base key) - default true for GPU compatibility
    glv_enabled: bool,
}

impl PhiloxKeyGenerator {
    /// Create a new key generator with cryptographically strong random seed
    /// Uses OS-provided entropy via `rand::thread_rng()` (backed by getrandom)
    /// GLV mode is enabled by default for GPU compatibility
    pub fn new() -> Self {
        use rand::Rng;
        
        // Use cryptographically secure random source from the OS
        // This is backed by /dev/urandom on Unix, BCryptGenRandom on Windows
        let mut rng = rand::thread_rng();
        let seed: u64 = rng.gen();
        
        Self {
            counter: AtomicU64::new(0),
            seed: [(seed & 0xFFFFFFFF) as u32, ((seed >> 32) & 0xFFFFFFFF) as u32],
            glv_enabled: true, // Match GPU default
        }
    }
    
    /// Create with specific seed for reproducibility
    pub fn with_seed(seed: u64) -> Self {
        Self {
            counter: AtomicU64::new(0),
            seed: [(seed & 0xFFFFFFFF) as u32, ((seed >> 32) & 0xFFFFFFFF) as u32],
            glv_enabled: true,
        }
    }
    
    /// Create without GLV (for testing or legacy compatibility)
    pub fn without_glv(seed: u64) -> Self {
        Self {
            counter: AtomicU64::new(0),
            seed: [(seed & 0xFFFFFFFF) as u32, ((seed >> 32) & 0xFFFFFFFF) as u32],
            glv_enabled: false,
        }
    }
    
    /// Check if GLV mode is enabled
    pub fn is_glv_enabled(&self) -> bool {
        self.glv_enabled
    }
    
    /// Generate a batch of raw key data in parallel
    /// With GLV enabled, returns 2x keys (base + GLV transformed)
    #[inline]
    pub fn generate_batch(&self, count: usize) -> Vec<RawKeyData> {
        let start_counter = self.counter.fetch_add(count as u64, Ordering::Relaxed);
        
        if self.glv_enabled {
            // GLV mode: each counter produces 2 keys
            (0..count)
                .into_par_iter()
                .flat_map(|i| {
                    let counter = start_counter + i as u64;
                    self.generate_with_glv(counter)
                })
                .collect()
        } else {
            // Legacy mode: one key per counter
            (0..count)
                .into_par_iter()
                .filter_map(|i| {
                    let counter = start_counter + i as u64;
                    self.generate_single(counter)
                })
                .collect()
        }
    }
    
    /// Generate base key + GLV key pair from counter value
    /// Returns 0, 1, or 2 keys depending on validity
    #[inline]
    fn generate_with_glv(&self, counter: u64) -> Vec<RawKeyData> {
        let mut results = Vec::with_capacity(2);
        
        // Generate base private key using Philox
        let mut private_key = [0u8; 32];
        
        let counter_lo = (counter & 0xFFFFFFFF) as u32;
        let counter_hi = ((counter >> 32) & 0xFFFFFFFF) as u32;
        
        // First 16 bytes: use stream 0
        let ctr0 = [counter_lo, counter_hi, 0, 0];
        let out0 = philox4x32(ctr0, self.seed);
        private_key[0..4].copy_from_slice(&out0[0].to_le_bytes());
        private_key[4..8].copy_from_slice(&out0[1].to_le_bytes());
        private_key[8..12].copy_from_slice(&out0[2].to_le_bytes());
        private_key[12..16].copy_from_slice(&out0[3].to_le_bytes());
        
        // Second 16 bytes: use stream 1
        let ctr1 = [counter_lo, counter_hi, 1, 0];
        let out1 = philox4x32(ctr1, self.seed);
        private_key[16..20].copy_from_slice(&out1[0].to_le_bytes());
        private_key[20..24].copy_from_slice(&out1[1].to_le_bytes());
        private_key[24..28].copy_from_slice(&out1[2].to_le_bytes());
        private_key[28..32].copy_from_slice(&out1[3].to_le_bytes());
        
        // Validate base key
        if !is_valid_private_key(&private_key) {
            return results;
        }
        
        // Try to generate base key data
        if let Some((pubkey_hash, p2sh_hash)) = compute_pubkey_hash(&private_key) {
            results.push(RawKeyData {
                private_key,
                pubkey_hash,
                p2sh_hash,
            });
        }
        
        // Generate GLV key: λ·k mod n
        if let Some(glv_key) = compute_glv_key(&private_key) {
            if is_valid_private_key(&glv_key) {
                if let Some((glv_pubkey_hash, glv_p2sh_hash)) = compute_pubkey_hash(&glv_key) {
                    results.push(RawKeyData {
                        private_key: glv_key,
                        pubkey_hash: glv_pubkey_hash,
                        p2sh_hash: glv_p2sh_hash,
                    });
                }
            }
        }
        
        results
    }
    
    /// Generate a single key from counter value (legacy, non-GLV)
    #[inline(always)]
    fn generate_single(&self, counter: u64) -> Option<RawKeyData> {
        // Generate 32 bytes using Philox
        // OPTIMIZED: 2 Philox calls (16 bytes each) instead of 8 calls (4 bytes each)
        // Philox-4x32 produces 4 x 32-bit = 128 bits = 16 bytes per call
        let mut private_key = [0u8; 32];
        
        let counter_lo = (counter & 0xFFFFFFFF) as u32;
        let counter_hi = ((counter >> 32) & 0xFFFFFFFF) as u32;
        
        // First 16 bytes: use stream 0
        let ctr0 = [counter_lo, counter_hi, 0, 0];
        let out0 = philox4x32(ctr0, self.seed);
        private_key[0..4].copy_from_slice(&out0[0].to_le_bytes());
        private_key[4..8].copy_from_slice(&out0[1].to_le_bytes());
        private_key[8..12].copy_from_slice(&out0[2].to_le_bytes());
        private_key[12..16].copy_from_slice(&out0[3].to_le_bytes());
        
        // Second 16 bytes: use stream 1
        let ctr1 = [counter_lo, counter_hi, 1, 0];
        let out1 = philox4x32(ctr1, self.seed);
        private_key[16..20].copy_from_slice(&out1[0].to_le_bytes());
        private_key[20..24].copy_from_slice(&out1[1].to_le_bytes());
        private_key[24..28].copy_from_slice(&out1[2].to_le_bytes());
        private_key[28..32].copy_from_slice(&out1[3].to_le_bytes());
        
        // Validate key
        if !is_valid_private_key(&private_key) {
            return None;
        }
        
        // Compute public key hash and p2sh hash
        let (pubkey_hash, p2sh_hash) = match compute_pubkey_hash(&private_key) {
            Some(h) => h,
            None => return None,
        };
        
        Some(RawKeyData {
            private_key,
            pubkey_hash,
            p2sh_hash,
        })
    }
    
    /// Get current counter value
    pub fn current_count(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }
    
    /// Get effective keys generated (counter * 2 if GLV enabled)
    pub fn effective_keys_generated(&self) -> u64 {
        let base = self.counter.load(Ordering::Relaxed);
        if self.glv_enabled { base * 2 } else { base }
    }
}

/// Compute GLV transformed key: λ·k mod n
/// 
/// Uses secp256k1's endomorphism property where:
/// φ(P) = λ·P, with φ(x,y) = (β·x, y)
/// 
/// This allows scanning two key ranges with one EC operation.
#[inline]
fn compute_glv_key(private_key: &[u8; 32]) -> Option<[u8; 32]> {
    // Convert to Scalar
    let k = Scalar::from_repr_vartime((*private_key).into())?;
    
    // Compute λ·k mod n
    let glv_k = k * *GLV_LAMBDA_SCALAR;
    
    // Convert back to bytes
    let glv_bytes = glv_k.to_repr();
    let mut result = [0u8; 32];
    result.copy_from_slice(&glv_bytes);
    
    Some(result)
}

impl Default for PhiloxKeyGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Philox 4x32 random number generator - single round
#[inline(always)]
fn philox4x32(counter: [u32; 4], key: [u32; 2]) -> [u32; 4] {
    let mut ctr = counter;
    let mut k = key;
    
    // 10 rounds
    for _ in 0..10 {
        let (hi0, lo0) = mulhilo(PHILOX_M0, ctr[0]);
        let (hi1, lo1) = mulhilo(PHILOX_M1, ctr[2]);
        
        ctr = [
            hi1 ^ ctr[1] ^ k[0],
            lo1,
            hi0 ^ ctr[3] ^ k[1],
            lo0,
        ];
        
        k[0] = k[0].wrapping_add(PHILOX_W0);
        k[1] = k[1].wrapping_add(PHILOX_W1);
    }
    
    ctr
}

/// Multiply and return high/low 32-bit results
#[inline(always)]
fn mulhilo(a: u32, b: u32) -> (u32, u32) {
    let product = (a as u64) * (b as u64);
    ((product >> 32) as u32, product as u32)
}

/// Check if private key is valid (non-zero and less than curve order)
#[inline(always)]
fn is_valid_private_key(key: &[u8; 32]) -> bool {
    // Safe zero check: compiler auto-vectorizes to efficient SIMD
    // This is faster than manual unaligned reads on ARM64 (M1/M2)
    // and avoids potential UB from unaligned pointer casts
    let is_zero = !key.iter().any(|&b| b != 0);
    
    if is_zero {
        return false;
    }
    
    // Check less than curve order (big-endian comparison)
    for i in 0..32 {
        if key[i] < SECP256K1_ORDER[i] {
            return true;
        }
        if key[i] > SECP256K1_ORDER[i] {
            return false;
        }
    }
    false
}

/// Compute HASH160 of compressed public key and P2SH-P2WPKH script hash
#[inline]
fn compute_pubkey_hash(private_key: &[u8; 32]) -> Option<([u8; 20], [u8; 20])> {
    let secret_key = SecretKey::from_bytes(private_key.into()).ok()?;
    let public_key = secret_key.public_key();
    let encoded = public_key.to_encoded_point(true); // compressed
    let pubkey_bytes = encoded.as_bytes();
    
    // HASH160 = RIPEMD160(SHA256(pubkey))
    let sha = Sha256::digest(pubkey_bytes);
    let ripemd = Ripemd160::digest(sha);
    
    let mut pubkey_hash = [0u8; 20];
    pubkey_hash.copy_from_slice(&ripemd);
    
    // P2SH-P2WPKH: HASH160(0x0014 || pubkey_hash)
    // Witness program: OP_0 (0x00) + OP_PUSHBYTES_20 (0x14) + pubkey_hash
    let mut witness_program = [0u8; 22];
    witness_program[0] = 0x00;
    witness_program[1] = 0x14;
    witness_program[2..22].copy_from_slice(&pubkey_hash);
    
    let sha = Sha256::digest(&witness_program);
    let ripemd = Ripemd160::digest(sha);
    
    let mut p2sh_hash = [0u8; 20];
    p2sh_hash.copy_from_slice(&ripemd);
    
    Some((pubkey_hash, p2sh_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // ========================================================================
    // CpuKeyGenerator (Sequential, GPU-compatible) Tests
    // ========================================================================
    
    #[test]
    fn test_cpu_sequential_generation() {
        let gen = CpuKeyGenerator::new(1, None, 1);
        let batch = gen.generate_batch(100);
        
        assert!(!batch.is_empty());
        assert!(batch.len() <= 100);
        
        // All keys should be unique
        let mut seen = std::collections::HashSet::new();
        for key in &batch {
            assert!(seen.insert(key.private_key), "Duplicate key found");
        }
    }
    
    #[test]
    fn test_cpu_sequential_is_sequential() {
        let gen = CpuKeyGenerator::new(1, None, 1);
        let batch = gen.generate_batch(10);
        
        // Keys should be sequential: 1, 2, 3, ...
        for (i, key) in batch.iter().enumerate() {
            let expected_offset = (i + 1) as u64;
            let mut expected_key = [0u8; 32];
            expected_key[24..32].copy_from_slice(&expected_offset.to_be_bytes());
            
            assert_eq!(key.private_key, expected_key, 
                "Key {} should be offset {}", i, expected_offset);
        }
    }
    
    #[test]
    fn test_cpu_sequential_glv2() {
        let gen = CpuKeyGenerator::new(1, None, 2);
        let batch = gen.generate_batch(50);
        
        // With GLV2, we should get ~2x keys
        assert!(batch.len() >= 90, "GLV2 should produce ~100 keys from 50 offsets, got {}", batch.len());
        
        // All keys should be unique
        let mut seen = std::collections::HashSet::new();
        for key in &batch {
            assert!(seen.insert(key.private_key), "Duplicate key found");
        }
    }
    
    #[test]
    fn test_cpu_sequential_glv3() {
        let gen = CpuKeyGenerator::new(1, None, 3);
        let batch = gen.generate_batch(50);
        
        // With GLV3, we should get ~3x keys
        assert!(batch.len() >= 140, "GLV3 should produce ~150 keys from 50 offsets, got {}", batch.len());
        
        // All keys should be unique
        let mut seen = std::collections::HashSet::new();
        for key in &batch {
            assert!(seen.insert(key.private_key), "Duplicate key found");
        }
    }
    
    #[test]
    fn test_cpu_sequential_range_limit() {
        let gen = CpuKeyGenerator::new(1, Some(10), 1);
        
        // First batch should work
        let batch1 = gen.generate_batch(5);
        assert_eq!(batch1.len(), 5);
        assert!(!gen.is_range_complete());
        
        // Second batch should hit limit
        let batch2 = gen.generate_batch(10);
        assert!(batch2.len() <= 5, "Should stop at end_offset");
        
        // Now range should be complete
        assert!(gen.is_range_complete());
    }
    
    // ========================================================================
    // PhiloxKeyGenerator (Legacy Random) Tests
    // ========================================================================
    
    #[test]
    #[allow(deprecated)]
    fn test_philox_key_generation() {
        let gen = PhiloxKeyGenerator::with_seed(12345);
        let batch = gen.generate_batch(100);
        assert!(!batch.is_empty());
        
        // All keys should be unique
        let mut seen = std::collections::HashSet::new();
        for key in &batch {
            assert!(seen.insert(key.private_key));
        }
    }
    
    // ========================================================================
    // Common Tests
    // ========================================================================
    
    #[test]
    fn test_valid_key_check() {
        assert!(!is_valid_private_key(&[0u8; 32]));
        assert!(is_valid_private_key(&[0x01; 32]));
        assert!(!is_valid_private_key(&SECP256K1_ORDER));
    }
    
    #[test]
    fn test_pubkey_hash() {
        let key = [0x01u8; 32];
        let hashes = compute_pubkey_hash(&key);
        assert!(hashes.is_some());
        let (pubkey_hash, p2sh_hash) = hashes.unwrap();
        assert_eq!(pubkey_hash.len(), 20);
        assert_eq!(p2sh_hash.len(), 20);
        // Verify hashes are different
        assert_ne!(pubkey_hash, p2sh_hash);
    }
    
    #[test]
    #[allow(deprecated)]
    fn test_glv_key_generation() {
        let gen = PhiloxKeyGenerator::with_seed(12345);
        assert!(gen.is_glv_enabled());
        
        // With GLV, we should get ~2x keys
        let batch = gen.generate_batch(50);
        // Most base keys should produce 2 keys (base + GLV)
        // Some might be invalid, so we check for > 50
        assert!(batch.len() > 50, "GLV should produce more than 50 keys from 50 counters, got {}", batch.len());
        
        // All keys should still be unique
        let mut seen = std::collections::HashSet::new();
        for key in &batch {
            assert!(seen.insert(key.private_key), "Duplicate key found");
        }
    }
    
    #[test]
    #[allow(deprecated)]
    fn test_glv_disabled() {
        let gen = PhiloxKeyGenerator::without_glv(12345);
        assert!(!gen.is_glv_enabled());
        
        let batch = gen.generate_batch(100);
        // Without GLV, should get <= 100 keys
        assert!(batch.len() <= 100);
    }
    
    #[test]
    fn test_glv_lambda_produces_valid_keys() {
        // Test that GLV transform produces valid keys
        let base_key: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        
        let glv_key = compute_glv_key(&base_key).expect("GLV should work for key=1");
        
        // GLV key should be different from base
        assert_ne!(base_key, glv_key);
        
        // GLV key should be valid
        assert!(is_valid_private_key(&glv_key));
        
        // GLV key should equal GLV_LAMBDA (since 1 * λ = λ)
        assert_eq!(glv_key, GLV_LAMBDA, "1 * λ should equal λ");
    }
    
    #[test]
    fn test_glv2_lambda_squared() {
        // Test GLV² transform: λ²·k mod n
        let base_key: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        
        let glv2_key = compute_glv2_key(&base_key).expect("GLV2 should work for key=1");
        let glv_key = compute_glv_key(&base_key).expect("GLV should work for key=1");
        
        // GLV² key should be different from both base and GLV
        assert_ne!(base_key, glv2_key);
        assert_ne!(glv_key, glv2_key);
        
        // GLV² key should be valid
        assert!(is_valid_private_key(&glv2_key));
        
        // Verify λ³ = 1: λ²·λ = λ³ ≡ 1 (mod n)
        // So glv2 * lambda should equal base_key (for k=1)
        let glv3_key = compute_glv_key(&glv2_key).expect("GLV of GLV2 should work");
        assert_eq!(glv3_key, base_key, "λ³ should equal 1 (identity)");
    }
}


//! High-performance private key generation (GPU-compatible)
//! 
//! ## Sequential Mode (GPU-compatible)
//! 
//! Generates keys as `base_privkey + offset`, matching GPU behavior exactly.
//! This ensures CPU and GPU scan the SAME key space.
//!
//! ## GLV Endomorphism Support
//! 
//! Supports GLV endomorphism for 2x/3x throughput:
//! - k (base key)
//! - λ·k mod n (GLV transformed key)
//! - λ²·k mod n (GLV² transformed key)

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
    
    /// Convenience constructor with start_offset
    /// 
    /// Quick way to create a generator starting from a specific offset.
    /// 
    /// Uses GLV3 mode (3x throughput) by default to match GPU behavior.
    /// Use `new()` with explicit glv_multiplier if you need different mode.
    pub fn with_seed(start_offset: u64) -> Self {
        Self::new(start_offset.max(1), None, 3)  // GLV3 mode (matches GPU default)
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
    /// CRITICAL: Matches GPU's scalar_add_u64 behavior EXACTLY
    /// 
    /// GPU uses 64-bit word arithmetic (not byte-by-byte):
    /// - load_be() converts big-endian bytes to ulong4 (4×64-bit words)
    /// - s.x = bytes 24-31 (LSW - Least Significant Word)
    /// - s.y = bytes 16-23
    /// - s.z = bytes 8-15
    /// - s.w = bytes 0-7 (MSW - Most Significant Word)
    /// - scalar_add_u64 adds offset to s.x, then propagates carry through s.y, s.z, s.w
    /// 
    /// This function simulates the exact same 64-bit word arithmetic to ensure
    /// CPU and GPU produce identical results, even for very large offsets (>2^32).
    fn add_offset_to_base(&self, offset: u64) -> Option<[u8; 32]> {
        // Convert big-endian bytes to 64-bit words (matching GPU's load_be)
        // GPU layout: w=MSW (bytes 0-7), z (bytes 8-15), y (bytes 16-23), x=LSW (bytes 24-31)
        let mut words = [
            u64::from_be_bytes([
                self.base_privkey[0], self.base_privkey[1], self.base_privkey[2], self.base_privkey[3],
                self.base_privkey[4], self.base_privkey[5], self.base_privkey[6], self.base_privkey[7],
            ]), // w (MSW)
            u64::from_be_bytes([
                self.base_privkey[8], self.base_privkey[9], self.base_privkey[10], self.base_privkey[11],
                self.base_privkey[12], self.base_privkey[13], self.base_privkey[14], self.base_privkey[15],
            ]), // z
            u64::from_be_bytes([
                self.base_privkey[16], self.base_privkey[17], self.base_privkey[18], self.base_privkey[19],
                self.base_privkey[20], self.base_privkey[21], self.base_privkey[22], self.base_privkey[23],
            ]), // y
            u64::from_be_bytes([
                self.base_privkey[24], self.base_privkey[25], self.base_privkey[26], self.base_privkey[27],
                self.base_privkey[28], self.base_privkey[29], self.base_privkey[30], self.base_privkey[31],
            ]), // x (LSW)
        ];
        
        // GPU's scalar_add_u64 logic: add offset to x (LSW), propagate carry
        let old_x = words[3];
        words[3] += offset;
        let mut overflow = false;
        
        // Carry propagation (matching GPU exactly)
        if words[3] < old_x {
            let old_y = words[2];
            words[2] += 1;
            if words[2] < old_y {
                let old_z = words[1];
                words[1] += 1;
                if words[1] < old_z {
                    let old_w = words[0];
                    words[0] += 1;
                    if words[0] < old_w {
                        overflow = true; // Overflow beyond 256 bits
                    }
                }
            }
        }
        
        // GPU's mod n reduction: subtract n if result >= n or overflow occurred
        // SECP256K1_N = curve order n (256-bit)
        // GPU layout (after load_be): w=MSW, z, y, x=LSW
        // Big-endian bytes: [0-7]=w, [8-15]=z, [16-23]=y, [24-31]=x
        const SECP256K1_N: [u64; 4] = [
            0xFFFFFFFFFFFFFFFF, // w (MSW, bytes 0-7)
            0xFFFFFFFFFFFFFFFE, // z (bytes 8-15)
            0xBAAEDCE6AF48A03B, // y (bytes 16-23)
            0xBFD25E8CD0364141, // x (LSW, bytes 24-31)
        ];
        
        // Iterative reduction (matching GPU's loop, max 4 iterations)
        for _iter in 0..4 {
            // Check if reduction needed: overflow OR words >= SECP256K1_N
            let needs_reduction = overflow ||
                words[0] > SECP256K1_N[0] ||
                (words[0] == SECP256K1_N[0] && words[1] > SECP256K1_N[1]) ||
                (words[0] == SECP256K1_N[0] && words[1] == SECP256K1_N[1] && words[2] > SECP256K1_N[2]) ||
                (words[0] == SECP256K1_N[0] && words[1] == SECP256K1_N[1] && words[2] == SECP256K1_N[2] && words[3] >= SECP256K1_N[3]);
            
            if !needs_reduction {
                break;
            }
            
            // Subtract n with borrow chain (matching GPU exactly)
            // GPU order: x (LSW), y, z, w (MSW) - same as our words[3], words[2], words[1], words[0]
            let mut borrow = 0u64;
            let mut new_words = [0u64; 4];
            
            // x = s.x - SECP256K1_N.x; bw = (s.x < SECP256K1_N.x) ? 1 : 0;
            new_words[3] = words[3].wrapping_sub(SECP256K1_N[3]);
            borrow = if words[3] < SECP256K1_N[3] { 1 } else { 0 };
            
            // y = s.y - SECP256K1_N.y - bw; bw = (s.y < SECP256K1_N.y + bw) ? 1 : 0;
            let y_sub = SECP256K1_N[2].wrapping_add(borrow);
            new_words[2] = words[2].wrapping_sub(y_sub);
            borrow = if words[2] < y_sub { 1 } else { 0 };
            
            // z = s.z - SECP256K1_N.z - bw; bw = (s.z < SECP256K1_N.z + bw) ? 1 : 0;
            let z_sub = SECP256K1_N[1].wrapping_add(borrow);
            new_words[1] = words[1].wrapping_sub(z_sub);
            borrow = if words[1] < z_sub { 1 } else { 0 };
            
            // w = s.w - SECP256K1_N.w - bw;
            new_words[0] = words[0].wrapping_sub(SECP256K1_N[0]).wrapping_sub(borrow);
            
            words = new_words;
            
            // Clear overflow when result < n (matching GPU logic)
            // GPU checks: s.w < N.w || (s.w == N.w && s.z < N.z) || ...
            if overflow {
                let s_lt_n = words[0] < SECP256K1_N[0] ||
                    (words[0] == SECP256K1_N[0] && words[1] < SECP256K1_N[1]) ||
                    (words[0] == SECP256K1_N[0] && words[1] == SECP256K1_N[1] && words[2] < SECP256K1_N[2]) ||
                    (words[0] == SECP256K1_N[0] && words[1] == SECP256K1_N[1] && words[2] == SECP256K1_N[2] && words[3] < SECP256K1_N[3]);
                if s_lt_n {
                    overflow = false; // s < n guarantees s < 2^256, overflow resolved
                }
            }
        }
        
        // Convert back to big-endian bytes (matching GPU's store_be)
        let mut result = [0u8; 32];
        result[0..8].copy_from_slice(&words[0].to_be_bytes());  // w (MSW)
        result[8..16].copy_from_slice(&words[1].to_be_bytes()); // z
        result[16..24].copy_from_slice(&words[2].to_be_bytes()); // y
        result[24..32].copy_from_slice(&words[3].to_be_bytes()); // x (LSW)
        
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
    // CPU-GPU Compatibility Tests
    // ========================================================================
    
    #[test]
    fn test_cpu_gpu_sequential_compatibility() {
        // Verifies that CPU generates keys in the same order as GPU would
        // GPU generates: base + 0, base + 1, base + 2, ...
        let start_offset = 1u64;
        let gen = CpuKeyGenerator::new(start_offset, None, 1);
        
        let batch = gen.generate_batch(5);
        
        // Each key should be exactly start_offset + i
        for (i, key) in batch.iter().enumerate() {
            let expected_privkey = (start_offset + i as u64).to_be_bytes();
            
            // Private key should have the offset in the low 8 bytes
            assert_eq!(&key.private_key[24..32], &expected_privkey,
                "CPU key {} should match GPU sequential pattern", i);
        }
    }
    
    #[test]
    fn test_cpu_glv_matches_gpu_glv() {
        // Verifies that GLV transformation matches GPU's implementation
        // GLV: k → λ·k mod n
        let gen = CpuKeyGenerator::new(1, None, 2);
        let batch = gen.generate_batch(1);
        
        // Should get 2 keys: base and GLV
        assert_eq!(batch.len(), 2, "GLV2 should produce 2 keys from 1 offset");
        
        // First key should be the base key (offset=1)
        let base_key = batch[0].private_key;
        let mut expected_base = [0u8; 32];
        expected_base[31] = 1;
        assert_eq!(base_key, expected_base, "Base key should be offset 1");
        
        // Second key should be λ·1 = λ (GLV_LAMBDA)
        let glv_key = batch[1].private_key;
        assert_eq!(glv_key, GLV_LAMBDA, "GLV(1) should equal λ");
    }
    
    #[test]
    fn test_cpu_deterministic_across_calls() {
        // Verifies that restarting from same offset produces same keys
        // This is critical for checkpointing/resuming scans
        let gen1 = CpuKeyGenerator::new(1000, None, 2);
        let batch1 = gen1.generate_batch(10);
        
        let gen2 = CpuKeyGenerator::new(1000, None, 2);
        let batch2 = gen2.generate_batch(10);
        
        assert_eq!(batch1.len(), batch2.len(), "Same config should produce same count");
        
        for (i, (k1, k2)) in batch1.iter().zip(batch2.iter()).enumerate() {
            assert_eq!(k1.private_key, k2.private_key,
                "Key {} should be identical across generators", i);
            assert_eq!(k1.pubkey_hash, k2.pubkey_hash,
                "Pubkey hash {} should be identical", i);
            assert_eq!(k1.p2sh_hash, k2.p2sh_hash,
                "P2SH hash {} should be identical", i);
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


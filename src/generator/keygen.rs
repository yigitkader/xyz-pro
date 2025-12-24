//! High-performance private key generation
//! 
//! Uses Philox RNG for deterministic, parallelizable random number generation.
//! Each thread gets its own counter space to avoid contention.

use std::sync::atomic::{AtomicU64, Ordering};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use rayon::prelude::*;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use super::RawKeyData;

/// Secp256k1 curve order - keys must be less than this
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Philox 4x32 constants
const PHILOX_M0: u32 = 0xD2511F53;
const PHILOX_M1: u32 = 0xCD9E8D57;
const PHILOX_W0: u32 = 0x9E3779B9;
const PHILOX_W1: u32 = 0xBB67AE85;

/// High-performance key generator
pub struct KeyGenerator {
    /// Global counter for unique key generation
    counter: AtomicU64,
    /// Seed for RNG
    seed: [u32; 2],
}

impl KeyGenerator {
    /// Create a new key generator with cryptographically strong random seed
    /// Uses OS-provided entropy via `rand::thread_rng()` (backed by getrandom)
    pub fn new() -> Self {
        use rand::Rng;
        
        // Use cryptographically secure random source from the OS
        // This is backed by /dev/urandom on Unix, BCryptGenRandom on Windows
        let mut rng = rand::thread_rng();
        let seed: u64 = rng.gen();
        
        Self {
            counter: AtomicU64::new(0),
            seed: [(seed & 0xFFFFFFFF) as u32, ((seed >> 32) & 0xFFFFFFFF) as u32],
        }
    }
    
    /// Create with specific seed for reproducibility
    pub fn with_seed(seed: u64) -> Self {
        Self {
            counter: AtomicU64::new(0),
            seed: [(seed & 0xFFFFFFFF) as u32, ((seed >> 32) & 0xFFFFFFFF) as u32],
        }
    }
    
    /// Generate a batch of raw key data in parallel
    #[inline]
    pub fn generate_batch(&self, count: usize) -> Vec<RawKeyData> {
        let start_counter = self.counter.fetch_add(count as u64, Ordering::Relaxed);
        
        (0..count)
            .into_par_iter()
            .filter_map(|i| {
                let counter = start_counter + i as u64;
                self.generate_single(counter)
            })
            .collect()
    }
    
    /// Generate a single key from counter value
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
}

impl Default for KeyGenerator {
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
    // SIMD-optimized zero check: read 4 u64s and OR together
    // 8x faster than byte-by-byte iteration
    let ptr = key.as_ptr() as *const u64;
    let is_zero = unsafe {
        let v0 = std::ptr::read_unaligned(ptr);
        let v1 = std::ptr::read_unaligned(ptr.add(1));
        let v2 = std::ptr::read_unaligned(ptr.add(2));
        let v3 = std::ptr::read_unaligned(ptr.add(3));
        (v0 | v1 | v2 | v3) == 0
    };
    
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
    
    #[test]
    fn test_key_generation() {
        let gen = KeyGenerator::with_seed(12345);
        let batch = gen.generate_batch(100);
        assert!(!batch.is_empty());
        
        // All keys should be unique
        let mut seen = std::collections::HashSet::new();
        for key in &batch {
            assert!(seen.insert(key.private_key));
        }
    }
    
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
}


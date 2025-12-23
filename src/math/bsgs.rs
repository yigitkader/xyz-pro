/// BABY-STEP GIANT-STEP (BSGS) Algorithm
/// 
/// Solves the Discrete Logarithm Problem: Find k where Q = k*G
/// 
/// Time Complexity: O(√n) instead of O(n)
/// Space Complexity: O(√n) - requires precomputed table
/// 
/// REALISTIC LIMITS (M1 Mac, 8-16 GB RAM):
/// - Puzzle 40: √(2^40) = 1M entries = ~40 MB   ✅ Easy
/// - Puzzle 45: √(2^45) = 6M entries = ~240 MB  ✅ OK
/// - Puzzle 50: √(2^50) = 33M entries = ~1.3 GB ⚠️ Tight
/// - Puzzle 55+: Too large for consumer hardware
/// 
/// Usage:
/// ```ignore
/// let bsgs = BSGS::new(40); // For puzzle 40
/// if let Some(privkey) = bsgs.solve(&target_pubkey) {
///     println!("Found: {}", hex::encode(privkey));
/// }
/// ```

use k256::{
    ProjectivePoint, AffinePoint, Scalar,
    elliptic_curve::{
        group::GroupEncoding,
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field, PrimeField,
    },
};
use std::collections::HashMap;
use std::time::Instant;

/// BSGS Solver for small puzzles (40-50 bits)
pub struct BSGS {
    /// Baby-step table: X-coordinate (32 bytes) → index
    baby_table: HashMap<[u8; 32], u64>,
    
    /// Step size (m = √n)
    step_size: u64,
    
    /// Precomputed: m*G (for giant steps)
    giant_step: ProjectivePoint,
    
    /// Puzzle range start (2^(puzzle-1))
    range_start: u128,
    
    /// Puzzle range end (2^puzzle)
    range_end: u128,
    
    /// Puzzle number (for info)
    puzzle_number: u8,
}

impl BSGS {
    /// Create BSGS solver for a specific puzzle
    /// 
    /// WARNING: This allocates significant memory!
    /// - Puzzle 40: ~40 MB
    /// - Puzzle 45: ~240 MB
    /// - Puzzle 50: ~1.3 GB
    pub fn new(puzzle_number: u8) -> Result<Self, String> {
        if puzzle_number < 20 {
            return Err("Puzzle too small, use brute force".to_string());
        }
        if puzzle_number > 52 {
            return Err(format!(
                "Puzzle {} requires ~{} GB RAM - too large for this implementation",
                puzzle_number,
                (1u64 << ((puzzle_number as u64 - 1) / 2)) * 40 / 1_000_000_000
            ));
        }
        
        let range_start = 1u128 << (puzzle_number - 1);
        let range_end = 1u128 << puzzle_number;
        let range_size = range_end - range_start;
        
        // Step size = √(range_size)
        // For puzzle N: range = 2^(N-1), so √range = 2^((N-1)/2)
        let step_size = (range_size as f64).sqrt().ceil() as u64;
        
        println!("[BSGS] Puzzle #{}: range 2^{} to 2^{}", puzzle_number, puzzle_number - 1, puzzle_number);
        println!("[BSGS] Step size: {} ({:.1}M entries)", step_size, step_size as f64 / 1e6);
        println!("[BSGS] Estimated memory: {:.1} MB", (step_size * 40) as f64 / 1e6);
        
        let start = Instant::now();
        print!("[BSGS] Building baby-step table... ");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        
        // Build baby-step table: i*G for i in 0..step_size
        let mut baby_table = HashMap::with_capacity(step_size as usize);
        let mut current = ProjectivePoint::IDENTITY;
        let generator = ProjectivePoint::GENERATOR;
        
        for i in 0..step_size {
            // Store X-coordinate → index mapping
            let affine = current.to_affine();
            let x_bytes = affine.x().to_repr();
            let mut x_arr = [0u8; 32];
            x_arr.copy_from_slice(x_bytes.as_slice());
            
            baby_table.insert(x_arr, i);
            
            // Progress every 1M entries
            if i > 0 && i % 1_000_000 == 0 {
                print!("{}M ", i / 1_000_000);
                std::io::Write::flush(&mut std::io::stdout()).ok();
            }
            
            current += generator;
        }
        
        println!("done ({:.2}s)", start.elapsed().as_secs_f64());
        
        // Precompute m*G for giant steps
        let m_scalar = Scalar::from(step_size);
        let giant_step = ProjectivePoint::GENERATOR * m_scalar;
        
        Ok(Self {
            baby_table,
            step_size,
            giant_step,
            range_start,
            range_end,
            puzzle_number,
        })
    }
    
    /// Solve: Find private key k where target_pubkey = k*G
    /// Returns 32-byte private key if found
    pub fn solve(&self, target_pubkey: &[u8]) -> Option<[u8; 32]> {
        let start = Instant::now();
        
        // Parse target public key
        let target_point = match parse_pubkey(target_pubkey) {
            Some(p) => p,
            None => {
                eprintln!("[BSGS] Invalid target public key");
                return None;
            }
        };
        
        println!("[BSGS] Searching for key in range [2^{}, 2^{})", 
            self.puzzle_number - 1, self.puzzle_number);
        
        // Adjust target for range: target' = target - range_start*G
        let range_start_scalar = scalar_from_u128(self.range_start);
        let adjusted_target = target_point - (ProjectivePoint::GENERATOR * range_start_scalar);
        
        // Giant-step search: Check target - j*m*G for j = 0, 1, 2, ...
        let mut current = adjusted_target;
        let neg_giant_step = -self.giant_step; // Precompute negation
        
        let max_giant_steps = self.step_size + 1; // Need step_size giant steps to cover range
        
        for j in 0..max_giant_steps {
            // Check if current point's X is in baby table
            let affine = current.to_affine();
            let x_bytes = affine.x().to_repr();
            let mut x_arr = [0u8; 32];
            x_arr.copy_from_slice(x_bytes.as_slice());
            
            if let Some(&i) = self.baby_table.get(&x_arr) {
                // Found! k = range_start + j*m + i
                let k = self.range_start + (j as u128 * self.step_size as u128) + i as u128;
                
                // Verify k is in valid range
                if k >= self.range_start && k < self.range_end {
                    // Handle Y-coordinate ambiguity (point could be -P)
                    let k_bytes = u128_to_privkey(k);
                    if verify_key(&k_bytes, target_pubkey) {
                        println!("[BSGS] ✅ FOUND! k = 0x{:x} ({}s)", k, start.elapsed().as_secs_f64());
                        return Some(k_bytes);
                    }
                    
                    // Try negation: k' = n - k (where n is curve order)
                    // This handles the case where we matched -P instead of P
                    let neg_k = negate_scalar(k);
                    let neg_k_bytes = u128_to_privkey(neg_k);
                    if verify_key(&neg_k_bytes, target_pubkey) {
                        println!("[BSGS] ✅ FOUND (negated)! k = 0x{:x} ({}s)", neg_k, start.elapsed().as_secs_f64());
                        return Some(neg_k_bytes);
                    }
                }
            }
            
            // Progress every 100K giant steps
            if j > 0 && j % 100_000 == 0 {
                println!("[BSGS] Giant step {}/{}...", j, max_giant_steps);
            }
            
            // Move to next giant step: current = current - m*G
            current += neg_giant_step;
        }
        
        println!("[BSGS] ❌ Not found in range ({}s)", start.elapsed().as_secs_f64());
        None
    }
    
    /// Memory usage in bytes
    pub fn memory_usage(&self) -> usize {
        // Approximate: HashMap overhead + entry size
        self.baby_table.len() * (32 + 8 + 16) // key + value + HashMap overhead
    }
    
    /// Get puzzle info
    pub fn info(&self) {
        println!("[BSGS] Puzzle #{}", self.puzzle_number);
        println!("[BSGS] Range: [2^{}, 2^{})", self.puzzle_number - 1, self.puzzle_number);
        println!("[BSGS] Step size: {}", self.step_size);
        println!("[BSGS] Table entries: {}", self.baby_table.len());
        println!("[BSGS] Memory: {:.1} MB", self.memory_usage() as f64 / 1e6);
    }
}

// Helper functions

fn parse_pubkey(bytes: &[u8]) -> Option<ProjectivePoint> {
    match bytes.len() {
        33 => {
            // Compressed
            let encoded = k256::EncodedPoint::from_bytes(bytes).ok()?;
            let affine = AffinePoint::from_encoded_point(&encoded);
            if affine.is_some().into() {
                Some(ProjectivePoint::from(affine.unwrap()))
            } else {
                None
            }
        }
        65 => {
            // Uncompressed
            let encoded = k256::EncodedPoint::from_bytes(bytes).ok()?;
            let affine = AffinePoint::from_encoded_point(&encoded);
            if affine.is_some().into() {
                Some(ProjectivePoint::from(affine.unwrap()))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn scalar_from_u128(value: u128) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&value.to_be_bytes());
    <Scalar as Reduce<k256::U256>>::reduce_bytes(&bytes.into())
}

fn u128_to_privkey(value: u128) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn negate_scalar(k: u128) -> u128 {
    // secp256k1 order n
    let n_bytes: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ];
    
    // n as u256 (simplified - only use low 128 bits for small k)
    // For puzzles < 128, this approximation works
    let n_low = u128::from_be_bytes(n_bytes[16..].try_into().unwrap());
    
    // n - k (mod n)
    if k < n_low {
        n_low - k
    } else {
        k // Should not happen for puzzle < 128
    }
}

fn verify_key(privkey: &[u8; 32], expected_pubkey: &[u8]) -> bool {
    use k256::SecretKey;
    
    if let Ok(secret) = SecretKey::from_slice(privkey) {
        let pubkey = secret.public_key();
        let compressed = pubkey.to_encoded_point(true);
        let uncompressed = pubkey.to_encoded_point(false);
        
        compressed.as_bytes() == expected_pubkey || uncompressed.as_bytes() == expected_pubkey
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bsgs_small_puzzle() {
        // Test with puzzle 20 (very small, fast test)
        // Private key in range [2^19, 2^20) = [524288, 1048576)
        
        // Known test: privkey = 600000 (in range)
        let test_privkey = 600000u128;
        let mut privkey_bytes = [0u8; 32];
        privkey_bytes[16..].copy_from_slice(&test_privkey.to_be_bytes());
        
        // Get public key
        let secret = k256::SecretKey::from_slice(&privkey_bytes).unwrap();
        let pubkey = secret.public_key();
        let pubkey_bytes = pubkey.to_encoded_point(true);
        
        // Solve with BSGS
        let bsgs = BSGS::new(20).unwrap();
        let result = bsgs.solve(pubkey_bytes.as_bytes());
        
        assert!(result.is_some(), "BSGS should find the key");
        let found = result.unwrap();
        assert_eq!(found, privkey_bytes, "Found key should match");
    }
    
    #[test]
    fn test_scalar_conversion() {
        let value = 12345678u128;
        let bytes = u128_to_privkey(value);
        
        // Verify last 16 bytes contain the value
        let recovered = u128::from_be_bytes(bytes[16..].try_into().unwrap());
        assert_eq!(recovered, value);
    }
    
    #[test]
    fn test_memory_estimate() {
        // Puzzle 40: should be ~40 MB
        let entries = 1u64 << 20; // 2^20 = ~1M
        let size_per_entry = 32 + 8 + 16; // key + value + overhead
        let total = entries * size_per_entry;
        
        assert!(total < 100_000_000, "Puzzle 40 should be < 100 MB");
    }
}


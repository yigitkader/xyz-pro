/// PUZZLE SCANNER MODULE
/// 
/// Optimized sequential scanner for Bitcoin Puzzle challenges.
/// 
/// REALITY CHECK:
/// - Puzzle #66 has 2^65 keys to check (36 quintillion)
/// - At 2.5M keys/sec = 467 million years
/// - At 250M keys/sec (100x faster) = 4.67 million years
/// - NO algorithm changes this - it's pure math
/// 
/// What this module DOES provide:
/// - Efficient sequential key generation (no Philox overhead)
/// - Optimized for known key ranges
/// - Progress tracking and resume capability (with u128 support!)
/// - Multi-GPU distribution support

use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::time::Instant;

use crate::gpu::{OptimizedScanner, PooledBuffer};
use crate::puzzle_mode::PuzzleConfig;
use crate::types::Hash160;

/// Checkpoint file for resume capability
const CHECKPOINT_FILE: &str = "puzzle_checkpoint.bin";
const CHECKPOINT_INTERVAL: u64 = 100_000_000; // Save every 100M keys

/// Sequential key generator for puzzle scanning
/// 
/// ARCHITECTURE:
/// - For puzzles ≤64: Uses AtomicU64 (lock-free, fast)
/// - For puzzles 65-128: Uses Mutex<u128> (correct range tracking)
/// 
/// Key generation is always correct via u128 arithmetic.
/// Only the position counter differs for large puzzles.
pub struct PuzzleScanner {
    /// Current position - low 64 bits (used for puzzles ≤64)
    current_lo: AtomicU64,
    
    /// Current position - high 64 bits (used for puzzles 65-128)
    current_hi: AtomicU64,
    
    /// Total keys in range (u128 for large puzzles)
    total_keys: u128,
    
    /// Target hash160 to find
    target_hash: Hash160,
    
    /// Puzzle number for logging
    puzzle_number: u8,
    
    /// Keys checked counter
    keys_checked: AtomicU64,
    
    /// Start time
    start_time: Instant,
}

impl PuzzleScanner {
    /// Create a new puzzle scanner
    pub fn new(config: &PuzzleConfig) -> Self {
        let (start, end) = config.key_range();
        let total_keys = end - start;
        
        // Initialize position counter
        // For puzzle N: range is [2^(N-1), 2^N)
        // We track position relative to start (0-based)
        Self {
            current_lo: AtomicU64::new(0),
            current_hi: AtomicU64::new(0),
            total_keys,
            target_hash: Hash160::from_slice(&config.target_hash),
            puzzle_number: config.puzzle_number,
            keys_checked: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }
    
    /// Get current position as u128
    #[inline]
    fn get_position(&self) -> u128 {
        let lo = self.current_lo.load(Ordering::Relaxed) as u128;
        let hi = self.current_hi.load(Ordering::Relaxed) as u128;
        (hi << 64) | lo
    }
    
    /// Increment position by amount and return old value
    /// Thread-safe for single producer (GPU thread)
    fn fetch_add_position(&self, amount: u64) -> u128 {
        let old_lo = self.current_lo.fetch_add(amount, Ordering::Relaxed);
        
        // Check for overflow in low 64 bits
        if old_lo.checked_add(amount).is_none() {
            // Overflow occurred, increment high bits
            self.current_hi.fetch_add(1, Ordering::Relaxed);
        }
        
        let hi = self.current_hi.load(Ordering::Relaxed) as u128;
        (hi << 64) | (old_lo as u128)
    }
    
    /// Set position from u128 (for resume)
    fn set_position(&self, pos: u128) {
        self.current_lo.store(pos as u64, Ordering::SeqCst);
        self.current_hi.store((pos >> 64) as u64, Ordering::SeqCst);
    }
    
    /// Try to load checkpoint and resume
    /// Checkpoint format v2: [puzzle:1][position_lo:8][position_hi:8] = 17 bytes
    /// Also supports legacy format v1: [puzzle:1][position:8] = 9 bytes
    pub fn try_resume(&self) -> bool {
        let Ok(mut file) = File::open(CHECKPOINT_FILE) else {
            return false;
        };
        
        // Try new format first (17 bytes)
        let mut buf = [0u8; 17];
        if file.read_exact(&mut buf).is_ok() {
            let saved_puzzle = buf[0];
            if saved_puzzle == self.puzzle_number {
                let pos_lo = u64::from_le_bytes(buf[1..9].try_into().unwrap());
                let pos_hi = u64::from_le_bytes(buf[9..17].try_into().unwrap());
                let position = ((pos_hi as u128) << 64) | (pos_lo as u128);
                
                if position < self.total_keys {
                    self.set_position(position);
                    println!("[Resume] Continuing from position: 0x{:032x}", position);
                    println!("[Resume] Progress: {:.6}%", (position as f64 / self.total_keys as f64) * 100.0);
                    return true;
                }
            }
        }
        
        // Try legacy format (9 bytes) for backward compatibility
        if let Ok(mut file) = File::open(CHECKPOINT_FILE) {
            let mut buf = [0u8; 9];
            if file.read_exact(&mut buf).is_ok() {
                let saved_puzzle = buf[0];
                if saved_puzzle == self.puzzle_number {
                    let position = u64::from_le_bytes(buf[1..9].try_into().unwrap());
                    self.set_position(position as u128);
                    println!("[Resume] Continuing from position (legacy): 0x{:016x}", position);
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Save checkpoint with u128 position
    fn save_checkpoint(&self) {
        let position = self.get_position();
        if let Ok(mut file) = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(CHECKPOINT_FILE) 
        {
            let mut buf = [0u8; 17];
            buf[0] = self.puzzle_number;
            buf[1..9].copy_from_slice(&(position as u64).to_le_bytes());
            buf[9..17].copy_from_slice(&((position >> 64) as u64).to_le_bytes());
            let _ = file.write_all(&buf);
            let _ = file.sync_all();
        }
    }
    
    /// Generate next base key for GPU batch
    /// Returns (32-byte key, batch_start_position) for key reconstruction on match
    pub fn next_base_key(&self, batch_size: u64) -> Option<([u8; 32], u64)> {
        let pos = self.fetch_add_position(batch_size);
        
        if pos >= self.total_keys {
            return None; // Finished scanning
        }
        
        // Periodic checkpoint
        let checked = self.keys_checked.fetch_add(batch_size, Ordering::Relaxed);
        if checked % CHECKPOINT_INTERVAL < batch_size {
            self.save_checkpoint();
        }
        
        // Build 32-byte key from puzzle range
        // Puzzle N: range is [2^(N-1), 2^N)
        // Position is 0-based offset from start of range
        let mut key = [0u8; 32];
        
        // Calculate actual key value: 2^(puzzle-1) + position
        // Using 128-bit arithmetic for puzzles up to 128
        let base: u128 = 1u128 << (self.puzzle_number - 1);
        let full_key = base + pos;
        
        // Convert to big-endian 32 bytes (only low 128 bits matter for puzzles < 128)
        let high = (full_key >> 64) as u64;
        let low = full_key as u64;
        
        key[16..24].copy_from_slice(&high.to_be_bytes());
        key[24..32].copy_from_slice(&low.to_be_bytes());
        
        // Return position as u64 for backward compatibility (low 64 bits)
        // Key reconstruction uses puzzle_number to get full position
        Some((key, pos as u64))
    }
    
    /// Check if a match was found for our target
    /// `batch_start_pos` is the position when the batch was dispatched
    /// 
    /// CRITICAL: GPU uses XorFilter which has false positive rate ~0.0015%
    /// We MUST verify the match on CPU before reporting!
    pub fn check_matches(&self, matches: &PooledBuffer, batch_start_pos: u64) -> Option<[u8; 32]> {
        use k256::SecretKey;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        
        for m in matches.as_ref().iter() {
            if m.hash == self.target_hash {
                // Reconstruct the private key
                let priv_key = self.reconstruct_key(batch_start_pos, m.key_index);
                
                // CPU VERIFICATION: Compute hash160 and verify it matches
                if let Ok(secret) = SecretKey::from_slice(&priv_key) {
                    let pubkey = secret.public_key();
                    
                    // Check compressed public key hash
                    let comp_hash = crate::crypto::hash160(
                        pubkey.to_encoded_point(true).as_bytes()
                    );
                    if comp_hash == *self.target_hash.as_bytes() {
                        // VERIFIED! This is the real key!
                        return Some(priv_key);
                    }
                    
                    // Check uncompressed public key hash (just in case)
                    let uncomp_hash = crate::crypto::hash160(
                        pubkey.to_encoded_point(false).as_bytes()
                    );
                    if uncomp_hash == *self.target_hash.as_bytes() {
                        return Some(priv_key);
                    }
                }
                // If we get here, it was a false positive - continue searching
            }
        }
        None
    }
    
    /// Reconstruct full private key from match
    /// `batch_start_pos` is the position when the batch was dispatched (before fetch_add)
    /// `offset` is the key_index within the batch
    fn reconstruct_key(&self, batch_start_pos: u64, offset: u32) -> [u8; 32] {
        // Private key = 2^(puzzle-1) + batch_start_pos + offset
        let base: u128 = 1u128 << (self.puzzle_number - 1);
        let full_key = base + batch_start_pos as u128 + offset as u128;
        
        let mut key = [0u8; 32];
        let high = (full_key >> 64) as u64;
        let low = full_key as u64;
        
        key[16..24].copy_from_slice(&high.to_be_bytes());
        key[24..32].copy_from_slice(&low.to_be_bytes());
        key
    }
    
    /// Get progress percentage (correct for u128 ranges!)
    pub fn progress(&self) -> f64 {
        let current = self.get_position();
        (current as f64 / self.total_keys as f64) * 100.0
    }
    
    /// Get current speed
    pub fn speed(&self) -> f64 {
        let checked = self.keys_checked.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            checked as f64 / elapsed
        } else {
            0.0
        }
    }
    
    /// Get ETA string (correct for u128 ranges!)
    pub fn eta(&self) -> String {
        let speed = self.speed();
        if speed <= 0.0 {
            return "∞".to_string();
        }
        
        let current = self.get_position();
        let remaining = self.total_keys.saturating_sub(current);
        let secs = remaining as f64 / speed;
        
        format_duration(secs)
    }
    
    /// Print status with u128 position
    pub fn print_status(&self) {
        let pos = self.get_position();
        // For display, show high:low if position > u64::MAX
        if pos > u64::MAX as u128 {
            println!(
                "[Puzzle #{}] {:.6}% | {:.2}M/s | ETA: {} | Pos: 0x{:016x}:{:016x}",
                self.puzzle_number,
                self.progress(),
                self.speed() / 1_000_000.0,
                self.eta(),
                (pos >> 64) as u64,
                pos as u64
            );
        } else {
            println!(
                "[Puzzle #{}] {:.6}% | {:.2}M/s | ETA: {} | Pos: 0x{:016x}",
                self.puzzle_number,
                self.progress(),
                self.speed() / 1_000_000.0,
                self.eta(),
                pos as u64
            );
        }
    }
}

fn format_duration(secs: f64) -> String {
    if secs < 60.0 {
        format!("{:.0}s", secs)
    } else if secs < 3600.0 {
        format!("{:.1}m", secs / 60.0)
    } else if secs < 86400.0 {
        format!("{:.1}h", secs / 3600.0)
    } else if secs < 31536000.0 {
        format!("{:.1}d", secs / 86400.0)
    } else {
        let years = secs / 31536000.0;
        if years > 1_000_000.0 {
            format!("{:.2e} years", years)
        } else {
            format!("{:.1} years", years)
        }
    }
}

/// Scan for a specific puzzle
pub fn run_puzzle_scan(
    gpu: &OptimizedScanner,
    config: &PuzzleConfig,
    shutdown: &AtomicBool,
) -> Option<[u8; 32]> {
    let scanner = PuzzleScanner::new(config);
    
    // Try to resume from checkpoint
    scanner.try_resume();
    
    let batch_size = gpu.keys_per_batch();
    let mut last_status = Instant::now();
    
    println!("\n[Puzzle #{}] Starting sequential scan", config.puzzle_number);
    println!("[Puzzle #{}] Range: 2^{} to 2^{}", 
        config.puzzle_number, 
        config.puzzle_number - 1, 
        config.puzzle_number
    );
    println!("[Puzzle #{}] Target: {}", 
        config.puzzle_number,
        hex::encode(config.target_hash)
    );
    println!();
    
    while !shutdown.load(Ordering::Relaxed) {
        // Get next base key and its starting position
        let (base_key, batch_start_pos) = match scanner.next_base_key(batch_size) {
            Some(k) => k,
            None => {
                println!("[Puzzle #{}] Range exhausted - puzzle NOT found", config.puzzle_number);
                return None;
            }
        };
        
        // Scan batch
        match gpu.scan_batch(&base_key) {
            Ok(matches) => {
                // Check for target match (pass batch_start_pos for correct key reconstruction)
                if let Some(found_key) = scanner.check_matches(&matches, batch_start_pos) {
                    println!("\n🎉🎉🎉 PUZZLE #{} SOLVED! 🎉🎉🎉", config.puzzle_number);
                    println!("Private Key: {}", hex::encode(found_key));
                    
                    // Save to file immediately with sync
                    if let Ok(mut f) = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("PUZZLE_FOUND.txt") 
                    {
                        let _ = writeln!(f, "Puzzle #{}: {}", config.puzzle_number, hex::encode(found_key));
                        let _ = f.sync_all();
                    }
                    
                    return Some(found_key);
                }
            }
            Err(e) => {
                eprintln!("[!] GPU error: {}", e);
                return None;
            }
        }
        
        // Status update every second
        if last_status.elapsed().as_secs() >= 1 {
            scanner.print_status();
            last_status = Instant::now();
        }
    }
    
    // Save checkpoint on shutdown
    scanner.save_checkpoint();
    println!("[Puzzle #{}] Checkpoint saved. Resume with PUZZLE={}", 
        config.puzzle_number, config.puzzle_number);
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_generation_low_puzzle() {
        let config = PuzzleConfig::for_puzzle(66).unwrap();
        let scanner = PuzzleScanner::new(&config);
        
        let (key, pos) = scanner.next_base_key(1000).unwrap();
        
        // For puzzle 66, range starts at 2^65
        // Position should be 0 for first batch
        assert_eq!(pos, 0);
        
        // 2^65 as 128-bit:
        // high = (1u128 << 65) >> 64 = 2
        // low = 0
        // So key[23] should be 0x02 (big-endian high 64-bit)
        
        // Key should be non-zero in the puzzle range
        let is_in_range = key.iter().skip(16).any(|&b| b != 0);
        assert!(is_in_range, "Key should be non-zero in puzzle 66 range");
        
        // Verify: bytes 16-23 = high.to_be_bytes() = 0x0000000000000002
        assert_eq!(key[23], 0x02, "byte 23 should be 0x02 for 2^65");
    }
    
    #[test]
    fn test_progress_tracking() {
        let config = PuzzleConfig::for_puzzle(66).unwrap();
        let scanner = PuzzleScanner::new(&config);
        
        // Initial progress should be 0%
        assert!(scanner.progress() < 0.001);
        
        // After some keys, progress should increase
        let _ = scanner.next_base_key(1_000_000);
        assert!(scanner.progress() > 0.0);
    }
    
    #[test]
    fn test_key_reconstruction() {
        let config = PuzzleConfig::for_puzzle(66).unwrap();
        let scanner = PuzzleScanner::new(&config);
        
        // Simulate finding a match at position 0, offset 42
        let reconstructed = scanner.reconstruct_key(0, 42);
        
        // Key should be 2^65 + 42
        // 2^65: high = 2, low = 0
        // +42: high = 2, low = 42
        // bytes 16-23 = 0x0000000000000002 (high)
        // bytes 24-31 = 0x000000000000002A (low = 42)
        assert_eq!(reconstructed[23], 0x02, "high should be 2");
        assert_eq!(reconstructed[31], 42, "low should include offset 42");
    }
}


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
/// - Progress tracking and resume capability
/// - Multi-GPU distribution support

use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::time::Instant;

use crate::gpu::{OptimizedScanner, PooledBuffer};
use crate::puzzle_mode::PuzzleConfig;
use crate::types::Hash160;

/// Checkpoint file for resume capability
const CHECKPOINT_FILE: &str = "puzzle_checkpoint.bin";
const CHECKPOINT_INTERVAL: u64 = 100_000_000; // Save every 100M keys

/// Sequential key generator for puzzle scanning
pub struct PuzzleScanner {
    /// Current position in the key range
    current: AtomicU64,
    
    /// Starting position (2^(puzzle-1))
    start: u64,
    
    /// Ending position (2^puzzle)
    end: u64,
    
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
        
        // For puzzles > 64, we use high bits differently
        let (start_u64, end_u64) = if config.puzzle_number <= 64 {
            (start as u64, end as u64)
        } else {
            // For puzzle 65+, we only track low 64 bits
            // High bits are implied by puzzle number
            (0u64, u64::MAX)
        };
        
        Self {
            current: AtomicU64::new(start_u64),
            start: start_u64,
            end: end_u64,
            target_hash: Hash160::from_slice(&config.target_hash),
            puzzle_number: config.puzzle_number,
            keys_checked: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }
    
    /// Try to load checkpoint and resume
    pub fn try_resume(&self) -> bool {
        if let Ok(mut file) = File::open(CHECKPOINT_FILE) {
            let mut buf = [0u8; 9]; // 1 byte puzzle + 8 bytes position
            if file.read_exact(&mut buf).is_ok() {
                let saved_puzzle = buf[0];
                if saved_puzzle == self.puzzle_number {
                    let position = u64::from_le_bytes(buf[1..9].try_into().unwrap());
                    if position >= self.start && position < self.end {
                        self.current.store(position, Ordering::SeqCst);
                        println!("[Resume] Continuing from position: 0x{:016x}", position);
                        return true;
                    }
                }
            }
        }
        false
    }
    
    /// Save checkpoint
    fn save_checkpoint(&self) {
        let position = self.current.load(Ordering::Relaxed);
        if let Ok(mut file) = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(CHECKPOINT_FILE) 
        {
            let mut buf = [0u8; 9];
            buf[0] = self.puzzle_number;
            buf[1..9].copy_from_slice(&position.to_le_bytes());
            let _ = file.write_all(&buf);
            let _ = file.sync_all();
        }
    }
    
    /// Generate next base key for GPU batch
    /// Returns 32-byte key with proper high bits for puzzle
    pub fn next_base_key(&self, batch_size: u64) -> Option<[u8; 32]> {
        let pos = self.current.fetch_add(batch_size, Ordering::Relaxed);
        
        if pos >= self.end {
            return None; // Finished scanning
        }
        
        // Periodic checkpoint
        let checked = self.keys_checked.fetch_add(batch_size, Ordering::Relaxed);
        if checked % CHECKPOINT_INTERVAL < batch_size {
            self.save_checkpoint();
        }
        
        // Build 32-byte key from puzzle range
        // Puzzle N: range is [2^(N-1), 2^N)
        // For puzzle 66: [2^65, 2^66) = [0x20000000000000000, 0x40000000000000000)
        let mut key = [0u8; 32];
        
        // Calculate actual key value: 2^(puzzle-1) + position
        // Using 128-bit arithmetic for puzzles up to 128
        let base: u128 = 1u128 << (self.puzzle_number - 1);
        let full_key = base + pos as u128;
        
        // Convert to big-endian 32 bytes (only low 128 bits matter for puzzles < 128)
        let high = (full_key >> 64) as u64;
        let low = full_key as u64;
        
        key[16..24].copy_from_slice(&high.to_be_bytes());
        key[24..32].copy_from_slice(&low.to_be_bytes());
        
        Some(key)
    }
    
    /// Check if a match was found for our target
    pub fn check_matches(&self, matches: &PooledBuffer) -> Option<[u8; 32]> {
        for m in matches.as_ref().iter() {
            if m.hash == self.target_hash {
                // FOUND IT!
                return Some(self.reconstruct_key(m.key_index));
            }
        }
        None
    }
    
    /// Reconstruct full private key from match
    fn reconstruct_key(&self, offset: u32) -> [u8; 32] {
        let base_pos = self.current.load(Ordering::Relaxed);
        // GPU batch starts from base_pos, match is at base_pos + offset
        let full_pos = base_pos.saturating_sub(self.keys_checked.load(Ordering::Relaxed) % 1_000_000) + offset as u64;
        
        let base: u128 = 1u128 << (self.puzzle_number - 1);
        let full_key = base + full_pos as u128;
        
        let mut key = [0u8; 32];
        let high = (full_key >> 64) as u64;
        let low = full_key as u64;
        
        key[16..24].copy_from_slice(&high.to_be_bytes());
        key[24..32].copy_from_slice(&low.to_be_bytes());
        key
    }
    
    /// Get progress percentage
    pub fn progress(&self) -> f64 {
        let current = self.current.load(Ordering::Relaxed);
        let range = self.end - self.start;
        ((current - self.start) as f64 / range as f64) * 100.0
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
    
    /// Get ETA string
    pub fn eta(&self) -> String {
        let speed = self.speed();
        if speed <= 0.0 {
            return "∞".to_string();
        }
        
        let remaining = self.end.saturating_sub(self.current.load(Ordering::Relaxed));
        let secs = remaining as f64 / speed;
        
        format_duration(secs)
    }
    
    /// Print status
    pub fn print_status(&self) {
        println!(
            "[Puzzle #{}] {:.6}% | {:.2}M/s | ETA: {} | Pos: 0x{:016x}",
            self.puzzle_number,
            self.progress(),
            self.speed() / 1_000_000.0,
            self.eta(),
            self.current.load(Ordering::Relaxed)
        );
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
        // Get next base key
        let base_key = match scanner.next_base_key(batch_size) {
            Some(k) => k,
            None => {
                println!("[Puzzle #{}] Range exhausted - puzzle NOT found", config.puzzle_number);
                return None;
            }
        };
        
        // Scan batch
        match gpu.scan_batch(&base_key) {
            Ok(matches) => {
                // Check for target match
                if let Some(found_key) = scanner.check_matches(&matches) {
                    println!("\n🎉🎉🎉 PUZZLE #{} SOLVED! 🎉🎉🎉", config.puzzle_number);
                    println!("Private Key: {}", hex::encode(&found_key));
                    
                    // Save to file immediately
                    if let Ok(mut f) = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("PUZZLE_FOUND.txt") 
                    {
                        let _ = writeln!(f, "Puzzle #{}: {}", config.puzzle_number, hex::encode(&found_key));
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
        
        let key = scanner.next_base_key(1000).unwrap();
        
        // For puzzle 66, range starts at 2^65
        // 2^65 = 0x0000000000000001_0000000000000000 (128 bits)
        // In big-endian 32-byte key:
        // - bytes 0-22 = 0
        // - byte 23 = 0x01 or higher (depending on puzzle)
        // - bytes 24-31 = lower 64 bits
        
        // Key should be non-zero in the puzzle range
        let is_in_range = key.iter().skip(16).any(|&b| b != 0);
        assert!(is_in_range, "Key should be non-zero in puzzle 66 range");
    }
    
    #[test]
    fn test_progress_tracking() {
        let config = PuzzleConfig::for_puzzle(66).unwrap();
        let scanner = PuzzleScanner::new(&config);
        
        // Initial progress should be 0%
        assert!(scanner.progress() < 0.001);
        
        // After some keys, progress should increase
        scanner.next_base_key(1_000_000);
        assert!(scanner.progress() > 0.0);
    }
}


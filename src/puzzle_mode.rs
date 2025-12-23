/// BITCOIN PUZZLE MODE
/// 
/// The Bitcoin Puzzle is a real challenge with known private key ranges.
/// Each puzzle has a known bit-range and a real BTC reward.
/// 
/// This is a REALISTIC target because:
/// 1. The key range is KNOWN (not 2^256, but e.g., 2^66)
/// 2. Sequential search is the correct approach
/// 3. Real rewards exist
/// 
/// Current unsolved puzzles (as of 2024):
/// - Puzzle #66: 2^65 to 2^66 (6.6 BTC reward, ~36 quintillion keys)
/// - Puzzle #67: 2^66 to 2^67 (6.7 BTC reward)
/// - ... up to Puzzle #160

use std::sync::atomic::{AtomicU64, Ordering};

/// Known Bitcoin Puzzle addresses (unsolved as of 2024)
pub const PUZZLE_TARGETS: &[(u8, &str, f64)] = &[
    // (puzzle_number, address, btc_reward)
    (66, "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so", 6.6),
    (67, "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9", 6.7),
    (68, "1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ", 6.8),
    (69, "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG", 6.9),
    (70, "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR", 7.0),
    // Add more puzzles as needed
];

/// Puzzle scanner configuration
#[derive(Clone)]
pub struct PuzzleConfig {
    /// Which puzzle to solve (66, 67, 68, etc.)
    pub puzzle_number: u8,
    
    /// Starting offset within the puzzle range (for distributed work)
    pub start_offset: u128,
    
    /// How many keys to scan (0 = entire range)
    pub key_count: u128,
    
    /// Target address hash160
    pub target_hash: [u8; 20],
}

/// Pre-computed hash160 values for puzzle addresses
const PUZZLE_HASHES: &[(u8, [u8; 20])] = &[
    // Puzzle 66: 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so
    (66, [0x20, 0xd4, 0x5a, 0x6a, 0x76, 0x25, 0x35, 0x70, 0x0c, 0xe9, 
          0xe0, 0xb2, 0x16, 0xe3, 0x19, 0x94, 0x33, 0x5d, 0xb8, 0xa5]),
    // Puzzle 67: 1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9
    (67, [0x73, 0x94, 0x37, 0xbb, 0x3d, 0xd6, 0xd1, 0x98, 0x3e, 0x66,
          0x62, 0x9c, 0x5f, 0x08, 0xc7, 0x0e, 0x52, 0x76, 0x93, 0x71]),
    // Puzzle 68: 1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ
    (68, [0xe0, 0xb8, 0xa2, 0xba, 0xee, 0x1b, 0x77, 0xfc, 0x70, 0x34,
          0x55, 0xf3, 0x9d, 0x51, 0x47, 0x7d, 0x25, 0x05, 0x4a, 0x36]),
];

impl PuzzleConfig {
    pub fn for_puzzle(puzzle_number: u8) -> Option<Self> {
        // Find the puzzle hash
        PUZZLE_HASHES.iter()
            .find(|(n, _)| *n == puzzle_number)
            .map(|(n, hash)| {
                Self {
                    puzzle_number: *n,
                    start_offset: 0,
                    key_count: 0, // Full range
                    target_hash: *hash,
                }
            })
    }
    
    /// Get the key range for this puzzle
    pub fn key_range(&self) -> (u128, u128) {
        let min = 1u128 << (self.puzzle_number - 1);
        let max = 1u128 << self.puzzle_number;
        
        let start = min + self.start_offset;
        let end = if self.key_count > 0 {
            (start + self.key_count).min(max)
        } else {
            max
        };
        
        (start, end)
    }
    
    /// Convert range start to 32-byte key
    pub fn start_key(&self) -> [u8; 32] {
        let (start, _) = self.key_range();
        let mut key = [0u8; 32];
        let bytes = start.to_be_bytes();
        key[16..32].copy_from_slice(&bytes);
        key
    }
    
    /// Total keys in this puzzle's range
    pub fn total_keys(&self) -> u128 {
        let (start, end) = self.key_range();
        end - start
    }
    
    /// Estimated time to complete at given speed
    pub fn estimated_time_secs(&self, keys_per_sec: f64) -> f64 {
        self.total_keys() as f64 / keys_per_sec
    }
    
    /// Estimated time as human-readable string
    pub fn estimated_time_human(&self, keys_per_sec: f64) -> String {
        let secs = self.estimated_time_secs(keys_per_sec);
        
        if secs < 60.0 {
            format!("{:.1} seconds", secs)
        } else if secs < 3600.0 {
            format!("{:.1} minutes", secs / 60.0)
        } else if secs < 86400.0 {
            format!("{:.1} hours", secs / 3600.0)
        } else if secs < 31536000.0 {
            format!("{:.1} days", secs / 86400.0)
        } else {
            format!("{:.2e} years", secs / 31536000.0)
        }
    }
}

/// Progress tracker for puzzle solving
pub struct PuzzleProgress {
    /// Keys checked so far
    checked: AtomicU64,
    
    /// Total keys to check
    total: u128,
    
    /// Start time
    start_time: std::time::Instant,
}

impl PuzzleProgress {
    pub fn new(total: u128) -> Self {
        Self {
            checked: AtomicU64::new(0),
            total,
            start_time: std::time::Instant::now(),
        }
    }
    
    pub fn add(&self, count: u64) {
        self.checked.fetch_add(count, Ordering::Relaxed);
    }
    
    pub fn checked(&self) -> u64 {
        self.checked.load(Ordering::Relaxed)
    }
    
    pub fn percentage(&self) -> f64 {
        (self.checked() as f64 / self.total as f64) * 100.0
    }
    
    pub fn keys_per_sec(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.checked() as f64 / elapsed
        } else {
            0.0
        }
    }
    
    pub fn eta_human(&self) -> String {
        let kps = self.keys_per_sec();
        if kps <= 0.0 {
            return "∞".to_string();
        }
        
        let remaining = self.total.saturating_sub(self.checked() as u128);
        let secs = remaining as f64 / kps;
        
        if secs < 60.0 {
            format!("{:.0}s", secs)
        } else if secs < 3600.0 {
            format!("{:.0}m", secs / 60.0)
        } else if secs < 86400.0 {
            format!("{:.1}h", secs / 3600.0)
        } else if secs < 31536000.0 {
            format!("{:.1}d", secs / 86400.0)
        } else {
            format!("{:.2e}y", secs / 31536000.0)
        }
    }
}

/// Print puzzle information
pub fn print_puzzle_info(puzzle_number: u8, keys_per_sec: f64) {
    if let Some(config) = PuzzleConfig::for_puzzle(puzzle_number) {
        println!("\n[🧩] BITCOIN PUZZLE #{}", puzzle_number);
        println!("     Range: 2^{} to 2^{}", puzzle_number - 1, puzzle_number);
        println!("     Keys:  {:.2e}", config.total_keys() as f64);
        println!("     ETA:   {} @ {:.1}M keys/sec", 
            config.estimated_time_human(keys_per_sec),
            keys_per_sec / 1_000_000.0
        );
        
        if let Some((_, _, reward)) = PUZZLE_TARGETS.iter().find(|(n, _, _)| *n == puzzle_number) {
            println!("     Prize: {} BTC", reward);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_puzzle_range() {
        let config = PuzzleConfig::for_puzzle(66).unwrap();
        let (start, end) = config.key_range();
        
        assert_eq!(start, 1u128 << 65);
        assert_eq!(end, 1u128 << 66);
        assert_eq!(config.total_keys(), 1u128 << 65);
    }
    
    #[test]
    fn test_puzzle_time_estimate() {
        let config = PuzzleConfig::for_puzzle(66).unwrap();
        
        // At 2.5M keys/sec (current M1 speed)
        let time = config.estimated_time_human(2_500_000.0);
        println!("Puzzle 66 ETA at 2.5M/s: {}", time);
        
        // Should be ~467 million years
        assert!(time.contains("e+") || time.contains("years"));
    }
    
    #[test]
    fn test_puzzle_progress() {
        let progress = PuzzleProgress::new(1_000_000);
        progress.add(100_000);
        
        assert_eq!(progress.percentage(), 10.0);
    }
}


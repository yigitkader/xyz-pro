/// Bitcoin Puzzle Mode - Sequential search in known key ranges

/// Known Bitcoin Puzzle addresses (unsolved as of 2024)
pub const PUZZLE_TARGETS: &[(u8, &str, f64)] = &[
    (66, "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so", 6.6),
    (67, "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9", 6.7),
    (68, "1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ", 6.8),
    (69, "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG", 6.9),
    (70, "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR", 7.0),
];

/// Pre-computed hash160 values for puzzle addresses
const PUZZLE_HASHES: &[(u8, [u8; 20])] = &[
    (66, [0x20, 0xd4, 0x5a, 0x6a, 0x76, 0x25, 0x35, 0x70, 0x0c, 0xe9, 
          0xe0, 0xb2, 0x16, 0xe3, 0x19, 0x94, 0x33, 0x5d, 0xb8, 0xa5]),
    (67, [0x73, 0x94, 0x37, 0xbb, 0x3d, 0xd6, 0xd1, 0x98, 0x3e, 0x66,
          0x62, 0x9c, 0x5f, 0x08, 0xc7, 0x0e, 0x52, 0x76, 0x93, 0x71]),
    (68, [0xe0, 0xb8, 0xa2, 0xba, 0xee, 0x1b, 0x77, 0xfc, 0x70, 0x34,
          0x55, 0xf3, 0x9d, 0x51, 0x47, 0x7d, 0x25, 0x05, 0x4a, 0x36]),
];

#[derive(Clone)]
pub struct PuzzleConfig {
    pub puzzle_number: u8,
    pub start_offset: u128,
    pub key_count: u128,
    pub target_hash: [u8; 20],
}

impl PuzzleConfig {
    pub fn for_puzzle(puzzle_number: u8) -> Option<Self> {
        PUZZLE_HASHES.iter()
            .find(|(n, _)| *n == puzzle_number)
            .map(|(n, hash)| Self {
                puzzle_number: *n,
                start_offset: 0,
                key_count: 0,
                target_hash: *hash,
            })
    }
    
    pub fn key_range(&self) -> (u128, u128) {
        let min = 1u128 << (self.puzzle_number - 1);
        let max = 1u128 << self.puzzle_number;
        let start = min + self.start_offset;
        let end = if self.key_count > 0 { (start + self.key_count).min(max) } else { max };
        (start, end)
    }
    
    pub fn total_keys(&self) -> u128 {
        let (start, end) = self.key_range();
        end - start
    }
    
    fn eta_human(&self, keys_per_sec: f64) -> String {
        let secs = self.total_keys() as f64 / keys_per_sec;
        if secs < 3600.0 { format!("{:.1}m", secs / 60.0) }
        else if secs < 86400.0 { format!("{:.1}h", secs / 3600.0) }
        else if secs < 31536000.0 { format!("{:.1}d", secs / 86400.0) }
        else { format!("{:.2e} years", secs / 31536000.0) }
    }
}

pub fn print_puzzle_info(puzzle_number: u8, keys_per_sec: f64) {
    if let Some(config) = PuzzleConfig::for_puzzle(puzzle_number) {
        println!("\n[🧩] BITCOIN PUZZLE #{}", puzzle_number);
        println!("     Range: 2^{} to 2^{}", puzzle_number - 1, puzzle_number);
        println!("     Keys:  {:.2e}", config.total_keys() as f64);
        println!("     ETA:   {} @ {:.1}M/s", config.eta_human(keys_per_sec), keys_per_sec / 1e6);
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
    }
}

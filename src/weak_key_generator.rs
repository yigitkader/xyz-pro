/// WEAK KEY GENERATOR MODULE
/// 
/// Generates keys from predictable sources that humans might use:
/// - Brain wallets (password → SHA256 → private key)
/// - Sequential patterns (0x1, 0x2, ... puzzle addresses)
/// - Common passwords and phrases
/// - Date-based keys
/// - Phone numbers, etc.

use sha2::{Sha256, Digest};

/// Generate a brain wallet key from a passphrase
/// WARNING: Brain wallets are known to be WEAK
pub fn brain_wallet(passphrase: &str) -> [u8; 32] {
    let hash = Sha256::digest(passphrase.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

/// Generate sequential keys for puzzle hunting
/// The Bitcoin Puzzle (1BTC per address) uses sequential keys
pub struct SequentialKeyGenerator {
    current: u128,
    max: u128,
}

impl SequentialKeyGenerator {
    /// Create generator for a specific bit range
    /// e.g., puzzle #66 is in range 2^65 to 2^66
    pub fn for_puzzle(puzzle_number: u8) -> Self {
        let min = 1u128 << (puzzle_number - 1);
        let max = 1u128 << puzzle_number;
        Self { current: min, max }
    }
    
    /// Create generator for arbitrary range
    pub fn for_range(start: u128, end: u128) -> Self {
        Self { current: start, max: end }
    }
    
    pub fn next_key(&mut self) -> Option<[u8; 32]> {
        if self.current >= self.max {
            return None;
        }
        
        let mut key = [0u8; 32];
        let bytes = self.current.to_be_bytes();
        key[16..32].copy_from_slice(&bytes);
        
        self.current += 1;
        Some(key)
    }
    
    pub fn remaining(&self) -> u128 {
        self.max.saturating_sub(self.current)
    }
}

/// Common weak patterns that have been found before
pub struct WeakPatternGenerator {
    patterns: Vec<Box<dyn Fn(u64) -> [u8; 32] + Send + Sync>>,
    current_pattern: usize,
    current_index: u64,
}

impl WeakPatternGenerator {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                // Pattern 1: Simple incrementing
                Box::new(|i| {
                    let mut key = [0u8; 32];
                    key[24..32].copy_from_slice(&i.to_be_bytes());
                    key
                }),
                
                // Pattern 2: Repeated bytes
                Box::new(|i| {
                    let byte = (i & 0xFF) as u8;
                    [byte; 32]
                }),
                
                // Pattern 3: Date-based (YYYYMMDD as number)
                Box::new(|i| {
                    // 20090103 (Bitcoin genesis) to 20241231
                    let date = 20090103 + i;
                    let mut key = [0u8; 32];
                    key[24..32].copy_from_slice(&date.to_be_bytes());
                    key
                }),
            ],
            current_pattern: 0,
            current_index: 0,
        }
    }
    
    pub fn next_key(&mut self) -> Option<[u8; 32]> {
        if self.current_pattern >= self.patterns.len() {
            return None;
        }
        
        let key = (self.patterns[self.current_pattern])(self.current_index);
        self.current_index += 1;
        
        // Move to next pattern after exhausting reasonable range
        if self.current_index > 1_000_000_000 {
            self.current_pattern += 1;
            self.current_index = 0;
        }
        
        Some(key)
    }
}

/// Wordlist-based brain wallet generator
pub struct WordlistGenerator {
    words: Vec<String>,
    current_single: usize,
    current_combo: (usize, usize),
}

impl WordlistGenerator {
    pub fn from_wordlist(words: Vec<String>) -> Self {
        Self {
            words,
            current_single: 0,
            current_combo: (0, 0),
        }
    }
    
    /// Load common password wordlist
    pub fn common_passwords() -> Self {
        // Top passwords that have been used as brain wallets
        let words = vec![
            "password", "123456", "bitcoin", "satoshi", "nakamoto",
            "blockchain", "crypto", "wallet", "secret", "private",
            "money", "cash", "gold", "silver", "moon", "hodl",
            "lambo", "rich", "freedom", "liberty", "trust",
            // Famous phrases
            "correct horse battery staple",
            "to be or not to be",
            "the quick brown fox",
            // More...
        ].into_iter().map(String::from).collect();
        
        Self::from_wordlist(words)
    }
    
    pub fn next_key(&mut self) -> Option<[u8; 32]> {
        // First: single words
        if self.current_single < self.words.len() {
            let key = brain_wallet(&self.words[self.current_single]);
            self.current_single += 1;
            return Some(key);
        }
        
        // Then: two-word combinations
        let (i, j) = self.current_combo;
        if i < self.words.len() && j < self.words.len() {
            let phrase = format!("{}{}", self.words[i], self.words[j]);
            let key = brain_wallet(&phrase);
            
            self.current_combo = if j + 1 < self.words.len() {
                (i, j + 1)
            } else {
                (i + 1, 0)
            };
            
            return Some(key);
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_brain_wallet() {
        // Known brain wallet: "satoshi" → specific address
        let key = brain_wallet("satoshi");
        assert!(!key.iter().all(|&b| b == 0));
    }
    
    #[test]
    fn test_sequential_generator() {
        let mut gen = SequentialKeyGenerator::for_puzzle(10);
        let key = gen.next_key().unwrap();
        // Puzzle 10 starts at 2^9 = 512
        assert_eq!(key[30], 2); // 512 = 0x200
        assert_eq!(key[31], 0);
    }
    
    #[test]
    fn test_weak_patterns() {
        let mut gen = WeakPatternGenerator::new();
        let key1 = gen.next_key().unwrap();
        let key2 = gen.next_key().unwrap();
        assert_ne!(key1, key2);
    }
}


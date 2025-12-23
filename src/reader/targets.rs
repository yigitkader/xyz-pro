//! Target address loader and matcher
//!
//! Loads targets.json and provides fast O(1) lookup using HashSet.
//! Supports all address types: P2PKH, P2SH, P2WPKH, P2WSH

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Instant;

/// Statistics about loaded targets
#[derive(Debug, Default)]
pub struct TargetStats {
    pub total: usize,
    pub p2pkh: usize,   // 1...
    pub p2sh: usize,    // 3...
    pub p2wpkh: usize,  // bc1q (short)
    pub p2wsh: usize,   // bc1q (long)
    pub load_time_ms: u64,
}

/// Fast target lookup using HashSet
pub struct TargetSet {
    /// All addresses as strings for direct lookup
    addresses: HashSet<String>,
    /// Hash160 lookups for P2PKH/P2WPKH (decoded from address)
    hash160_set: HashSet<[u8; 20]>,
    /// P2SH script hashes
    p2sh_set: HashSet<[u8; 20]>,
    /// Stats
    pub stats: TargetStats,
}

impl TargetSet {
    /// Load targets from JSON file
    /// Format: { "addresses": ["addr1", "addr2", ...] }
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let start = Instant::now();
        let file = File::open(path.as_ref())
            .map_err(|e| format!("Failed to open targets file: {}", e))?;
        
        let reader = BufReader::with_capacity(64 * 1024 * 1024, file); // 64MB buffer
        
        let mut addresses = HashSet::new();
        let mut hash160_set = HashSet::new();
        let mut p2sh_set = HashSet::new();
        let mut stats = TargetStats::default();
        
        println!("📂 Loading targets...");
        
        // Simple line-by-line parsing (faster than serde for large files)
        for line in reader.lines() {
            let line = line.map_err(|e| format!("Read error: {}", e))?;
            let trimmed = line.trim();
            
            // Skip JSON syntax
            if trimmed.is_empty() 
                || trimmed == "{" 
                || trimmed == "}" 
                || trimmed == "]" 
                || trimmed.starts_with("\"addresses\"") 
                || trimmed == "[" 
            {
                continue;
            }
            
            // Extract address from JSON string
            // Order: trim comma first, then quotes
            let addr = trimmed
                .trim_end_matches(',')
                .trim_start_matches('"')
                .trim_end_matches('"');
            
            if addr.is_empty() {
                continue;
            }
            
            // Classify and store
            if addr.starts_with('1') {
                stats.p2pkh += 1;
                if let Some(hash) = decode_p2pkh(addr) {
                    hash160_set.insert(hash);
                }
            } else if addr.starts_with('3') {
                stats.p2sh += 1;
                if let Some(hash) = decode_p2sh(addr) {
                    p2sh_set.insert(hash);
                }
            } else if addr.starts_with("bc1q") {
                if addr.len() <= 44 {
                    stats.p2wpkh += 1;
                    if let Some(hash) = decode_bech32(addr) {
                        hash160_set.insert(hash);
                    }
                } else {
                    stats.p2wsh += 1;
                }
            }
            
            addresses.insert(addr.to_string());
            stats.total += 1;
            
            // Progress
            if stats.total % 1_000_000 == 0 {
                println!("   Loaded {} addresses...", stats.total);
            }
        }
        
        stats.load_time_ms = start.elapsed().as_millis() as u64;
        
        println!("✅ Loaded {} targets in {}ms", stats.total, stats.load_time_ms);
        println!("   P2PKH: {}, P2SH: {}, P2WPKH: {}, P2WSH: {}", 
                 stats.p2pkh, stats.p2sh, stats.p2wpkh, stats.p2wsh);
        println!("   Hash160 set: {} entries", hash160_set.len());
        println!("   P2SH set: {} entries", p2sh_set.len());
        
        Ok(Self {
            addresses,
            hash160_set,
            p2sh_set,
            stats,
        })
    }
    
    /// Check if address string exists in targets
    #[inline]
    pub fn contains_address(&self, addr: &str) -> bool {
        self.addresses.contains(addr)
    }
    
    /// Check if hash160 exists (for P2PKH and P2WPKH)
    #[inline]
    pub fn contains_hash160(&self, hash: &[u8; 20]) -> bool {
        self.hash160_set.contains(hash)
    }
    
    /// Check if P2SH script hash exists
    #[inline]
    pub fn contains_p2sh(&self, hash: &[u8; 20]) -> bool {
        self.p2sh_set.contains(hash)
    }
    
    /// Check raw key data against all target types
    /// Returns (p2pkh_match, p2sh_match, p2wpkh_match)
    #[inline]
    pub fn check_raw(&self, pubkey_hash: &[u8; 20], p2sh_hash: &[u8; 20]) -> (bool, bool, bool) {
        let p2pkh = self.hash160_set.contains(pubkey_hash);
        let p2sh = self.p2sh_set.contains(p2sh_hash);
        let p2wpkh = p2pkh; // Same hash for P2WPKH
        (p2pkh, p2sh, p2wpkh)
    }
}

/// Decode P2PKH address to hash160
fn decode_p2pkh(addr: &str) -> Option<[u8; 20]> {
    // Base58Check: [version:1][hash160:20][checksum:4] = 25 bytes
    let decoded = bs58::decode(addr).into_vec().ok()?;
    
    if decoded.len() != 25 {
        return None;
    }
    
    // Skip version (1 byte), take hash160 (20 bytes), skip checksum (4 bytes)
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&decoded[1..21]);
    Some(hash)
}

/// Decode P2SH address to script hash
fn decode_p2sh(addr: &str) -> Option<[u8; 20]> {
    // Base58Check: [version:1][script_hash:20][checksum:4] = 25 bytes
    let decoded = bs58::decode(addr).into_vec().ok()?;
    
    if decoded.len() != 25 {
        return None;
    }
    
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&decoded[1..21]);
    Some(hash)
}

/// Decode bech32 address to hash
fn decode_bech32(addr: &str) -> Option<[u8; 20]> {
    use bech32::FromBase32;
    
    // Decode bech32/bech32m address
    let decoded = bech32::decode(addr).ok()?;
    let data_5bit = decoded.1;
    
    if data_5bit.is_empty() {
        return None;
    }
    
    // First 5-bit value is witness version (0 for P2WPKH)
    // The rest is the witness program in 5-bit encoding
    let witness_version = data_5bit[0].to_u8();
    if witness_version != 0 {
        // Only handle witness version 0 (P2WPKH/P2WSH)
        return None;
    }
    
    // Convert remaining 5-bit data to 8-bit
    let program = Vec::<u8>::from_base32(&data_5bit[1..]).ok()?;
    
    // P2WPKH has 20-byte program, P2WSH has 32-byte
    if program.len() == 20 {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&program);
        Some(hash)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_decode_p2pkh() {
        // Known address with known hash
        let hash = decode_p2pkh("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert!(hash.is_some());
    }
    
    #[test]
    fn test_decode_bech32() {
        let hash = decode_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(hash.is_some());
    }
}


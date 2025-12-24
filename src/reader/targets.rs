//! Target address loader and matcher
//!
//! Loads targets.json and provides fast O(1) lookup using HashSet with FxHash.
//! Supports all address types: P2PKH, P2SH, P2WPKH, P2WSH
//!
//! **Performance**: Uses FxHash instead of SipHash for ~3x faster hash lookups.
//! **Cache Support**: Parses JSON once, saves binary cache for fast reload.
//! Cache is invalidated when source file changes (size or mtime).

use std::collections::HashSet;
use std::fs::{self, File};
use std::hash::BuildHasherDefault;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::Instant;

use fxhash::FxHasher;
use serde::{Serialize, Deserialize};

/// Fast HashSet using FxHash - 3x faster than default SipHash for fixed-size keys
type FxHashSet<T> = HashSet<T, BuildHasherDefault<FxHasher>>;

/// Cache file format version (increment when format changes)
const CACHE_VERSION: u32 = 1;

/// Statistics about loaded targets
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TargetStats {
    pub total: usize,
    pub p2pkh: usize,   // 1...
    pub p2sh: usize,    // 3...
    pub p2wpkh: usize,  // bc1q (short)
    pub p2wsh: usize,   // bc1q (long)
    pub load_time_ms: u64,
}

/// Cache metadata for invalidation
#[derive(Serialize, Deserialize)]
struct CacheMetadata {
    version: u32,
    source_size: u64,
    source_mtime: u64,
}

/// Cached target data
#[derive(Serialize, Deserialize)]
struct CachedTargets {
    metadata: CacheMetadata,
    hash160_list: Vec<[u8; 20]>,
    p2sh_list: Vec<[u8; 20]>,
    stats: TargetStats,
}

/// Fast target lookup using FxHashSet (~3x faster than default)
pub struct TargetSet {
    /// All addresses as strings for direct lookup
    addresses: HashSet<String>,
    /// Hash160 lookups for P2PKH/P2WPKH (decoded from address)
    /// Uses FxHash for faster lookup on fixed-size keys
    hash160_set: FxHashSet<[u8; 20]>,
    /// P2SH script hashes
    /// Uses FxHash for faster lookup on fixed-size keys
    p2sh_set: FxHashSet<[u8; 20]>,
    /// Stats
    pub stats: TargetStats,
}

impl TargetSet {
    /// Load targets from JSON file with automatic caching
    /// 
    /// Cache is stored as `{path}.cache` and invalidated when source changes.
    /// First load: Parse JSON (~10s for 10M addresses)
    /// Cached load: Binary deserialize (~0.5s for 10M addresses)
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        let cache_path = path.with_extension("json.cache");
        
        // Try to load from cache first
        if let Some(cached) = Self::try_load_cache(path, &cache_path) {
            return Ok(cached);
        }
        
        // Cache miss or invalid - parse JSON
        let result = Self::load_from_json(path)?;
        
        // Save cache for next time
        if let Err(e) = result.save_cache(path, &cache_path) {
            eprintln!("⚠️ Failed to save cache: {}", e);
        }
        
        Ok(result)
    }
    
    /// Try to load from cache if valid
    fn try_load_cache(source_path: &Path, cache_path: &Path) -> Option<Self> {
        let start = Instant::now();
        
        // Check if cache file exists
        if !cache_path.exists() {
            return None;
        }
        
        // Get source file metadata
        let source_meta = fs::metadata(source_path).ok()?;
        let source_size = source_meta.len();
        let source_mtime = source_meta.modified().ok()?
            .duration_since(std::time::UNIX_EPOCH).ok()?
            .as_secs();
        
        // Read cache file
        let cache_data = fs::read(cache_path).ok()?;
        let cached: CachedTargets = bincode::deserialize(&cache_data).ok()?;
        
        // Validate cache
        if cached.metadata.version != CACHE_VERSION {
            println!("📦 Cache version mismatch, rebuilding...");
            return None;
        }
        
        if cached.metadata.source_size != source_size || 
           cached.metadata.source_mtime != source_mtime {
            println!("📦 Source file changed, rebuilding cache...");
            return None;
        }
        
        // Cache is valid - rebuild FxHashSets from lists
        let hash160_set: FxHashSet<[u8; 20]> = cached.hash160_list.into_iter().collect();
        let p2sh_set: FxHashSet<[u8; 20]> = cached.p2sh_list.into_iter().collect();
        
        let load_time = start.elapsed().as_millis() as u64;
        
        println!("⚡ Loaded {} targets from cache in {}ms", 
                 cached.stats.total, load_time);
        println!("   P2PKH: {}, P2SH: {}, P2WPKH: {}, P2WSH: {}", 
                 cached.stats.p2pkh, cached.stats.p2sh, 
                 cached.stats.p2wpkh, cached.stats.p2wsh);
        
        // Create empty addresses set (not needed for matching, saves memory)
        let addresses = HashSet::new();
        
        Some(Self {
            addresses,
            hash160_set,
            p2sh_set,
            stats: TargetStats {
                load_time_ms: load_time,
                ..cached.stats
            },
        })
    }
    
    /// Save current data to cache
    fn save_cache(&self, source_path: &Path, cache_path: &Path) -> Result<(), String> {
        let source_meta = fs::metadata(source_path)
            .map_err(|e| format!("Failed to get source metadata: {}", e))?;
        
        let source_mtime = source_meta.modified()
            .map_err(|e| format!("Failed to get mtime: {}", e))?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Time error: {}", e))?
            .as_secs();
        
        let cached = CachedTargets {
            metadata: CacheMetadata {
                version: CACHE_VERSION,
                source_size: source_meta.len(),
                source_mtime,
            },
            hash160_list: self.hash160_set.iter().copied().collect(),
            p2sh_list: self.p2sh_set.iter().copied().collect(),
            stats: self.stats.clone(),
        };
        
        let encoded = bincode::serialize(&cached)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        let mut file = File::create(cache_path)
            .map_err(|e| format!("Failed to create cache file: {}", e))?;
        
        file.write_all(&encoded)
            .map_err(|e| format!("Failed to write cache: {}", e))?;
        
        let cache_size_mb = encoded.len() as f64 / (1024.0 * 1024.0);
        println!("💾 Cache saved: {} ({:.1} MB)", cache_path.display(), cache_size_mb);
        
        Ok(())
    }
    
    /// Load targets directly from JSON (no cache)
    fn load_from_json(path: &Path) -> Result<Self, String> {
        let start = Instant::now();
        let file = File::open(path)
            .map_err(|e| format!("Failed to open targets file: {}", e))?;
        
        let reader = BufReader::with_capacity(64 * 1024 * 1024, file); // 64MB buffer
        
        let mut addresses = HashSet::new();
        let mut hash160_set: FxHashSet<[u8; 20]> = FxHashSet::default();
        let mut p2sh_set: FxHashSet<[u8; 20]> = FxHashSet::default();
        let mut stats = TargetStats::default();
        
        println!("📂 Parsing targets from JSON (first run, will cache)...");
        
        // Parse JSON - handles both compact and multi-line formats
        for line in reader.lines() {
            let line = line.map_err(|e| format!("Read error: {}", e))?;
            
            // For each line, extract all quoted strings that look like addresses
            // This handles both compact JSON and multi-line JSON
            let addresses_in_line = extract_addresses_from_line(&line);
            
            for addr in addresses_in_line {
                if addr.is_empty() {
                    continue;
                }
            
                // Classify and store - only count if decode succeeds
                if addr.starts_with('1') {
                    if let Some(hash) = decode_p2pkh(&addr) {
                        hash160_set.insert(hash);
                        stats.p2pkh += 1;
                    } else {
                        eprintln!("   ⚠️ Failed to decode P2PKH address (skipped): {}", addr);
                        continue;
                    }
                } else if addr.starts_with('3') {
                    if let Some(hash) = decode_p2sh(&addr) {
                        p2sh_set.insert(hash);
                        stats.p2sh += 1;
                    } else {
                        eprintln!("   ⚠️ Failed to decode P2SH address (skipped): {}", addr);
                        continue;
                    }
                } else if addr.starts_with("bc1q") {
                    if addr.len() <= 44 {
                        // Only count as P2WPKH if decode succeeds
                        match decode_bech32(&addr) {
                            Some(hash) => { 
                                hash160_set.insert(hash);
                                stats.p2wpkh += 1;
                            }
                            None => {
                                // Log decode failures - important for debugging invalid target addresses
                                // Don't increment stats for failed decodes
                                eprintln!("   ⚠️ Failed to decode bech32 address (skipped): {}", addr);
                                continue; // Skip this invalid address entirely
                            }
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
        }
        
        stats.load_time_ms = start.elapsed().as_millis() as u64;
        
        println!("✅ Parsed {} targets in {}ms", stats.total, stats.load_time_ms);
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

/// Extract addresses from a line (handles both compact and multi-line JSON)
fn extract_addresses_from_line(line: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    let mut in_quote = false;
    let mut current_addr = String::new();
    
    for ch in line.chars() {
        if ch == '"' {
            if in_quote {
                // End of quoted string
                // Check if it looks like a Bitcoin address
                if !current_addr.is_empty() 
                   && (current_addr.starts_with('1') 
                       || current_addr.starts_with('3')
                       || current_addr.starts_with("bc1"))
                {
                    addresses.push(current_addr.clone());
                }
                current_addr.clear();
            }
            in_quote = !in_quote;
        } else if in_quote {
            current_addr.push(ch);
        }
    }
    
    addresses
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
    
    #[test]
    fn test_extract_addresses_compact() {
        let line = r#"{"addresses":["1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH","3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC","bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]}"#;
        let addrs = extract_addresses_from_line(line);
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0], "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        assert_eq!(addrs[1], "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC");
        assert_eq!(addrs[2], "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }
    
    #[test]
    fn test_same_pubkey_different_formats() {
        // These addresses are for the SAME public key, just different formats
        // P2PKH: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
        // P2WPKH: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
        // They share the same hash160!
        
        let p2pkh = decode_p2pkh("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        let p2wpkh = decode_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        
        assert!(p2pkh.is_some(), "P2PKH decode should succeed");
        assert!(p2wpkh.is_some(), "P2WPKH decode should succeed");
        
        // Same pubkey = same hash160 (this is correct!)
        assert_eq!(p2pkh.unwrap(), p2wpkh.unwrap(), 
            "Same pubkey should produce same hash160 across address formats");
    }
    
    #[test]
    fn test_different_pubkeys() {
        // Different addresses = different hashes
        let addr1 = decode_p2pkh("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"); // Satoshi's genesis
        let addr2 = decode_p2pkh("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"); // Different
        
        assert!(addr1.is_some());
        assert!(addr2.is_some());
        assert_ne!(addr1.unwrap(), addr2.unwrap(), "Different addresses should have different hashes");
    }
}


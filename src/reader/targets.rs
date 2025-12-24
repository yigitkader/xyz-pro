//! Target address loader and matcher
//!
//! Loads targets.json and provides fast O(1) lookup using HashSet with FxHash.
//! Supports all address types: P2PKH, P2SH, P2WPKH, P2WSH
//!
//! **Performance**: Uses FxHash instead of SipHash for ~3x faster hash lookups.
//! **XOR Filter**: When enabled, uses Xor8 filter for 10x faster negative lookups.
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

#[cfg(feature = "xor-filter")]
use xorf::{Filter, Xor8};

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
/// When xor-filter feature is enabled, uses Xor8 for 10x faster negative lookups
/// 
/// **Optimized for 50M+ targets:**
/// - No string storage (saves ~2GB for 50M addresses)
/// - Pre-allocated HashSets
/// - XOR filters for fast negative lookups
pub struct TargetSet {
    /// Hash160 lookups for P2PKH/P2WPKH (decoded from address)
    /// Uses FxHash for faster lookup on fixed-size keys
    /// Memory: 50M × 20 bytes = 1GB + HashSet overhead (~50%) = 1.5GB
    hash160_set: FxHashSet<[u8; 20]>,
    /// P2SH script hashes
    /// Uses FxHash for faster lookup on fixed-size keys
    p2sh_set: FxHashSet<[u8; 20]>,
    
    /// XOR Filter for hash160 - ultra-fast negative lookup
    /// False positive rate ~0.4%, but HashSet confirms positives
    /// Memory: 50M × 1.23 bytes = 61MB (very efficient!)
    #[cfg(feature = "xor-filter")]
    hash160_xor: Option<Xor8>,
    
    /// XOR Filter for P2SH hashes
    #[cfg(feature = "xor-filter")]
    p2sh_xor: Option<Xor8>,
    
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
        let hash160_set: FxHashSet<[u8; 20]> = cached.hash160_list.iter().copied().collect();
        let p2sh_set: FxHashSet<[u8; 20]> = cached.p2sh_list.iter().copied().collect();
        
        // Build XOR filters if feature enabled
        #[cfg(feature = "xor-filter")]
        let (hash160_xor, p2sh_xor) = {
            let xor_start = Instant::now();
            
            // Convert [u8; 20] to u64 keys for XOR filter
            let hash160_keys: Vec<u64> = cached.hash160_list.iter()
                .map(|h| hash160_to_u64(h))
                .collect();
            let p2sh_keys: Vec<u64> = cached.p2sh_list.iter()
                .map(|h| hash160_to_u64(h))
                .collect();
            
            let h_xor = if !hash160_keys.is_empty() {
                Xor8::try_from(&hash160_keys).ok()
            } else {
                None
            };
            
            let p_xor = if !p2sh_keys.is_empty() {
                Xor8::try_from(&p2sh_keys).ok()
            } else {
                None
            };
            
            println!("   XOR filters built in {}ms", xor_start.elapsed().as_millis());
            (h_xor, p_xor)
        };
        
        let load_time = start.elapsed().as_millis() as u64;
        
        println!("⚡ Loaded {} targets from cache in {}ms", 
                 cached.stats.total, load_time);
        println!("   P2PKH: {}, P2SH: {}, P2WPKH: {}, P2WSH: {}", 
                 cached.stats.p2pkh, cached.stats.p2sh, 
                 cached.stats.p2wpkh, cached.stats.p2wsh);
        
        #[cfg(feature = "xor-filter")]
        println!("   ✓ XOR Filter enabled (10x faster negative lookups)");
        
        Some(Self {
            hash160_set,
            p2sh_set,
            #[cfg(feature = "xor-filter")]
            hash160_xor,
            #[cfg(feature = "xor-filter")]
            p2sh_xor,
            stats: TargetStats {
                load_time_ms: load_time,
                ..cached.stats
            },
        })
    }
    
    /// Save current data to cache using atomic write (temp file + rename)
    /// This prevents corruption if multiple processes write simultaneously
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
        
        // Atomic write: write to temp file, then rename
        // This prevents corruption from concurrent writes
        let temp_path = cache_path.with_extension("json.cache.tmp");
        
        let mut file = File::create(&temp_path)
            .map_err(|e| format!("Failed to create temp cache file: {}", e))?;
        
        file.write_all(&encoded)
            .map_err(|e| format!("Failed to write cache: {}", e))?;
        
        // Ensure data is flushed to disk before rename
        file.sync_all()
            .map_err(|e| format!("Failed to sync cache file: {}", e))?;
        
        // Drop file handle before rename (important on Windows)
        drop(file);
        
        // Platform-specific atomic rename
        atomic_rename_file(&temp_path, cache_path)
            .map_err(|e| format!("Failed to rename cache file: {}", e))?;
        
        let cache_size_mb = encoded.len() as f64 / (1024.0 * 1024.0);
        println!("💾 Cache saved: {} ({:.1} MB)", cache_path.display(), cache_size_mb);
        
        Ok(())
    }
    
    /// Load targets directly from JSON (no cache)
    /// 
    /// **Optimized for 50M+ targets:**
    /// - Pre-allocated HashSets (avoids rehashing during growth)
    /// - No string storage (saves ~2GB memory)
    /// - Progress reporting every 500K addresses
    /// - Memory estimate: 50M targets ≈ 1.5GB RAM
    fn load_from_json(path: &Path) -> Result<Self, String> {
        let start = Instant::now();
        let file = File::open(path)
            .map_err(|e| format!("Failed to open targets file: {}", e))?;
        
        // Estimate target count from file size (~45 bytes per address on average)
        let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        let estimated_count = (file_size / 45) as usize;
        let initial_capacity = estimated_count.max(1_000_000); // At least 1M
        
        println!("📂 Parsing targets from JSON (first run, will cache)...");
        println!("   File size: {:.1} MB, estimated targets: ~{}",
                 file_size as f64 / (1024.0 * 1024.0),
                 format_count(estimated_count));
        println!("   Pre-allocating {} capacity for HashSets...", format_count(initial_capacity));
        
        let reader = BufReader::with_capacity(128 * 1024 * 1024, file); // 128MB buffer for large files
        
        // Pre-allocate HashSets to avoid rehashing during growth
        // This is CRITICAL for 50M+ targets - rehashing is O(n) each time
        let mut hash160_set: FxHashSet<[u8; 20]> = FxHashSet::default();
        hash160_set.reserve(initial_capacity);
        
        let mut p2sh_set: FxHashSet<[u8; 20]> = FxHashSet::default();
        p2sh_set.reserve(initial_capacity / 10); // P2SH typically fewer
        
        let mut stats = TargetStats::default();
        let mut last_progress = Instant::now();
        
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
                // NOTE: We don't store the address string - saves ~2GB for 50M targets!
                if addr.starts_with('1') {
                    if let Some(hash) = decode_p2pkh(&addr) {
                        hash160_set.insert(hash);
                        stats.p2pkh += 1;
                        stats.total += 1;
                    }
                    // Silently skip invalid addresses for performance
                } else if addr.starts_with('3') {
                    if let Some(hash) = decode_p2sh(&addr) {
                        p2sh_set.insert(hash);
                        stats.p2sh += 1;
                        stats.total += 1;
                    }
                } else if addr.starts_with("bc1q") {
                    if addr.len() <= 44 {
                        if let Some(hash) = decode_bech32(&addr) {
                            hash160_set.insert(hash);
                            stats.p2wpkh += 1;
                            stats.total += 1;
                        }
                    } else {
                        stats.p2wsh += 1;
                        stats.total += 1;
                    }
                }
                
                // Progress every 500K or every 2 seconds
                if stats.total % 500_000 == 0 || last_progress.elapsed().as_secs() >= 2 {
                    let elapsed = start.elapsed().as_secs_f64();
                    let rate = stats.total as f64 / elapsed;
                    let remaining = if rate > 0.0 {
                        (estimated_count.saturating_sub(stats.total)) as f64 / rate
                    } else {
                        0.0
                    };
                    println!("   {} loaded ({:.1} addr/sec, ETA: {:.0}s)", 
                             format_count(stats.total), rate, remaining);
                    last_progress = Instant::now();
                }
            }
        }
        
        // Shrink to fit after loading (release unused capacity)
        hash160_set.shrink_to_fit();
        p2sh_set.shrink_to_fit();
        
        // Build XOR filters if feature enabled
        #[cfg(feature = "xor-filter")]
        let (hash160_xor, p2sh_xor) = {
            println!("   Building XOR filters for {} + {} hashes...", 
                     format_count(hash160_set.len()), format_count(p2sh_set.len()));
            let xor_start = Instant::now();
            
            // Convert [u8; 20] to u64 keys for XOR filter
            let hash160_keys: Vec<u64> = hash160_set.iter()
                .map(|h| hash160_to_u64(h))
                .collect();
            let p2sh_keys: Vec<u64> = p2sh_set.iter()
                .map(|h| hash160_to_u64(h))
                .collect();
            
            let h_xor = if !hash160_keys.is_empty() {
                Xor8::try_from(&hash160_keys).ok()
            } else {
                None
            };
            
            let p_xor = if !p2sh_keys.is_empty() {
                Xor8::try_from(&p2sh_keys).ok()
            } else {
                None
            };
            
            println!("   XOR filters built in {}ms", xor_start.elapsed().as_millis());
            (h_xor, p_xor)
        };
        
        stats.load_time_ms = start.elapsed().as_millis() as u64;
        
        // Memory usage estimate
        let hash160_mem = hash160_set.len() * 20 * 3 / 2; // ~1.5x for HashSet overhead
        let p2sh_mem = p2sh_set.len() * 20 * 3 / 2;
        let total_mem_mb = (hash160_mem + p2sh_mem) as f64 / (1024.0 * 1024.0);
        
        println!("✅ Parsed {} targets in {:.1}s", format_count(stats.total), stats.load_time_ms as f64 / 1000.0);
        println!("   P2PKH: {}, P2SH: {}, P2WPKH: {}, P2WSH: {}", 
                 format_count(stats.p2pkh), format_count(stats.p2sh), 
                 format_count(stats.p2wpkh), format_count(stats.p2wsh));
        println!("   Hash160 set: {} entries", format_count(hash160_set.len()));
        println!("   P2SH set: {} entries", format_count(p2sh_set.len()));
        println!("   Estimated memory: {:.1} MB", total_mem_mb);
        
        #[cfg(feature = "xor-filter")]
        {
            let xor_mem = (hash160_set.len() + p2sh_set.len()) as f64 * 1.23 / (1024.0 * 1024.0);
            println!("   XOR filter memory: {:.1} MB", xor_mem);
            println!("   ✓ XOR Filter enabled (10x faster negative lookups)");
        }
        
        Ok(Self {
            hash160_set,
            p2sh_set,
            #[cfg(feature = "xor-filter")]
            hash160_xor,
            #[cfg(feature = "xor-filter")]
            p2sh_xor,
            stats,
        })
    }
    
    /// Get memory usage estimate in bytes
    pub fn memory_usage(&self) -> usize {
        let hash160_mem = self.hash160_set.len() * 20 * 3 / 2;
        let p2sh_mem = self.p2sh_set.len() * 20 * 3 / 2;
        
        #[cfg(feature = "xor-filter")]
        let xor_mem = (self.hash160_set.len() + self.p2sh_set.len()) * 123 / 100;
        
        #[cfg(not(feature = "xor-filter"))]
        let xor_mem = 0;
        
        hash160_mem + p2sh_mem + xor_mem
    }
    
    /// Check if hash160 exists (for P2PKH and P2WPKH)
    #[inline]
    pub fn contains_hash160(&self, hash: &[u8; 20]) -> bool {
        #[cfg(feature = "xor-filter")]
        {
            // Fast XOR filter check first
            let key = hash160_to_u64(hash);
            let maybe = self.hash160_xor
                .as_ref()
                .map(|xor| xor.contains(&key))
                .unwrap_or(false);
            
            // Confirm with HashSet if XOR says maybe
            maybe && self.hash160_set.contains(hash)
        }
        
        #[cfg(not(feature = "xor-filter"))]
        {
            self.hash160_set.contains(hash)
        }
    }
    
    /// Check if P2SH script hash exists
    #[inline]
    pub fn contains_p2sh(&self, hash: &[u8; 20]) -> bool {
        #[cfg(feature = "xor-filter")]
        {
            let key = hash160_to_u64(hash);
            let maybe = self.p2sh_xor
                .as_ref()
                .map(|xor| xor.contains(&key))
                .unwrap_or(false);
            
            maybe && self.p2sh_set.contains(hash)
        }
        
        #[cfg(not(feature = "xor-filter"))]
        {
            self.p2sh_set.contains(hash)
        }
    }
    
    /// Check raw key data against all target types
    /// Returns (p2pkh_match, p2sh_match, p2wpkh_match)
    /// 
    /// When xor-filter is enabled:
    /// 1. XOR filter provides ultra-fast negative lookup (rejects ~99.6% of non-matches)
    /// 2. If XOR filter says "maybe", HashSet confirms (eliminates false positives)
    #[inline]
    pub fn check_raw(&self, pubkey_hash: &[u8; 20], p2sh_hash: &[u8; 20]) -> (bool, bool, bool) {
        #[cfg(feature = "xor-filter")]
        {
            // Fast path: XOR filter rejects most non-matches instantly
            let pubkey_key = hash160_to_u64(pubkey_hash);
            let p2sh_key = hash160_to_u64(p2sh_hash);
            
            // Check hash160 (P2PKH/P2WPKH)
            let maybe_p2pkh = self.hash160_xor
                .as_ref()
                .map(|xor| xor.contains(&pubkey_key))
                .unwrap_or(false);
            
            // Check P2SH
            let maybe_p2sh = self.p2sh_xor
                .as_ref()
                .map(|xor| xor.contains(&p2sh_key))
                .unwrap_or(false);
            
            // If XOR filter says no, it's definitely no (no false negatives)
            // If XOR filter says maybe, confirm with HashSet
            let p2pkh = maybe_p2pkh && self.hash160_set.contains(pubkey_hash);
            let p2sh = maybe_p2sh && self.p2sh_set.contains(p2sh_hash);
            let p2wpkh = p2pkh; // Same hash for P2WPKH
            
            (p2pkh, p2sh, p2wpkh)
        }
        
        #[cfg(not(feature = "xor-filter"))]
        {
            let p2pkh = self.hash160_set.contains(pubkey_hash);
            let p2sh = self.p2sh_set.contains(p2sh_hash);
            let p2wpkh = p2pkh; // Same hash for P2WPKH
            (p2pkh, p2sh, p2wpkh)
        }
    }
}

/// Convert 20-byte hash160 to u64 key for XOR filter
/// 
/// Uses XOR-fold to incorporate ALL 20 bytes, not just the first 8.
/// This eliminates hash collisions where different hash160 values
/// would map to the same XOR filter key.
/// 
/// Without XOR-fold: Only first 8 bytes used → collision if bytes 8-19 differ
/// With XOR-fold: All 20 bytes contribute → collision only if XOR-fold matches
/// 
/// Layout: [8 bytes] XOR [8 bytes] XOR [4 bytes as u64]
#[cfg(feature = "xor-filter")]
#[inline(always)]
fn hash160_to_u64(hash: &[u8; 20]) -> u64 {
    // XOR-fold all 20 bytes into 64 bits
    // This ensures every byte of the hash160 contributes to the key
    let p1 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
    let p2 = u64::from_le_bytes(hash[8..16].try_into().unwrap());
    let p3 = u32::from_le_bytes(hash[16..20].try_into().unwrap()) as u64;
    p1 ^ p2 ^ p3
}

/// Atomic file rename - platform-specific implementation
/// 
/// On Unix: rename() is atomic by POSIX specification
/// On Windows: Uses MoveFileExW with MOVEFILE_REPLACE_EXISTING for atomic operation
/// 
/// This prevents cache corruption when multiple processes write simultaneously.
#[cfg(unix)]
fn atomic_rename_file(temp: &Path, target: &Path) -> std::io::Result<()> {
    // POSIX rename() is atomic - if target exists, it's replaced atomically
    fs::rename(temp, target)
}

#[cfg(windows)]
fn atomic_rename_file(temp: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::iter::once;
    
    // Windows FFI for MoveFileExW
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(
            lpExistingFileName: *const u16,
            lpNewFileName: *const u16,
            dwFlags: u32,
        ) -> i32;
    }
    
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x00000001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x00000008;
    
    fn to_wide_null(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(once(0)).collect()
    }
    
    let temp_wide = to_wide_null(temp.as_os_str());
    let target_wide = to_wide_null(target.as_os_str());
    
    // MOVEFILE_REPLACE_EXISTING: Replace target if exists (atomic)
    // MOVEFILE_WRITE_THROUGH: Ensure data is written to disk before returning
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    
    let result = unsafe {
        MoveFileExW(temp_wide.as_ptr(), target_wide.as_ptr(), flags)
    };
    
    if result != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

// Fallback for other platforms (should not be reached in practice)
#[cfg(not(any(unix, windows)))]
fn atomic_rename_file(temp: &Path, target: &Path) -> std::io::Result<()> {
    // Best effort: try remove then rename
    let _ = fs::remove_file(target);
    fs::rename(temp, target)
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
/// 
/// Bitcoin address encoding rules:
/// - Witness version 0 (P2WPKH/P2WSH): MUST use Bech32 encoding
/// - Witness version 1+ (Taproot/P2TR): MUST use Bech32m encoding
/// 
/// This function only handles P2WPKH (witness version 0), so we 
/// explicitly require Bech32 variant and reject Bech32m.
fn decode_bech32(addr: &str) -> Option<[u8; 20]> {
    use bech32::{FromBase32, Variant};
    
    // Decode bech32/bech32m address - returns (hrp, data, variant)
    let (hrp, data_5bit, variant) = bech32::decode(addr).ok()?;
    
    // Validate HRP for mainnet Bitcoin
    if hrp != "bc" {
        return None;
    }
    
    if data_5bit.is_empty() {
        return None;
    }
    
    // First 5-bit value is witness version (0 for P2WPKH)
    // The rest is the witness program in 5-bit encoding
    let witness_version = data_5bit[0].to_u8();
    
    // Validate variant matches witness version per BIP-350:
    // - Witness version 0: MUST use Bech32 (not Bech32m)
    // - Witness version 1+: MUST use Bech32m (not Bech32)
    // We only handle witness version 0 (P2WPKH/P2WSH)
    if witness_version != 0 || variant != Variant::Bech32 {
        // Either wrong witness version or wrong encoding variant
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

/// Format large numbers with K/M/B suffixes for readability
fn format_count(n: usize) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
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


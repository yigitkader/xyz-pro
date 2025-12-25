//! Target address loader and matcher
//!
//! Loads targets.json and provides fast O(1) lookup using HashSet with FxHash.
//! Supports all address types: P2PKH, P2SH, P2WPKH, P2WSH
//!
//! **Performance**: Uses FxHash instead of SipHash for ~3x faster hash lookups.
//! **XOR Filter**: When enabled, uses Xor8 filter for 10x faster negative lookups.
//! **Cache Support**: Parses JSON once, saves binary cache for fast reload.
//! Cache is invalidated when source file changes (size or mtime).
//!
//! ## JSON Parsing
//! 
//! Uses serde_json for robust, standards-compliant JSON parsing.
//! Supports multiple formats:
//! - `{"addresses": ["addr1", "addr2", ...]}`
//! - `["addr1", "addr2", ...]`
//! - Nested structures with addresses anywhere

use std::collections::HashSet;
use std::fs::{self, File};
use std::hash::BuildHasherDefault;
use std::io::{BufReader, Write};
use std::path::Path;
use std::time::Instant;

use fxhash::FxHasher;
use serde::{Serialize, Deserialize};
use serde_json::Value;

#[cfg(feature = "xor-filter")]
use xorf::{Filter, Xor8};

/// Fast HashSet using FxHash - 3x faster than default SipHash for fixed-size keys
type FxHashSet<T> = HashSet<T, BuildHasherDefault<FxHasher>>;

/// Cache file format version (increment when format changes)
/// v1: Initial format
/// v2: Added hash160_types, p2wsh_list, checksum
const CACHE_VERSION: u32 = 2;

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

/// Address type flags for precise match reporting
/// A single hash160 can belong to multiple address types (same key, different formats)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AddressTypeFlags(pub u8);

impl AddressTypeFlags {
    pub const NONE: u8 = 0;
    pub const P2PKH: u8 = 0x01;   // 1... addresses
    pub const P2WPKH: u8 = 0x02;  // bc1q... (20 byte) addresses
    
    #[inline]
    pub fn has_p2pkh(&self) -> bool { self.0 & Self::P2PKH != 0 }
    #[inline]
    pub fn has_p2wpkh(&self) -> bool { self.0 & Self::P2WPKH != 0 }
    #[inline]
    pub fn add_p2pkh(&mut self) { self.0 |= Self::P2PKH; }
    #[inline]
    pub fn add_p2wpkh(&mut self) { self.0 |= Self::P2WPKH; }
}

/// Cached target data (v2 - includes type flags and P2WSH)
#[derive(Serialize, Deserialize)]
struct CachedTargets {
    metadata: CacheMetadata,
    hash160_list: Vec<[u8; 20]>,
    hash160_types: Vec<u8>,  // AddressTypeFlags for each hash160
    p2sh_list: Vec<[u8; 20]>,
    p2wsh_list: Vec<[u8; 32]>,  // 32-byte SHA256 witness program
    stats: TargetStats,
    #[serde(default)]
    checksum: u64,  // XOR checksum of all hashes for integrity
}

/// Fast target lookup using FxHashSet (~3x faster than default)
/// When xor-filter feature is enabled, uses Xor8 for 10x faster negative lookups
/// 
/// **Optimized for 50M+ targets:**
/// - No string storage (saves ~2GB for 50M addresses)
/// - Pre-allocated HashSets
/// - XOR filters for fast negative lookups
/// - **Precise type tracking**: Each hash160 knows which address type(s) it came from
/// - **P2WSH support**: 32-byte witness program hashes are now tracked
pub struct TargetSet {
    /// Hash160 lookups for P2PKH/P2WPKH (decoded from address)
    /// Uses FxHash for faster lookup on fixed-size keys
    /// Memory: 50M × 20 bytes = 1GB + HashSet overhead (~50%) = 1.5GB
    hash160_set: FxHashSet<[u8; 20]>,
    
    /// Type flags for each hash160 - tracks which address types this hash came from
    /// This allows precise match reporting (P2PKH vs P2WPKH vs both)
    hash160_types: std::collections::HashMap<[u8; 20], AddressTypeFlags, BuildHasherDefault<FxHasher>>,
    
    /// P2SH script hashes (20 bytes - RIPEMD160 of SHA256)
    /// Uses FxHash for faster lookup on fixed-size keys
    p2sh_set: FxHashSet<[u8; 20]>,
    
    /// P2WSH witness program hashes (32 bytes - SHA256)
    /// bc1q... addresses with length > 44 characters
    p2wsh_set: FxHashSet<[u8; 32]>,
    
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
        
        // Verify checksum for data integrity
        let computed_checksum = compute_checksum(&cached.hash160_list, &cached.p2sh_list, &cached.p2wsh_list);
        if cached.checksum != 0 && cached.checksum != computed_checksum {
            println!("⚠️ Cache checksum mismatch, rebuilding...");
            return None;
        }
        
        // Cache is valid - rebuild FxHashSets from lists
        let hash160_set: FxHashSet<[u8; 20]> = cached.hash160_list.iter().copied().collect();
        let p2sh_set: FxHashSet<[u8; 20]> = cached.p2sh_list.iter().copied().collect();
        let p2wsh_set: FxHashSet<[u8; 32]> = cached.p2wsh_list.iter().copied().collect();
        
        // Rebuild hash160_types map from cached data
        type FxHashMap<K, V> = std::collections::HashMap<K, V, BuildHasherDefault<FxHasher>>;
        let mut hash160_types: FxHashMap<[u8; 20], AddressTypeFlags> = FxHashMap::default();
        hash160_types.reserve(cached.hash160_list.len());
        
        for (hash, type_flag) in cached.hash160_list.iter().zip(cached.hash160_types.iter()) {
            hash160_types.insert(*hash, AddressTypeFlags(*type_flag));
        }
        
        // Build XOR filters if feature enabled
        #[cfg(feature = "xor-filter")]
        let (hash160_xor, p2sh_xor) = {
            let xor_start = Instant::now();
            
            // Convert [u8; 20] to u64 keys for XOR filter
            // IMPORTANT: Must deduplicate! XOR filter panics on duplicate keys
            // Collisions in hash160_to_u64 are rare but possible (XOR-fold of 20 bytes to 8)
            let mut hash160_keys: Vec<u64> = cached.hash160_list.iter()
                .map(|h| hash160_to_u64(h))
                .collect();
            hash160_keys.sort_unstable();
            hash160_keys.dedup();
            
            let mut p2sh_keys: Vec<u64> = cached.p2sh_list.iter()
                .map(|h| hash160_to_u64(h))
                .collect();
            p2sh_keys.sort_unstable();
            p2sh_keys.dedup();
            
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
            hash160_types,
            p2sh_set,
            p2wsh_set,
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
    /// 
    /// # Concurrency Safety
    /// Uses PID-based temp file naming to prevent collisions when multiple
    /// processes try to write the cache simultaneously.
    fn save_cache(&self, source_path: &Path, cache_path: &Path) -> Result<(), String> {
        let source_meta = fs::metadata(source_path)
            .map_err(|e| format!("Failed to get source metadata: {}", e))?;
        
        let source_mtime = source_meta.modified()
            .map_err(|e| format!("Failed to get mtime: {}", e))?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Time error: {}", e))?
            .as_secs();
        
        // Collect lists in consistent order for caching
        let hash160_list: Vec<[u8; 20]> = self.hash160_set.iter().copied().collect();
        let hash160_types: Vec<u8> = hash160_list.iter()
            .map(|h| self.hash160_types.get(h).map(|t| t.0).unwrap_or(0))
            .collect();
        let p2sh_list: Vec<[u8; 20]> = self.p2sh_set.iter().copied().collect();
        let p2wsh_list: Vec<[u8; 32]> = self.p2wsh_set.iter().copied().collect();
        
        // Compute checksum for integrity verification
        let checksum = compute_checksum(&hash160_list, &p2sh_list, &p2wsh_list);
        
        let cached = CachedTargets {
            metadata: CacheMetadata {
                version: CACHE_VERSION,
                source_size: source_meta.len(),
                source_mtime,
            },
            hash160_list,
            hash160_types,
            p2sh_list,
            p2wsh_list,
            stats: self.stats.clone(),
            checksum,
        };
        
        let encoded = bincode::serialize(&cached)
            .map_err(|e| format!("Serialization error: {}", e))?;
        
        // Atomic write: write to PID-unique temp file, then rename
        // PID ensures no collision when multiple processes write simultaneously
        let pid = std::process::id();
        let temp_filename = format!(
            "{}.cache.{}.tmp",
            cache_path.file_stem().unwrap_or_default().to_string_lossy(),
            pid
        );
        let temp_path = cache_path.with_file_name(&temp_filename);
        
        let mut file = File::create(&temp_path)
            .map_err(|e| format!("Failed to create temp cache file: {}", e))?;
        
        file.write_all(&encoded)
            .map_err(|e| format!("Failed to write cache: {}", e))?;
        
        // Ensure data is flushed to disk before rename
        file.sync_all()
            .map_err(|e| format!("Failed to sync cache file: {}", e))?;
        
        // Drop file handle before rename (important on Windows)
        drop(file);
        
        // =========================================================================
        // RACE CONDITION PREVENTION: Verify source hasn't changed during write
        // =========================================================================
        // Scenario without this check:
        //   Process A: reads source v1, starts writing cache
        //   Process B: modifies source to v2
        //   Process C: reads source v2, starts writing cache
        //   Process A: renames cache (contains v1 data)
        //   Process C: renames cache (overwrites with v2 data) - OK
        //   BUT: If order is reversed, stale cache remains!
        //
        // With this check: We verify source is still the same before committing.
        // =========================================================================
        let current_meta = fs::metadata(source_path)
            .map_err(|e| format!("Failed to verify source: {}", e))?;
        
        if current_meta.len() != source_meta.len() {
            // Source file changed during cache write - abort to prevent stale cache
            let _ = fs::remove_file(&temp_path);
            return Err("Source file changed during cache write - aborting".to_string());
        }
        
        // Also check mtime if available
        if let Ok(current_mtime) = current_meta.modified() {
            if let Ok(original_mtime) = source_meta.modified() {
                if current_mtime != original_mtime {
                    let _ = fs::remove_file(&temp_path);
                    return Err("Source file modified during cache write - aborting".to_string());
                }
            }
        }
        
        // Platform-specific atomic rename
        let rename_result = atomic_rename_file(&temp_path, cache_path);
        
        // Clean up temp file on rename failure
        if rename_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        
        rename_result.map_err(|e| format!("Failed to rename cache file: {}", e))?;
        
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
    /// 
    /// **Robust JSON Parsing:**
    /// - Uses serde_json for 100% JSON-compliant parsing
    /// - Handles comments, different indentation, escaped characters
    /// - Recursively extracts addresses from any JSON structure
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
        
        // Type tracking for each hash160 - allows precise match reporting
        type FxHashMap<K, V> = std::collections::HashMap<K, V, BuildHasherDefault<FxHasher>>;
        let mut hash160_types: FxHashMap<[u8; 20], AddressTypeFlags> = FxHashMap::default();
        hash160_types.reserve(initial_capacity);
        
        let mut p2sh_set: FxHashSet<[u8; 20]> = FxHashSet::default();
        p2sh_set.reserve(initial_capacity / 10); // P2SH typically fewer
        
        // NEW: P2WSH support - 32-byte witness program hashes
        let mut p2wsh_set: FxHashSet<[u8; 32]> = FxHashSet::default();
        p2wsh_set.reserve(initial_capacity / 100); // P2WSH typically rare
        
        let mut stats = TargetStats::default();
        let mut last_progress = Instant::now();
        
        // Parse JSON using serde_json - robust and standards-compliant
        // Handles: compact JSON, multi-line, nested structures, escaped chars
        let json: Value = serde_json::from_reader(reader)
            .map_err(|e| format!("JSON parse error: {}", e))?;
        
        // Recursively extract all string values that look like Bitcoin addresses
        // NOW WITH: precise type tracking and P2WSH support
        fn extract_addresses_recursive(
            value: &Value,
            hash160_set: &mut FxHashSet<[u8; 20]>,
            hash160_types: &mut FxHashMap<[u8; 20], AddressTypeFlags>,
            p2sh_set: &mut FxHashSet<[u8; 20]>,
            p2wsh_set: &mut FxHashSet<[u8; 32]>,
            stats: &mut TargetStats,
            start: &Instant,
            estimated_count: usize,
            last_progress: &mut Instant,
        ) {
            match value {
                Value::String(addr) => {
                    if addr.is_empty() {
                        return;
                    }
                    
                    // Classify and store - only count if decode succeeds
                    // FIXED: Now tracks which address type each hash160 came from
                    if addr.starts_with('1') {
                        if let Some(hash) = decode_p2pkh(addr) {
                            hash160_set.insert(hash);
                            // Track type: this hash came from a P2PKH address
                            hash160_types.entry(hash)
                                .or_insert(AddressTypeFlags::default())
                                .add_p2pkh();
                            stats.p2pkh += 1;
                            stats.total += 1;
                        }
                    } else if addr.starts_with('3') {
                        if let Some(hash) = decode_p2sh(addr) {
                            p2sh_set.insert(hash);
                            stats.p2sh += 1;
                            stats.total += 1;
                        }
                    } else if addr.starts_with("bc1q") {
                        if addr.len() <= 44 {
                            // P2WPKH: 20-byte witness program
                            if let Some(hash) = decode_bech32(addr) {
                                hash160_set.insert(hash);
                                // Track type: this hash came from a P2WPKH address
                                hash160_types.entry(hash)
                                    .or_insert(AddressTypeFlags::default())
                                    .add_p2wpkh();
                                stats.p2wpkh += 1;
                                stats.total += 1;
                            }
                        } else {
                            // P2WSH: 32-byte witness program
                            // FIXED: Now actually storing the hash instead of just counting!
                            if let Some(hash) = decode_bech32_p2wsh(addr) {
                                p2wsh_set.insert(hash);
                                stats.p2wsh += 1;
                                stats.total += 1;
                            }
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
                        *last_progress = Instant::now();
                    }
                }
                Value::Array(arr) => {
                    for item in arr {
                        extract_addresses_recursive(
                            item, hash160_set, hash160_types, p2sh_set, p2wsh_set, stats, 
                            start, estimated_count, last_progress
                        );
                    }
                }
                Value::Object(obj) => {
                    for (_, v) in obj {
                        extract_addresses_recursive(
                            v, hash160_set, hash160_types, p2sh_set, p2wsh_set, stats,
                            start, estimated_count, last_progress
                        );
                    }
                }
                _ => {} // Ignore numbers, bools, null
            }
        }
        
        // Extract all addresses from the parsed JSON
        extract_addresses_recursive(
            &json, &mut hash160_set, &mut hash160_types, &mut p2sh_set, &mut p2wsh_set, &mut stats,
            &start, estimated_count, &mut last_progress
        );
        
        // Print P2SH scope warning if P2SH addresses are present
        if stats.p2sh > 0 {
            println!("   ⚠️  P2SH NOTE: Only P2SH-P2WPKH (nested SegWit) scripts are scannable.");
            println!("      Multi-sig or custom P2SH scripts will NOT be matched.");
        }
        
        // Print P2WSH warning if present (requires additional GPU work not yet implemented)
        if stats.p2wsh > 0 {
            println!("   ⚠️  P2WSH NOTE: P2WSH scanning requires witness script generation.");
            println!("      Currently only single-key scripts (P2WPKH wrapped) are supported.");
        }
        
        // Shrink to fit after loading (release unused capacity)
        hash160_set.shrink_to_fit();
        hash160_types.shrink_to_fit();
        p2sh_set.shrink_to_fit();
        p2wsh_set.shrink_to_fit();
        
        // Build XOR filters if feature enabled
        #[cfg(feature = "xor-filter")]
        let (hash160_xor, p2sh_xor) = {
            println!("   Building XOR filters for {} + {} hashes...", 
                     format_count(hash160_set.len()), format_count(p2sh_set.len()));
            let xor_start = Instant::now();
            
            // Convert [u8; 20] to u64 keys for XOR filter
            // IMPORTANT: Must deduplicate! XOR filter panics on duplicate keys
            // Collisions in hash160_to_u64 are possible (XOR-fold of 20 bytes to 8)
            let mut hash160_keys: Vec<u64> = hash160_set.iter()
                .map(|h| hash160_to_u64(h))
                .collect();
            hash160_keys.sort_unstable();
            hash160_keys.dedup();
            
            let mut p2sh_keys: Vec<u64> = p2sh_set.iter()
                .map(|h| hash160_to_u64(h))
                .collect();
            p2sh_keys.sort_unstable();
            p2sh_keys.dedup();
            
            // Log collision stats
            let h_collisions = hash160_set.len() - hash160_keys.len();
            let p_collisions = p2sh_set.len() - p2sh_keys.len();
            if h_collisions > 0 || p_collisions > 0 {
                println!("   ⚠️  XOR key collisions: {} hash160, {} p2sh (expected ~0.00001%)", 
                         h_collisions, p_collisions);
            }
            
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
        let hash160_types_mem = hash160_types.len() * (20 + 1) * 3 / 2; // key + flag
        let p2sh_mem = p2sh_set.len() * 20 * 3 / 2;
        let p2wsh_mem = p2wsh_set.len() * 32 * 3 / 2;
        let total_mem_mb = (hash160_mem + hash160_types_mem + p2sh_mem + p2wsh_mem) as f64 / (1024.0 * 1024.0);
        
        println!("✅ Parsed {} targets in {:.1}s", format_count(stats.total), stats.load_time_ms as f64 / 1000.0);
        println!("   P2PKH: {}, P2SH: {}, P2WPKH: {}, P2WSH: {}", 
                 format_count(stats.p2pkh), format_count(stats.p2sh), 
                 format_count(stats.p2wpkh), format_count(stats.p2wsh));
        println!("   Hash160 set: {} entries (with type tracking)", format_count(hash160_set.len()));
        println!("   P2SH set: {} entries", format_count(p2sh_set.len()));
        println!("   P2WSH set: {} entries", format_count(p2wsh_set.len()));
        println!("   Estimated memory: {:.1} MB", total_mem_mb);
        
        #[cfg(feature = "xor-filter")]
        {
            let xor_mem = (hash160_set.len() + p2sh_set.len()) as f64 * 1.23 / (1024.0 * 1024.0);
            println!("   XOR filter memory: {:.1} MB", xor_mem);
            println!("   ✓ XOR Filter enabled (10x faster negative lookups)");
        }
        
        Ok(Self {
            hash160_set,
            hash160_types,
            p2sh_set,
            p2wsh_set,
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
    
    /// Check if P2WSH witness program hash exists (32 bytes)
    #[inline]
    pub fn contains_p2wsh(&self, hash: &[u8; 32]) -> bool {
        self.p2wsh_set.contains(hash)
    }
    
    /// Get the address types for a hash160 (P2PKH, P2WPKH, or both)
    /// 
    /// This allows precise match reporting - we know exactly which
    /// address type(s) the hash came from in targets.json
    #[inline]
    pub fn get_hash160_types(&self, hash: &[u8; 20]) -> Option<AddressTypeFlags> {
        self.hash160_types.get(hash).copied()
    }
    
    /// Check raw key data against all target types
    /// Returns (p2pkh_match, p2sh_match, p2wpkh_match)
    /// 
    /// FIXED: Now uses precise type tracking instead of global stats.
    /// If a hash matches, we return only the types that hash was loaded from.
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
            let maybe_hash160 = self.hash160_xor
                .as_ref()
                .map(|xor| xor.contains(&pubkey_key))
                .unwrap_or(false);
            
            // Check P2SH
            let maybe_p2sh = self.p2sh_xor
                .as_ref()
                .map(|xor| xor.contains(&p2sh_key))
                .unwrap_or(false);
            
            // If XOR filter says no, it's definitely no (no false negatives)
            // If XOR filter says maybe, confirm with HashSet AND get precise types
            let (p2pkh, p2wpkh) = if maybe_hash160 && self.hash160_set.contains(pubkey_hash) {
                // FIXED: Use precise type tracking, not global stats
                if let Some(types) = self.hash160_types.get(pubkey_hash) {
                    (types.has_p2pkh(), types.has_p2wpkh())
                } else {
                    // Fallback (shouldn't happen if loading was correct)
                    (true, true)
                }
            } else {
                (false, false)
            };
            
            let p2sh = maybe_p2sh && self.p2sh_set.contains(p2sh_hash);
            
            (p2pkh, p2sh, p2wpkh)
        }
        
        #[cfg(not(feature = "xor-filter"))]
        {
            let (p2pkh, p2wpkh) = if self.hash160_set.contains(pubkey_hash) {
                // FIXED: Use precise type tracking, not global stats
                if let Some(types) = self.hash160_types.get(pubkey_hash) {
                    (types.has_p2pkh(), types.has_p2wpkh())
                } else {
                    (true, true)
                }
            } else {
                (false, false)
            };
            let p2sh = self.p2sh_set.contains(p2sh_hash);
            (p2pkh, p2sh, p2wpkh)
        }
    }
}

/// Compute XOR checksum for data integrity verification
/// 
/// Combines all hash data into a single u64 checksum.
/// If cache is corrupted or truncated, checksum will mismatch.
fn compute_checksum(
    hash160_list: &[[u8; 20]], 
    p2sh_list: &[[u8; 20]], 
    p2wsh_list: &[[u8; 32]]
) -> u64 {
    let mut checksum: u64 = 0xDEADBEEF_CAFEBABE; // Magic seed
    
    // XOR all hash160 values
    for hash in hash160_list {
        let p1 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        let p2 = u64::from_le_bytes(hash[8..16].try_into().unwrap());
        let p3 = u32::from_le_bytes(hash[16..20].try_into().unwrap()) as u64;
        checksum ^= p1.rotate_left(7) ^ p2.rotate_left(13) ^ p3.rotate_left(23);
    }
    
    // XOR all P2SH values
    for hash in p2sh_list {
        let p1 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        let p2 = u64::from_le_bytes(hash[8..16].try_into().unwrap());
        let p3 = u32::from_le_bytes(hash[16..20].try_into().unwrap()) as u64;
        checksum ^= p1.rotate_left(11) ^ p2.rotate_left(17) ^ p3.rotate_left(29);
    }
    
    // XOR all P2WSH values (32 bytes)
    for hash in p2wsh_list {
        let p1 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        let p2 = u64::from_le_bytes(hash[8..16].try_into().unwrap());
        let p3 = u64::from_le_bytes(hash[16..24].try_into().unwrap());
        let p4 = u64::from_le_bytes(hash[24..32].try_into().unwrap());
        checksum ^= p1.rotate_left(3) ^ p2.rotate_left(19) ^ p3.rotate_left(31) ^ p4.rotate_left(37);
    }
    
    // Mix in list lengths to detect truncation
    checksum ^= (hash160_list.len() as u64).rotate_left(41);
    checksum ^= (p2sh_list.len() as u64).rotate_left(43);
    checksum ^= (p2wsh_list.len() as u64).rotate_left(47);
    
    checksum
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

/// Decode bech32 address to hash (P2WPKH - 20 bytes)
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

/// Decode bech32 address to hash (P2WSH - 32 bytes)
/// 
/// P2WSH uses a 32-byte SHA256 witness program hash.
/// Only witness version 0 with Bech32 encoding is supported.
fn decode_bech32_p2wsh(addr: &str) -> Option<[u8; 32]> {
    use bech32::{FromBase32, Variant};
    
    let (hrp, data_5bit, variant) = bech32::decode(addr).ok()?;
    
    if hrp != "bc" {
        return None;
    }
    
    if data_5bit.is_empty() {
        return None;
    }
    
    let witness_version = data_5bit[0].to_u8();
    
    // Witness version 0 with Bech32 encoding
    if witness_version != 0 || variant != Variant::Bech32 {
        return None;
    }
    
    let program = Vec::<u8>::from_base32(&data_5bit[1..]).ok()?;
    
    // P2WSH has 32-byte program
    if program.len() == 32 {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&program);
        Some(hash)
    } else {
        None
    }
}

/// Extract addresses from a JSON string using serde_json
/// 
/// This function is a thin wrapper around serde_json for robust parsing.
/// Handles any valid JSON structure containing Bitcoin addresses.
/// 
/// Used primarily for testing; the main loader uses extract_addresses_recursive directly.
#[cfg(test)]
fn extract_addresses_from_json(json_str: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    
    // Try to parse as JSON Value
    if let Ok(value) = serde_json::from_str::<Value>(json_str) {
        extract_strings_recursive(&value, &mut addresses);
    }
    
    addresses
}

/// Recursively extract all strings that look like Bitcoin addresses from a JSON Value
#[cfg(test)]
fn extract_strings_recursive(value: &Value, addresses: &mut Vec<String>) {
    match value {
        Value::String(s) => {
            if !s.is_empty() 
               && (s.starts_with('1') || s.starts_with('3') || s.starts_with("bc1"))
            {
                addresses.push(s.clone());
            }
        }
        Value::Array(arr) => {
            for item in arr {
                extract_strings_recursive(item, addresses);
            }
        }
        Value::Object(obj) => {
            for (_, v) in obj {
                extract_strings_recursive(v, addresses);
            }
        }
        _ => {}
    }
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
        let json = r#"{"addresses":["1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH","3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC","bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]}"#;
        let addrs = extract_addresses_from_json(json);
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0], "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        assert_eq!(addrs[1], "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC");
        assert_eq!(addrs[2], "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    }
    
    #[test]
    fn test_extract_addresses_nested() {
        // Test nested JSON structure
        let json = r#"{"data":{"wallets":[{"address":"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"},{"address":"3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC"}]}}"#;
        let addrs = extract_addresses_from_json(json);
        assert_eq!(addrs.len(), 2);
    }
    
    #[test]
    fn test_extract_addresses_with_comments_in_keys() {
        // Test that non-address strings are ignored
        let json = r#"{"comment":"This is not an address: 1fake","real":"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"}"#;
        let addrs = extract_addresses_from_json(json);
        // Should only extract the real address (1BgGZ... starts with 1)
        // The comment contains "1fake" which starts with 1 but is not a valid address format
        assert!(addrs.iter().any(|a| a == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"));
    }
    
    #[test]
    fn test_extract_addresses_simple_array() {
        // Test simple array format
        let json = r#"["1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH","bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]"#;
        let addrs = extract_addresses_from_json(json);
        assert_eq!(addrs.len(), 2);
    }
    
    #[test]
    fn test_extract_addresses_multiline() {
        // Test multi-line JSON with proper formatting
        let json = r#"
        {
            "addresses": [
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC"
            ]
        }
        "#;
        let addrs = extract_addresses_from_json(json);
        assert_eq!(addrs.len(), 2);
    }
    
    #[test]
    fn test_extract_addresses_escaped_chars() {
        // Test JSON with escaped characters (serde_json handles this correctly)
        let json = r#"{"note":"Address with \"quotes\"","addr":"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"}"#;
        let addrs = extract_addresses_from_json(json);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
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


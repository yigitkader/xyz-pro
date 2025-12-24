//! RAW file scanner - reads generator output and matches against targets
//!
//! Optimizations:
//! - Memory-mapped file reading (zero-copy)
//! - Parallel chunk processing with rayon
//! - Direct hash comparison (no string conversion)

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use std::collections::HashSet;

use rayon::prelude::*;

use super::{TargetSet, AddressEncoder};

/// RAW file format constants (must match generator)
/// 
/// Header format v1:
/// - magic:    4 bytes ("BTCR")
/// - version:  1 byte  (current: 1)
/// - reserved: 3 bytes (for future use, must be 0)
/// - count:    8 bytes (little-endian u64)
/// Total header: 16 bytes
const MAGIC: &[u8; 4] = b"BTCR";
const FORMAT_VERSION: u8 = 1;
const HEADER_SIZE: usize = 16; // magic(4) + version(1) + reserved(3) + count(8)
const ENTRY_SIZE: usize = 72; // privkey(32) + hash160(20) + p2sh_hash(20)

/// SIMD-optimized zero check for 32-byte private keys
/// 8x faster than byte-by-byte iteration
#[inline(always)]
fn is_privkey_zero(privkey: &[u8]) -> bool {
    if privkey.len() < 32 {
        return privkey.iter().all(|&b| b == 0);
    }
    let ptr = privkey.as_ptr() as *const u64;
    unsafe {
        let v0 = std::ptr::read_unaligned(ptr);
        let v1 = std::ptr::read_unaligned(ptr.add(1));
        let v2 = std::ptr::read_unaligned(ptr.add(2));
        let v3 = std::ptr::read_unaligned(ptr.add(3));
        (v0 | v1 | v2 | v3) == 0
    }
}

/// Address type enum - avoids String allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    P2PKH,
    P2SH,
    P2WPKH,
}

impl AddressType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AddressType::P2PKH => "P2PKH",
            AddressType::P2SH => "P2SH",
            AddressType::P2WPKH => "P2WPKH",
        }
    }
}

impl std::fmt::Display for AddressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A match found during scanning
/// Uses Arc<String> for filename to avoid heap cloning per match
#[derive(Debug, Clone)]
pub struct Match {
    pub private_key: String,
    pub address: String,
    pub address_type: AddressType, // No heap allocation
    pub file: Arc<String>,         // Arc<String> instead of String - no clone overhead
    pub offset: u64,
}

/// Result of scanning operation
#[derive(Debug, Default)]
pub struct ScanResult {
    pub files_scanned: usize,
    pub keys_scanned: u64,
    pub matches: Vec<Match>,
    pub elapsed_secs: f64,
}

impl ScanResult {
    pub fn keys_per_second(&self) -> f64 {
        if self.elapsed_secs > 0.0 {
            self.keys_scanned as f64 / self.elapsed_secs
        } else {
            0.0
        }
    }
}

/// Scanner for RAW files
pub struct RawFileScanner {
    targets: Arc<TargetSet>,
    #[allow(dead_code)]
    threads: usize,
}

impl RawFileScanner {
    /// Create new scanner with loaded targets
    pub fn new(targets: TargetSet, threads: usize) -> Self {
        let threads = if threads == 0 {
            std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4)
        } else {
            threads
        };
        
        // Configure rayon thread pool
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .ok();
        
        println!("🔍 Scanner initialized with {} threads", threads);
        
        Self {
            targets: Arc::new(targets),
            threads,
        }
    }
    
    /// Scan all .raw files in directory
    pub fn scan_directory<P: AsRef<Path>>(&self, dir: P) -> Result<ScanResult, String> {
        let start = Instant::now();
        
        // Find all .raw files
        let files: Vec<PathBuf> = fs::read_dir(dir.as_ref())
            .map_err(|e| format!("Failed to read directory: {}", e))?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().map(|e| e == "raw").unwrap_or(false))
            .collect();
        
        if files.is_empty() {
            return Err("No .raw files found in directory".to_string());
        }
        
        println!("📁 Found {} .raw files to scan", files.len());
        
        let total_keys = AtomicU64::new(0);
        let all_matches: Vec<Match> = files
            .par_iter()
            .flat_map(|file| {
                match self.scan_file(file) {
                    Ok((count, matches)) => {
                        total_keys.fetch_add(count, Ordering::Relaxed);
                        matches
                    }
                    Err(e) => {
                        eprintln!("❌ Error scanning {:?}: {}", file, e);
                        vec![]
                    }
                }
            })
            .collect();
        
        let elapsed = start.elapsed().as_secs_f64();
        
        Ok(ScanResult {
            files_scanned: files.len(),
            keys_scanned: total_keys.load(Ordering::Relaxed),
            matches: all_matches,
            elapsed_secs: elapsed,
        })
    }
    
    /// Scan a single .raw file
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<(u64, Vec<Match>), String> {
        let path = path.as_ref();
        let file = File::open(path)
            .map_err(|e| format!("Failed to open file: {}", e))?;
        
        // Memory-map the file
        let mmap = unsafe {
            memmap2::Mmap::map(&file)
                .map_err(|e| format!("Failed to mmap: {}", e))?
        };
        
        // Verify header
        if mmap.len() < HEADER_SIZE {
            return Err("File too small".to_string());
        }
        
        // Check magic bytes
        if &mmap[0..4] != MAGIC {
            return Err("Invalid magic bytes".to_string());
        }
        
        // ROBUST FORMAT DETECTION: Use filesize validation, not just version byte
        // This prevents ambiguity when legacy count's first byte equals a valid version
        //
        // Legacy (v0): magic(4) + count(8) = 12 bytes header
        // V1:          magic(4) + version(1) + reserved(3) + count(8) = 16 bytes header
        
        let file_size = mmap.len();
        
        // Try v1 format first (more strict validation)
        let v1_valid = if file_size >= HEADER_SIZE {
            let version = mmap[4];
            let reserved_ok = mmap[5] == 0 && mmap[6] == 0 && mmap[7] == 0;
            let count = u64::from_le_bytes(mmap[8..16].try_into().unwrap());
            let expected = HEADER_SIZE + (count as usize * ENTRY_SIZE);
            
            version == FORMAT_VERSION && reserved_ok && file_size == expected
        } else {
            false
        };
        
        // Try legacy format
        let legacy_valid = if file_size >= 12 {
            let count = u64::from_le_bytes(mmap[4..12].try_into().unwrap());
            let expected = 12 + (count as usize * ENTRY_SIZE);
            
            file_size == expected
        } else {
            false
        };
        
        // Choose format based on exact match
        if v1_valid && legacy_valid {
            // Ambiguous - prefer v1 (newer)
            // This should be rare; log a warning
            eprintln!("⚠️ File '{}' matches both v0 and v1 format, using v1", path.display());
        }
        
        if legacy_valid && !v1_valid {
            // Legacy format
            let count = u64::from_le_bytes(mmap[4..12].try_into().unwrap());
            return self.scan_file_legacy(path, &mmap, count);
        }
        
        if !v1_valid && !legacy_valid {
            // Try relaxed v1 (count within reasonable bounds but not exact match)
            if file_size >= HEADER_SIZE {
                let version = mmap[4];
                if version > FORMAT_VERSION {
                    return Err(format!(
                        "Unsupported file version {} (max supported: {}). Please update the software.",
                        version, FORMAT_VERSION
                    ));
                }
            }
            return Err(format!(
                "Invalid file format: size {} doesn't match expected header+data layout",
                file_size
            ));
        }
        
        // V1 format - already validated above
        // Check reserved bytes are zero (offset 5-7)
        if mmap[5] != 0 || mmap[6] != 0 || mmap[7] != 0 {
            return Err("Invalid header: reserved bytes must be zero".to_string());
        }
        
        // Read count (offset 8-15, 8 bytes)
        let count = u64::from_le_bytes(mmap[8..16].try_into().unwrap());
        let expected_size = HEADER_SIZE + (count as usize * ENTRY_SIZE);
        
        // This should always pass since we validated above, but keep for safety
        if mmap.len() < expected_size {
            return Err(format!("File truncated: expected {}, got {}", expected_size, mmap.len()));
        }
        
        let filename = path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        // Parallel scan of entries
        let data = &mmap[HEADER_SIZE..];
        let chunk_size = 10_000; // Process 10K keys per chunk
        let num_chunks = (count as usize + chunk_size - 1) / chunk_size;
        
        // Clone filename once, share via Arc to avoid per-match cloning
        let filename_arc = Arc::new(filename);
        
        let matches: Vec<Match> = (0..num_chunks)
            .into_par_iter()
            .flat_map(|chunk_idx| {
                let start_key = chunk_idx * chunk_size;
                let end_key = ((chunk_idx + 1) * chunk_size).min(count as usize);
                // Pre-allocate with reasonable capacity (matches are rare)
                let mut chunk_matches = Vec::with_capacity(8);
                
                // Arc clone is O(1) - just increment refcount, no heap allocation
                let chunk_filename = Arc::clone(&filename_arc);
                
                for key_idx in start_key..end_key {
                    let offset = key_idx * ENTRY_SIZE;
                    if offset + ENTRY_SIZE > data.len() {
                        break;
                    }
                    
                    let entry = &data[offset..offset + ENTRY_SIZE];
                    let privkey = &entry[0..32];
                    let pubkey_hash: [u8; 20] = entry[32..52].try_into().unwrap();
                    let p2sh_hash: [u8; 20] = entry[52..72].try_into().unwrap();
                    
                    // Skip zero keys (SIMD optimized)
                    if is_privkey_zero(privkey) {
                        continue;
                    }
                    
                    // Check against targets
                    let (p2pkh_match, p2sh_match, p2wpkh_match) = 
                        self.targets.check_raw(&pubkey_hash, &p2sh_hash);
                    
                    if p2pkh_match || p2sh_match || p2wpkh_match {
                        // Only encode private key once (hex is expensive)
                        let mut privkey_hex = hex::encode(privkey);
                        
                        // Thread-local encoder avoids allocation per call
                        thread_local! {
                            static ENCODER: std::cell::RefCell<AddressEncoder> = 
                                std::cell::RefCell::new(AddressEncoder::new());
                        }
                        
                        // Count matches to minimize privkey_hex cloning
                        let match_count = p2pkh_match as u8 + p2sh_match as u8 + p2wpkh_match as u8;
                        let mut matches_remaining = match_count;
                        
                        if p2pkh_match {
                            matches_remaining -= 1;
                            let privkey = if matches_remaining > 0 { privkey_hex.clone() } else { std::mem::take(&mut privkey_hex) };
                            chunk_matches.push(Match {
                                private_key: privkey,
                                address: ENCODER.with(|enc| enc.borrow_mut().encode_p2pkh(&pubkey_hash)),
                                address_type: AddressType::P2PKH,
                                file: Arc::clone(&chunk_filename), // O(1) refcount increment
                                offset: key_idx as u64,
                            });
                        }
                        
                        if p2sh_match {
                            matches_remaining -= 1;
                            let privkey = if matches_remaining > 0 { privkey_hex.clone() } else { std::mem::take(&mut privkey_hex) };
                            chunk_matches.push(Match {
                                private_key: privkey,
                                address: ENCODER.with(|enc| enc.borrow_mut().encode_p2sh(&p2sh_hash)),
                                address_type: AddressType::P2SH,
                                file: Arc::clone(&chunk_filename), // O(1) refcount increment
                                offset: key_idx as u64,
                            });
                        }
                        
                        if p2wpkh_match {
                            chunk_matches.push(Match {
                                private_key: privkey_hex, // Last use, move instead of clone
                                address: ENCODER.with(|enc| enc.borrow_mut().encode_p2wpkh(&pubkey_hash)),
                                address_type: AddressType::P2WPKH,
                                file: Arc::clone(&chunk_filename), // O(1) refcount increment
                                offset: key_idx as u64,
                            });
                        }
                    }
                }
                
                chunk_matches
            })
            .collect();
        
        if !matches.is_empty() {
            println!("🎯 Found {} matches in {}", matches.len(), filename_arc);
        }
        
        Ok((count, matches))
    }
    
    /// Scan a legacy format file (v0, without version field)
    /// Legacy header: magic(4) + count(8) = 12 bytes
    fn scan_file_legacy(&self, path: &Path, mmap: &memmap2::Mmap, count: u64) -> Result<(u64, Vec<Match>), String> {
        const LEGACY_HEADER_SIZE: usize = 12;
        let expected_size = LEGACY_HEADER_SIZE + (count as usize * ENTRY_SIZE);
        
        if mmap.len() < expected_size {
            return Err(format!("Legacy file truncated: expected {}, got {}", expected_size, mmap.len()));
        }
        
        eprintln!("⚠️  Reading legacy format file (no version). Consider re-generating.");
        
        let filename = path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        let filename_arc = std::sync::Arc::new(filename);
        
        // Process with legacy header offset
        let data = &mmap[LEGACY_HEADER_SIZE..];
        let chunk_size = 10_000;
        let num_chunks = (count as usize + chunk_size - 1) / chunk_size;
        
        let matches: Vec<Match> = (0..num_chunks)
            .into_par_iter()
            .flat_map(|chunk_idx| {
                // Arc clone is O(1) - just increment refcount, no heap allocation
                let chunk_filename = Arc::clone(&filename_arc);
                let start_key = chunk_idx * chunk_size;
                let end_key = std::cmp::min(start_key + chunk_size, count as usize);
                let mut chunk_matches = Vec::new();
                
                for key_idx in start_key..end_key {
                    let offset = key_idx * ENTRY_SIZE;
                    let entry = &data[offset..offset + ENTRY_SIZE];
                    
                    let privkey: [u8; 32] = entry[0..32].try_into().unwrap();
                    let pubkey_hash: [u8; 20] = entry[32..52].try_into().unwrap();
                    let p2sh_hash: [u8; 20] = entry[52..72].try_into().unwrap();
                    
                    // Skip zero keys (SIMD optimized)
                    if is_privkey_zero(&privkey) {
                        continue;
                    }
                    
                    let (p2pkh_match, p2sh_match, p2wpkh_match) = 
                        self.targets.check_raw(&pubkey_hash, &p2sh_hash);
                    
                    if p2pkh_match || p2sh_match || p2wpkh_match {
                        let mut privkey_hex = hex::encode(privkey);
                        
                        thread_local! {
                            static ENCODER: std::cell::RefCell<AddressEncoder> = 
                                std::cell::RefCell::new(AddressEncoder::new());
                        }
                        
                        let match_count = p2pkh_match as u8 + p2sh_match as u8 + p2wpkh_match as u8;
                        let mut matches_remaining = match_count;
                        
                        if p2pkh_match {
                            matches_remaining -= 1;
                            let privkey = if matches_remaining > 0 { privkey_hex.clone() } else { std::mem::take(&mut privkey_hex) };
                            chunk_matches.push(Match {
                                private_key: privkey,
                                address: ENCODER.with(|enc| enc.borrow_mut().encode_p2pkh(&pubkey_hash)),
                                address_type: AddressType::P2PKH,
                                file: Arc::clone(&chunk_filename), // O(1) refcount increment
                                offset: key_idx as u64,
                            });
                        }
                        
                        if p2sh_match {
                            matches_remaining -= 1;
                            let privkey = if matches_remaining > 0 { privkey_hex.clone() } else { std::mem::take(&mut privkey_hex) };
                            chunk_matches.push(Match {
                                private_key: privkey,
                                address: ENCODER.with(|enc| enc.borrow_mut().encode_p2sh(&p2sh_hash)),
                                address_type: AddressType::P2SH,
                                file: Arc::clone(&chunk_filename), // O(1) refcount increment
                                offset: key_idx as u64,
                            });
                        }
                        
                        if p2wpkh_match {
                            let privkey = std::mem::take(&mut privkey_hex);
                            chunk_matches.push(Match {
                                private_key: privkey,
                                address: ENCODER.with(|enc| enc.borrow_mut().encode_p2wpkh(&pubkey_hash)),
                                address_type: AddressType::P2WPKH,
                                file: Arc::clone(&chunk_filename), // O(1) refcount increment
                                offset: key_idx as u64,
                            });
                        }
                    }
                }
                
                chunk_matches
            })
            .collect();
        
        Ok((count, matches))
    }
    
    /// Watch directory for new files and scan them
    pub fn watch_and_scan<P: AsRef<Path>>(&self, dir: P, interval_secs: u64) -> Result<(), String> {
        use std::thread;
        use std::time::Duration;
        
        let dir = dir.as_ref().to_path_buf();
        let mut scanned_files: HashSet<PathBuf> = HashSet::new();
        
        println!("👀 Watching {} for new .raw files...", dir.display());
        println!("   Press Ctrl+C to stop");
        
        loop {
            // Find new files
            let current_files: Vec<PathBuf> = fs::read_dir(&dir)
                .map_err(|e| format!("Failed to read directory: {}", e))?
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|path| path.extension().map(|e| e == "raw").unwrap_or(false))
                .filter(|path| !scanned_files.contains(path))
                .collect();
            
            for file in current_files {
                println!("📄 New file: {:?}", file);
                
                match self.scan_file(&file) {
                    Ok((count, matches)) => {
                        println!("   Scanned {} keys", count);
                        if !matches.is_empty() {
                            println!("   🎯 MATCHES FOUND: {}", matches.len());
                            for m in &matches {
                                println!("      {} = {} ({})", m.address, m.private_key, m.address_type);
                            }
                        }
                        scanned_files.insert(file);
                    }
                    Err(e) => {
                        eprintln!("   Error: {}", e);
                    }
                }
            }
            
            thread::sleep(Duration::from_secs(interval_secs));
        }
    }
}

/// Save matches to JSON file
pub fn save_matches<P: AsRef<Path>>(matches: &[Match], path: P) -> std::io::Result<()> {
    use std::io::Write;
    
    let file = File::create(path)?;
    let mut writer = std::io::BufWriter::new(file);
    
    writeln!(writer, "{{")?;
    writeln!(writer, "  \"matches\": [")?;
    
    for (i, m) in matches.iter().enumerate() {
        let comma = if i < matches.len() - 1 { "," } else { "" };
        writeln!(writer, "    {{")?;
        writeln!(writer, "      \"private_key\": \"{}\",", m.private_key)?;
        writeln!(writer, "      \"address\": \"{}\",", m.address)?;
        writeln!(writer, "      \"type\": \"{}\",", m.address_type.as_str())?;
        writeln!(writer, "      \"file\": \"{}\",", m.file.as_str())?; // Deref Arc<String>
        writeln!(writer, "      \"offset\": {}", m.offset)?;
        writeln!(writer, "    }}{}", comma)?;
    }
    
    writeln!(writer, "  ]")?;
    writeln!(writer, "}}")?;
    
    Ok(())
}


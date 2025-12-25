//! Trait Definitions for Bridge
//!
//! These traits define the interface between Generator and Reader.
//! Implementation details are hidden behind these abstractions.

use super::{KeyBatch, Match};

/// Key Generator Trait
/// 
/// Any key generator (GPU, CPU, etc.) must implement this trait.
/// The bridge uses this to generate batches without knowing implementation details.
pub trait KeyGenerator: Send + Sync {
    /// Get the number of keys per batch
    fn batch_size(&self) -> usize;
    
    /// Generate the next batch of keys
    /// Returns a raw byte slice from the internal buffer
    /// The returned slice is valid until the next call to generate_batch
    fn generate_batch(&self) -> Result<&[u8], String>;
    
    /// Get the current key offset
    fn current_offset(&self) -> u64;
    
    /// Check if generator should stop
    fn should_stop(&self) -> bool;
    
    /// Signal the generator to stop
    fn stop(&self);
    
    /// Get total keys generated so far
    fn total_generated(&self) -> u64;
    
    /// Check if the configured range has been completely scanned
    /// Returns true if end_offset is set AND current_offset >= end_offset
    /// This prevents wrap-around when scanning specific ranges (e.g., Bitcoin Puzzles)
    fn is_range_complete(&self) -> bool {
        false // Default: no range limit
    }
    
    /// Get the end offset if configured
    fn end_offset(&self) -> Option<u64> {
        None // Default: no limit
    }
    
    /// Get progress percentage (0.0 to 100.0) if end_offset is configured
    fn progress_percent(&self) -> Option<f64> {
        None // Default: unknown progress
    }
    
    /// Get the pipeline depth (number of batches dispatched ahead)
    /// 
    /// This is used for draining the pipeline when range scanning completes.
    /// When `is_range_complete()` returns true, there may still be `pipeline_depth - 1`
    /// batches waiting in the GPU pipeline that need to be processed.
    /// 
    /// Default: 1 (no pipelining, each generate_batch is synchronous)
    fn pipeline_depth(&self) -> usize {
        1
    }
    
    /// Drain a single buffer from the pipeline WITHOUT dispatching new work
    /// 
    /// CRITICAL for range scanning: When the range is complete, we must retrieve
    /// remaining batches that are already computed in the GPU pipeline, but we
    /// must NOT dispatch new work (which would scan beyond the range).
    /// 
    /// This method:
    /// 1. Waits for GPU completion on the specified buffer
    /// 2. Reads the computed key data
    /// 3. Does NOT dispatch new work to the buffer
    /// 
    /// Default implementation falls back to generate_batch() for backwards compatibility,
    /// but optimized implementations should override this to avoid unnecessary dispatch.
    /// 
    /// Returns the raw key data from the drained buffer, or error if drain fails.
    fn drain_buffer(&self, _buffer_idx: usize) -> Result<&[u8], String> {
        // Default: fall back to generate_batch for compatibility
        // This may dispatch new work, but range-complete generators should handle this
        self.generate_batch()
    }
}

/// Matcher Trait
/// 
/// Any matcher (HashSet, Bloom filter, etc.) must implement this trait.
/// The bridge uses this to check batches without knowing implementation details.
pub trait Matcher: Send + Sync {
    /// Check a key batch for matches
    /// Returns all matching keys
    fn check_batch(&self, batch: &KeyBatch) -> Vec<Match>;
    
    /// Check a single raw key data
    /// Returns matches if found
    fn check_key(&self, pubkey_hash: &[u8; 20], p2sh_hash: &[u8; 20]) -> Vec<super::MatchType>;
    
    /// Get the total number of targets
    fn target_count(&self) -> usize;
    
    /// Get statistics about loaded targets
    fn stats(&self) -> MatcherStats;
}

/// Matcher statistics
#[derive(Debug, Clone, Default)]
pub struct MatcherStats {
    pub total: usize,
    pub p2pkh: usize,
    pub p2sh: usize,
    pub p2wpkh: usize,
}

/// Match Output Trait
/// 
/// Handles what happens when a match is found.
/// Could write to file, database, send notification, etc.
pub trait MatchOutput: Send + Sync {
    /// Called when matches are found
    fn on_matches(&self, matches: &[Match]) -> Result<(), String>;
    
    /// Flush any buffered output
    fn flush(&self) -> Result<(), String>;
    
    /// Get total matches recorded
    fn total_matches(&self) -> u64;
}

// ============================================================================
// Default Implementations
// ============================================================================

/// Console output - prints matches to stdout
pub struct ConsoleOutput {
    count: std::sync::atomic::AtomicU64,
}

impl ConsoleOutput {
    pub fn new() -> Self {
        Self {
            count: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl Default for ConsoleOutput {
    fn default() -> Self {
        Self::new()
    }
}

impl MatchOutput for ConsoleOutput {
    fn on_matches(&self, matches: &[Match]) -> Result<(), String> {
        for m in matches {
            println!("{}", m.to_string_detailed());
        }
        self.count.fetch_add(matches.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    
    fn flush(&self) -> Result<(), String> {
        Ok(())
    }
    
    fn total_matches(&self) -> u64 {
        self.count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// File output - writes matches to a file
/// Uses unbuffered writes to ensure no data loss
pub struct FileOutput {
    path: std::path::PathBuf,
    file: std::sync::Mutex<std::fs::File>,
    count: std::sync::atomic::AtomicU64,
}

impl FileOutput {
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> Result<Self, String> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .map_err(|e| format!("Failed to open output file: {}", e))?;
        
        Ok(Self {
            path: path.as_ref().to_path_buf(),
            file: std::sync::Mutex::new(file),
            count: std::sync::atomic::AtomicU64::new(0),
        })
    }
    
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl MatchOutput for FileOutput {
    fn on_matches(&self, matches: &[Match]) -> Result<(), String> {
        use std::io::Write;
        
        let mut file = self.file.lock().map_err(|e| format!("Lock error: {}", e))?;
        
        for m in matches {
            writeln!(file, "{}", m.to_string_detailed())
                .map_err(|e| format!("Write error: {}", e))?;
        }
        
        // CRITICAL: sync_all forces write to physical disk - no data loss!
        file.sync_all().map_err(|e| format!("Sync error: {}", e))?;
        
        self.count.fetch_add(matches.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    
    fn flush(&self) -> Result<(), String> {
        let file = self.file.lock().map_err(|e| format!("Lock error: {}", e))?;
        file.sync_all().map_err(|e| format!("Sync error: {}", e))
    }
    
    fn total_matches(&self) -> u64 {
        self.count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Combined output - writes to both console and file
pub struct CombinedOutput {
    console: ConsoleOutput,
    file: FileOutput,
}

impl CombinedOutput {
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> Result<Self, String> {
        Ok(Self {
            console: ConsoleOutput::new(),
            file: FileOutput::new(path)?,
        })
    }
}

impl MatchOutput for CombinedOutput {
    fn on_matches(&self, matches: &[Match]) -> Result<(), String> {
        self.console.on_matches(matches)?;
        self.file.on_matches(matches)?;
        Ok(())
    }
    
    fn flush(&self) -> Result<(), String> {
        self.file.flush()
    }
    
    fn total_matches(&self) -> u64 {
        self.file.total_matches()
    }
}


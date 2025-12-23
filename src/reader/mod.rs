//! High-Performance Bitcoin Address Reader & Matcher
//!
//! Standalone module that reads generated keys and matches against targets.
//! Designed to run independently from the generator for maximum throughput.
//!
//! Architecture:
//! - Generator: Produces keys at max speed → writes to disk
//! - Reader: Reads from disk → matches against targets
//!
//! Optimizations:
//! - Memory-mapped file reading
//! - HashSet with O(1) lookups
//! - Parallel processing with rayon
//! - Zero-copy address matching
//!
//! ## Bridge Integration
//! 
//! Use `TargetMatcher` to integrate with the bridge pipeline:
//! ```ignore
//! use xyz_pro::reader::{TargetSet, TargetMatcher};
//! use xyz_pro::bridge::Matcher;
//! 
//! let matcher = TargetMatcher::load("targets.json")?;
//! // Now 'matcher' implements Matcher trait
//! ```

mod targets;
mod scanner;
mod encoder;
mod adapter;

pub use targets::{TargetSet, TargetStats};
pub use scanner::{RawFileScanner, ScanResult, Match, save_matches};
pub use encoder::AddressEncoder;
pub use adapter::{TargetMatcher, ParallelMatcher};

/// Configuration for the reader
#[derive(Debug, Clone)]
pub struct ReaderConfig {
    /// Path to targets.json
    pub targets_path: String,
    /// Directory containing .raw files
    pub input_dir: String,
    /// Number of threads (0 = auto)
    pub threads: usize,
    /// Output file for matches
    pub output_path: String,
}

impl Default for ReaderConfig {
    fn default() -> Self {
        Self {
            targets_path: "targets.json".to_string(),
            input_dir: "./output".to_string(),
            threads: 0,
            output_path: "matches.json".to_string(),
        }
    }
}


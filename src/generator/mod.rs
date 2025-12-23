//! High-Performance Bitcoin Key Generator
//! 
//! Standalone module for generating BTC private keys with addresses.
//! Target: 1 billion keys per minute.
//! 
//! Features:
//! - GPU-accelerated with Metal (GLV Endomorphism for 2x throughput)
//! - CPU fallback with parallel processing
//! - Multiple output formats (JSON, Binary, Raw)
//! 
//! Supports:
//! - P2PKH (Legacy)
//! - P2SH (Nested SegWit)
//! - P2WPKH (Native SegWit - Bech32)
//!
//! ## Bridge Integration
//! 
//! Use `GpuGeneratorAdapter` to integrate with the bridge pipeline:
//! ```ignore
//! use xyz_pro::generator::{GpuKeyGenerator, GpuGeneratorAdapter, GeneratorConfig};
//! use xyz_pro::bridge::KeyGenerator;
//! 
//! let config = GeneratorConfig::default();
//! let gpu_gen = GpuKeyGenerator::new(config)?;
//! let adapter = GpuGeneratorAdapter::new(gpu_gen);
//! // Now 'adapter' implements KeyGenerator trait
//! ```

mod keygen;
mod encoder;
mod writer;
mod batch;
mod gpu;
mod adapter;

pub use keygen::KeyGenerator as CpuKeyGenerator;
pub use encoder::AddressEncoder;
pub use writer::{OutputWriter, OutputFormat, AsyncRawWriter};
pub use batch::BatchProcessor;
pub use gpu::{GpuKeyGenerator, BufferSet};
pub use adapter::{GpuGeneratorAdapter, DirectBufferAdapter};

use serde::{Deserialize, Serialize};

/// Single key entry with all address types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub private_key: String,
    #[serde(rename = "P2PKH")]
    pub p2pkh: String,
    #[serde(rename = "P2SH")]
    pub p2sh: String,
    #[serde(rename = "P2WPKH")]
    pub p2wpkh: String,
}

/// Output JSON structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyOutput {
    pub private_keys: Vec<KeyEntry>,
}

/// Raw key data for internal processing (minimal allocations)
#[derive(Clone, Copy)]
pub struct RawKeyData {
    pub private_key: [u8; 32],
    pub pubkey_hash: [u8; 20],
}

/// Generator configuration
#[derive(Debug, Clone)]
pub struct GeneratorConfig {
    /// Batch size for parallel processing
    pub batch_size: usize,
    /// Number of worker threads (0 = auto-detect)
    pub threads: usize,
    /// Output format
    pub output_format: OutputFormat,
    /// Output directory
    pub output_dir: String,
    /// Keys per file (1 billion default)
    pub keys_per_file: u64,
    /// Starting offset for private keys (optional)
    pub start_offset: u64,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            batch_size: 100_000,
            threads: 0,
            output_format: OutputFormat::Json,
            output_dir: "./output".to_string(),
            keys_per_file: 1_000_000_000,
            start_offset: 1, // Start from 1 (0 is invalid private key)
        }
    }
}

/// Statistics for monitoring
#[derive(Debug, Default)]
pub struct GeneratorStats {
    pub total_generated: u64,
    pub duplicates_skipped: u64,
    pub files_written: u64,
    pub elapsed_secs: f64,
}

impl GeneratorStats {
    pub fn keys_per_second(&self) -> f64 {
        if self.elapsed_secs > 0.0 {
            self.total_generated as f64 / self.elapsed_secs
        } else {
            0.0
        }
    }
    
    pub fn keys_per_minute(&self) -> f64 {
        self.keys_per_second() * 60.0
    }
}


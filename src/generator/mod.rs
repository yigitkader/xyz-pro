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
//! ```no_run
//! use xyz_pro::generator::{GpuKeyGenerator, GpuGeneratorAdapter, GeneratorConfig};
//! use xyz_pro::bridge::KeyGenerator;
//! 
//! fn main() -> Result<(), String> {
//!     let config = GeneratorConfig::default();
//!     let gpu_gen = GpuKeyGenerator::new(config)?;
//!     let adapter = GpuGeneratorAdapter::new(gpu_gen);
//!     println!("Batch size: {}", adapter.batch_size());
//!     Ok(())
//! }
//! ```

mod keygen;
mod encoder;
mod writer;
mod batch;
mod gpu;
mod adapter;

pub use keygen::KeyGenerator as CpuKeyGenerator;
pub use encoder::AddressEncoder;
// Singleton encoder functions (preferred API - zero allocation)
pub use encoder::{encode_key, encode_p2pkh, encode_p2sh, encode_p2wpkh};
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
/// Layout must match GPU output: [privkey:32][pubkey_hash:20][p2sh_hash:20] = 72 bytes
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct RawKeyData {
    pub private_key: [u8; 32],
    pub pubkey_hash: [u8; 20],
    pub p2sh_hash: [u8; 20],
}

impl RawKeyData {
    pub const SIZE: usize = 72;
    
    /// Create from raw bytes slice (zero-copy)
    #[inline(always)]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        let mut raw = Self {
            private_key: [0u8; 32],
            pubkey_hash: [0u8; 20],
            p2sh_hash: [0u8; 20],
        };
        raw.private_key.copy_from_slice(&data[0..32]);
        raw.pubkey_hash.copy_from_slice(&data[32..52]);
        raw.p2sh_hash.copy_from_slice(&data[52..72]);
        Some(raw)
    }
    
    /// Check if private key is non-zero (valid)
    /// 
    /// Uses safe byte iteration instead of unaligned pointer casts.
    /// The compiler will auto-vectorize this into SIMD operations.
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        // Safe implementation: any non-zero byte means valid key
        // Compiler auto-vectorizes this into efficient SIMD code
        self.private_key.iter().any(|&b| b != 0)
    }
}

/// GLV Endomorphism mode for throughput optimization
/// 
/// GLV (Gallant-Lambert-Vanstone) uses secp256k1's efficient endomorphism
/// to generate multiple keys from a single EC point multiplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GlvMode {
    /// Standard mode: 1 key per EC operation
    Disabled,
    /// GLV 2x mode: 2 keys per EC operation (k and λk)
    Glv2x,
    /// GLV 3x mode: 3 keys per EC operation (k, λk, λ²k)
    /// Default: Maximum throughput with mathematically proven correctness.
    #[default]
    Glv3x,
}

impl GlvMode {
    /// Keys generated per EC point multiplication
    pub fn keys_per_ec_op(&self) -> usize {
        match self {
            GlvMode::Disabled => 1,
            GlvMode::Glv2x => 2,
            GlvMode::Glv3x => 3,
        }
    }
    
    /// Output size per batch entry in bytes
    pub fn output_size_per_entry(&self) -> usize {
        self.keys_per_ec_op() * 72  // 72 bytes per key
    }
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
    /// Ending offset for private keys (optional, None = unlimited/wrap around)
    /// When set, generator stops when current_offset reaches this value.
    /// This is useful for scanning specific ranges (e.g., Bitcoin Puzzle challenges).
    pub end_offset: Option<u64>,
    /// GLV Endomorphism mode (default: Glv2x for 2x throughput)
    pub glv_mode: GlvMode,
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
            end_offset: None, // No limit by default
            glv_mode: GlvMode::default(), // Glv2x for best stability
        }
    }
}

/// secp256k1 curve order (n) - maximum valid private key
/// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
/// Note: This is 256 bits, but we represent it as u64 limbs for comparison
/// In practice, u64::MAX (~1.8×10^19) is much smaller than n (~1.16×10^77),
/// so any u64 offset is always valid. This constant is for documentation.
pub const SECP256K1_ORDER_HIGH: u64 = 0xFFFFFFFFFFFFFFFE;
pub const SECP256K1_ORDER_NOTE: &str = 
    "secp256k1 order n ≈ 1.16×10^77, u64 max ≈ 1.8×10^19 - all u64 values are valid";

impl GeneratorConfig {
    /// Validate the configuration
    /// 
    /// # Validation Rules
    /// - start_offset must be > 0 (0 is invalid private key)
    /// - end_offset must be > start_offset (if set)
    /// - u64 offsets are always < secp256k1 order (n ≈ 2^256)
    pub fn validate(&self) -> Result<(), String> {
        if self.start_offset == 0 {
            return Err("start_offset cannot be 0 (invalid private key)".to_string());
        }
        
        if let Some(end) = self.end_offset {
            if end <= self.start_offset {
                return Err(format!(
                    "end_offset ({}) must be greater than start_offset ({})",
                    end, self.start_offset
                ));
            }
        }
        
        // Note: u64 values are always valid for secp256k1 since:
        // u64::MAX = 18,446,744,073,709,551,615 (~1.8×10^19)
        // secp256k1 n = 115,792,089,237,316,195,423,570,985,008,687,907,852,837,564,279,074,904,382,605,163,141,518,161,494,337 (~1.16×10^77)
        // Therefore: u64::MAX << n, so all u64 offsets are valid private keys
        
        Ok(())
    }
    
    /// Get the total range size (if end_offset is set)
    pub fn range_size(&self) -> Option<u64> {
        self.end_offset.map(|end| end.saturating_sub(self.start_offset))
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


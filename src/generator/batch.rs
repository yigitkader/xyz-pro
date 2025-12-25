//! Batch processor for high-throughput key generation
//! 
//! Handles high-throughput key generation with:
//! - Parallel batch processing
//! - Automatic file writing at configured intervals
//! 
//! ## Deduplication Note
//! 
//! **Sequential mode (default)**: Deduplication is DISABLED because mathematically
//! no duplicates can occur. The offset-based generation guarantees unique keys:
//! `key[i] = base + i` where `i` is strictly increasing.
//! 
//! This saves significant RAM (previously used GB of memory for DashSet).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rayon::prelude::*;

use super::{
    AddressEncoder, GeneratorConfig, GeneratorStats, KeyEntry, CpuKeyGenerator,
    OutputWriter,
};

/// Batch processor for high-throughput key generation
/// 
/// ## Memory Efficiency
/// 
/// In sequential mode (the only mode now), deduplication is disabled because:
/// - Keys are generated as `base + offset` where offset is strictly increasing
/// - Mathematically impossible to produce duplicates
/// - Saves gigabytes of RAM that was previously wasted on DashSet
pub struct BatchProcessor {
    config: GeneratorConfig,
    keygen: Arc<CpuKeyGenerator>,
    /// Statistics
    total_generated: Arc<AtomicU64>,
    /// Stop signal
    should_stop: Arc<AtomicBool>,
}

impl BatchProcessor {
    /// Create a new batch processor
    pub fn new(config: GeneratorConfig) -> Self {
        // Configure thread pool with explicit error handling
        if config.threads > 0 {
            if let Err(e) = rayon::ThreadPoolBuilder::new()
                .num_threads(config.threads)
                .build_global() 
            {
                // Log warning but continue - rayon will use defaults
                eprintln!("⚠️ Warning: Could not configure thread pool: {}. Using defaults.", e);
            }
        }
        
        // Use sequential mode matching GPU behavior
        let glv_mult = config.glv_mode.keys_per_ec_op();
        
        Self {
            config: config.clone(),
            keygen: Arc::new(CpuKeyGenerator::new(config.start_offset, config.end_offset, glv_mult)),
            total_generated: Arc::new(AtomicU64::new(0)),
            should_stop: Arc::new(AtomicBool::new(false)),
        }
    }
    
    /// Create with specific start offset for reproducibility
    /// 
    /// NOTE: The 'seed' parameter is now interpreted as 'start_offset' for
    /// GPU-compatible sequential key generation.
    pub fn with_seed(config: GeneratorConfig, start_offset: u64) -> Self {
        if config.threads > 0 {
            if let Err(e) = rayon::ThreadPoolBuilder::new()
                .num_threads(config.threads)
                .build_global() 
            {
                eprintln!("⚠️ Warning: Could not configure thread pool: {}. Using defaults.", e);
            }
        }
        
        let glv_mult = config.glv_mode.keys_per_ec_op();
        
        Self {
            config: config.clone(),
            keygen: Arc::new(CpuKeyGenerator::new(start_offset.max(1), config.end_offset, glv_mult)),
            total_generated: Arc::new(AtomicU64::new(0)),
            should_stop: Arc::new(AtomicBool::new(false)),
        }
    }
    
    /// Request stop
    pub fn stop(&self) {
        self.should_stop.store(true, Ordering::SeqCst);
    }
    
    /// Check if should stop
    pub fn should_stop(&self) -> bool {
        self.should_stop.load(Ordering::SeqCst)
    }
    
    /// Run the generator until stopped or target reached
    pub fn run(&self, target_keys: Option<u64>) -> std::io::Result<GeneratorStats> {
        let start_time = Instant::now();
        let mut writer = OutputWriter::new(&self.config.output_dir, self.config.output_format)?;
        let mut current_batch: Vec<KeyEntry> = Vec::with_capacity(self.config.keys_per_file as usize);
        
        println!("🚀 Starting BTC Key Generator");
        println!("   Batch size: {}", self.config.batch_size);
        println!("   Keys per file: {}", self.config.keys_per_file);
        println!("   Output: {}", self.config.output_dir);
        println!("   Format: {:?}", self.config.output_format);
        println!();
        
        let mut last_report = Instant::now();
        let report_interval = Duration::from_secs(5);
        
        while !self.should_stop() {
            // Check target
            if let Some(target) = target_keys {
                if self.total_generated.load(Ordering::Relaxed) >= target {
                    break;
                }
            }
            
            // Generate batch
            let raw_keys = self.keygen.generate_batch(self.config.batch_size);
            
            // Process with parallel encoding
            // NOTE: No deduplication needed - sequential mode guarantees unique keys
            // (key[i] = base + i where i is strictly increasing)
            let new_entries: Vec<KeyEntry> = raw_keys
                .into_par_iter()
                .map(|raw| {
                    // Encode addresses (thread-local encoder)
                    thread_local! {
                        static ENCODER: std::cell::RefCell<AddressEncoder> = 
                            std::cell::RefCell::new(AddressEncoder::new());
                    }
                    
                    ENCODER.with(|enc| {
                        enc.borrow_mut().encode(&raw)
                    })
                })
                .collect();
            
            let new_count = new_entries.len() as u64;
            self.total_generated.fetch_add(new_count, Ordering::Relaxed);
            current_batch.extend(new_entries);
            
            // Write file when batch is full
            if current_batch.len() >= self.config.keys_per_file as usize {
                let filename = writer.write_batch(&current_batch)?;
                println!("📁 Written: {} ({} keys)", filename, current_batch.len());
                current_batch.clear();
            }
            
            // Progress report
            if last_report.elapsed() >= report_interval {
                let total = self.total_generated.load(Ordering::Relaxed);
                let elapsed = start_time.elapsed().as_secs_f64();
                let rate = total as f64 / elapsed;
                
                println!(
                    "⚡ Progress: {} keys | {:.2}M/sec | {:.2}M/min | Pending: {}",
                    format_number(total),
                    rate / 1_000_000.0,
                    rate * 60.0 / 1_000_000.0,
                    format_number(current_batch.len() as u64)
                );
                
                last_report = Instant::now();
            }
        }
        
        // Write remaining keys
        if !current_batch.is_empty() {
            let filename = writer.write_batch(&current_batch)?;
            println!("📁 Final write: {} ({} keys)", filename, current_batch.len());
        }
        
        let elapsed = start_time.elapsed().as_secs_f64();
        
        Ok(GeneratorStats {
            total_generated: self.total_generated.load(Ordering::Relaxed),
            duplicates_skipped: 0, // Sequential mode: no duplicates possible
            files_written: writer.files_written(),
            elapsed_secs: elapsed,
        })
    }
    
    /// Generate exactly N keys (for testing)
    /// 
    /// NOTE: No deduplication - sequential mode guarantees unique keys
    pub fn generate_n(&self, n: usize) -> Vec<KeyEntry> {
        let mut result = Vec::with_capacity(n);
        let mut encoder = AddressEncoder::new();
        
        while result.len() < n {
            let remaining = n - result.len();
            let batch = self.keygen.generate_batch(self.config.batch_size.min(remaining));
            
            for raw in batch {
                result.push(encoder.encode(&raw));
                if result.len() >= n {
                    break;
                }
            }
        }
        
        result
    }
    
    /// Get current stats
    pub fn stats(&self, elapsed: Duration) -> GeneratorStats {
        GeneratorStats {
            total_generated: self.total_generated.load(Ordering::Relaxed),
            duplicates_skipped: 0, // Sequential mode: no duplicates possible
            files_written: 0,
            elapsed_secs: elapsed.as_secs_f64(),
        }
    }
}

/// Format large numbers with commas
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_batch_generation() {
        let config = GeneratorConfig {
            batch_size: 1000,
            keys_per_file: 10_000,
            ..Default::default()
        };
        
        let processor = BatchProcessor::with_seed(config, 12345);
        let keys = processor.generate_n(100);
        
        assert_eq!(keys.len(), 100);
        
        // All keys should be unique
        let mut seen = std::collections::HashSet::new();
        for key in &keys {
            assert!(seen.insert(&key.private_key));
        }
    }
    
    #[test]
    fn test_deduplication() {
        let config = GeneratorConfig {
            batch_size: 100,
            ..Default::default()
        };
        
        let processor = BatchProcessor::with_seed(config, 12345);
        let keys1 = processor.generate_n(50);
        
        // Generate more - should not have any duplicates with first batch
        let keys2 = processor.generate_n(50);
        
        // Combine and check uniqueness
        let mut all_keys = std::collections::HashSet::new();
        for key in keys1.iter().chain(keys2.iter()) {
            assert!(all_keys.insert(&key.private_key));
        }
    }
    
    #[test]
    fn test_address_formats() {
        let config = GeneratorConfig::default();
        let processor = BatchProcessor::with_seed(config, 12345);
        let keys = processor.generate_n(10);
        
        for key in &keys {
            // Check address formats
            assert!(key.p2pkh.starts_with('1'), "P2PKH should start with 1");
            assert!(key.p2sh.starts_with('3'), "P2SH should start with 3");
            assert!(key.p2wpkh.starts_with("bc1q"), "P2WPKH should start with bc1q");
            
            // Check private key is 64 hex chars
            assert_eq!(key.private_key.len(), 64);
        }
    }
}


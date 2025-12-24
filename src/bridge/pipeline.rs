//! Integrated Pipeline - Orchestrates Generator and Matcher
//!
//! This is the heart of the bridge - it connects generator and matcher
//! through clean trait interfaces, handling all the orchestration.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use rayon::prelude::*;

/// Global reference instant for lock-free elapsed time calculation
/// All timestamps are stored as nanoseconds since this reference point
static INSTANT_REFERENCE: Lazy<Instant> = Lazy::new(Instant::now);

use super::{KeyBatch, KeyGenerator, Match, MatchOutput, Matcher, RawKeyData};

/// Pipeline configuration
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Report interval in seconds
    pub report_interval_secs: u64,
    /// Enable parallel matching
    pub parallel_matching: bool,
    /// Chunk size for parallel processing
    pub parallel_chunk_size: usize,
    /// Maximum retries for generate_batch failures (0 = no retries)
    pub max_retries: u32,
    /// Initial retry delay in milliseconds (doubles on each retry)
    pub retry_delay_ms: u64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            report_interval_secs: 2,
            parallel_matching: true,
            // Dynamic chunk size based on CPU cores for optimal parallelism:
            // - Target: 2-4 chunks per CPU core for good load balancing
            // - Example: 12 cores → ~4K chunk size (48K batch / 12 = 4K)
            // - This ensures all cores are utilized regardless of GPU batch size
            // - Previous static 100K value caused single-threading when batch < 100K
            parallel_chunk_size: Self::compute_optimal_chunk_size(),
            // Retry configuration for transient GPU errors
            max_retries: 3,
            retry_delay_ms: 10,
        }
    }
}

impl PipelineConfig {
    /// Compute optimal chunk size based on available CPU cores
    /// 
    /// Strategy: Target 2-4 chunks per core for good load balancing
    /// - Too few chunks: cores sit idle waiting for work
    /// - Too many chunks: excessive overhead from task scheduling
    /// 
    /// Returns chunk size in number of keys (not bytes)
    fn compute_optimal_chunk_size() -> usize {
        let num_cores = rayon::current_num_threads();
        
        // Target: 3 chunks per core on average
        // Minimum: 1K keys per chunk (avoid excessive task overhead)
        // Maximum: 8K keys per chunk (ensure reasonable granularity)
        const MIN_CHUNK: usize = 1_000;
        const MAX_CHUNK: usize = 8_000;
        const CHUNKS_PER_CORE: usize = 3;
        
        // Assume typical GPU batch size of ~65K-131K keys
        // For M1 Pro (10 cores): 65K / (10 * 3) ≈ 2.1K → use 2K
        // For M2 Ultra (24 cores): 131K / (24 * 3) ≈ 1.8K → use 2K
        let target_chunks = num_cores * CHUNKS_PER_CORE;
        
        // Use a reasonable default batch estimate
        const TYPICAL_BATCH_SIZE: usize = 65_536;
        let computed = TYPICAL_BATCH_SIZE / target_chunks.max(1);
        
        // Clamp to reasonable bounds
        computed.clamp(MIN_CHUNK, MAX_CHUNK)
    }
}

/// Pipeline statistics
#[derive(Debug, Clone, Default)]
pub struct PipelineStats {
    pub keys_scanned: u64,
    pub matches_found: u64,
    pub elapsed_secs: f64,
}

impl PipelineStats {
    pub fn keys_per_second(&self) -> f64 {
        if self.elapsed_secs > 0.0 {
            self.keys_scanned as f64 / self.elapsed_secs
        } else {
            0.0
        }
    }
    
    pub fn keys_per_minute(&self) -> f64 {
        self.keys_per_second() * 60.0
    }
}

/// Integrated Pipeline - connects Generator and Matcher
/// 
/// This is the main orchestrator that:
/// 1. Gets batches from the generator
/// 2. Passes them to the matcher
/// 3. Outputs any matches found
/// 4. Reports progress
pub struct IntegratedPipeline<G, M, O>
where
    G: KeyGenerator,
    M: Matcher,
    O: MatchOutput,
{
    generator: Arc<G>,
    matcher: Arc<M>,
    output: Arc<O>,
    config: PipelineConfig,
    
    // Stats (all lock-free atomics)
    matches_found: AtomicU64,
    /// Start time as nanoseconds since INSTANT_REFERENCE (lock-free)
    /// Using AtomicU64 instead of Mutex<Instant> for lock-free stats() access
    start_nanos: AtomicU64,
}

impl<G, M, O> IntegratedPipeline<G, M, O>
where
    G: KeyGenerator,
    M: Matcher,
    O: MatchOutput,
{
    /// Create a new pipeline
    pub fn new(generator: G, matcher: M, output: O) -> Self {
        Self::with_config(generator, matcher, output, PipelineConfig::default())
    }
    
    /// Create a new pipeline with custom config
    pub fn with_config(generator: G, matcher: M, output: O, config: PipelineConfig) -> Self {
        // Initialize start_nanos relative to global reference
        let start_nanos = Instant::now()
            .duration_since(*INSTANT_REFERENCE)
            .as_nanos() as u64;
        
        Self {
            generator: Arc::new(generator),
            matcher: Arc::new(matcher),
            output: Arc::new(output),
            config,
            matches_found: AtomicU64::new(0),
            start_nanos: AtomicU64::new(start_nanos),
        }
    }
    
    /// Run the pipeline
    /// 
    /// Note: Can be called multiple times. Each call resets stats tracking.
    pub fn run(&self) -> Result<PipelineStats, String> {
        let now = Instant::now();
        
        // Reset start time for this run (lock-free atomic update)
        let start_nanos = now.duration_since(*INSTANT_REFERENCE).as_nanos() as u64;
        self.start_nanos.store(start_nanos, Ordering::Release);
        // Reset match counter for this run
        self.matches_found.store(0, Ordering::SeqCst);
        
        let start_time = now;
        let mut last_report = Instant::now();
        let report_interval = Duration::from_secs(self.config.report_interval_secs);
        
        self.print_banner();
        
        while !self.generator.should_stop() {
            // Check if range is complete BEFORE generating next batch
            // This prevents wrap-around when scanning specific ranges
            if self.generator.is_range_complete() {
                println!("🏁 Range scan complete - reached end offset");
                break;
            }
            
            // 1. Generate batch (zero-copy from GPU) with retry logic
            let batch_data = self.generate_with_retry()?;
            let batch = KeyBatch::new(batch_data);
            
            // 2. Match batch (parallel or sequential)
            let matches = if self.config.parallel_matching {
                self.match_batch_parallel(&batch)
            } else {
                self.matcher.check_batch(&batch)
            };
            
            // 3. Output matches
            if !matches.is_empty() {
                self.matches_found.fetch_add(matches.len() as u64, Ordering::Relaxed);
                self.output.on_matches(&matches)?;
            }
            
            // 4. Progress report
            if last_report.elapsed() >= report_interval {
                self.report_progress(start_time.elapsed());
                last_report = Instant::now();
            }
        }
        
        // Flush output
        self.output.flush()?;
        
        let elapsed = start_time.elapsed().as_secs_f64();
        
        // Print completion summary
        if self.generator.is_range_complete() {
            println!("✅ Range scan completed successfully!");
            if let Some(progress) = self.generator.progress_percent() {
                println!("   Progress: {:.2}%", progress);
            }
        }
        
        Ok(PipelineStats {
            keys_scanned: self.generator.total_generated(),
            matches_found: self.matches_found.load(Ordering::Relaxed),
            elapsed_secs: elapsed,
        })
    }
    
    /// Generate batch with retry logic for transient GPU errors
    /// Uses exponential backoff: delay_ms * 2^attempt
    /// 
    /// Fatal errors are NOT retried - they indicate unrecoverable conditions:
    /// - GPU device lost / hung
    /// - Out of memory
    /// - Shader compilation failure
    /// - Buffer corruption
    fn generate_with_retry(&self) -> Result<&[u8], String> {
        let mut last_error = String::new();
        let mut delay = Duration::from_millis(self.config.retry_delay_ms);
        
        for attempt in 0..=self.config.max_retries {
            match self.generator.generate_batch() {
                Ok(data) => return Ok(data),
                Err(e) => {
                    // Check if error is fatal (non-recoverable)
                    if Self::is_fatal_error(&e) {
                        eprintln!("❌ FATAL GPU error (not retrying): {}", e);
                        return Err(format!("Fatal GPU error: {}", e));
                    }
                    
                    last_error = e;
                    if attempt < self.config.max_retries {
                        eprintln!("⚠️ GPU error (attempt {}/{}): {}, retrying in {:?}...",
                                  attempt + 1, self.config.max_retries + 1, last_error, delay);
                        std::thread::sleep(delay);
                        delay *= 2; // Exponential backoff
                    }
                }
            }
        }
        
        Err(format!("GPU failed after {} retries: {}", 
                    self.config.max_retries + 1, last_error))
    }
    
    /// Check if an error is fatal (non-recoverable)
    /// 
    /// Fatal errors indicate hardware/driver issues that won't resolve with retries:
    /// - Device lost: GPU crashed or was reset
    /// - Out of memory: System memory exhausted
    /// - Compilation failed: Shader is broken
    /// - Invalid buffer: Memory corruption detected
    /// - Command encoder: Metal command buffer creation failed
    /// 
    /// # Error Detection Strategy
    /// 1. First, check for Metal API error codes (most reliable)
    /// 2. Fall back to string pattern matching for driver-specific messages
    /// 
    /// Note: Metal API returns MTLCommandBufferError codes which are more reliable
    /// than string matching, but some drivers may format errors differently.
    #[inline]
    fn is_fatal_error(error: &str) -> bool {
        use super::GpuErrorCode;
        
        // Strategy 1: Check for known Metal error code patterns
        // Metal errors often include status codes like "Error" or code numbers
        let error_lower = error.to_lowercase();
        
        // MTLCommandBufferStatus::Error indicates GPU failure
        if error_lower.contains("status error") || 
           error_lower.contains("status: error") ||
           error_lower.contains("commandbufferstatus::error") {
            return true;
        }
        
        // Check for specific MTLCommandBufferError code mentions
        // These are the fatal error codes from Metal API
        const FATAL_ERROR_CODES: &[(&str, GpuErrorCode)] = &[
            ("outofmemory", GpuErrorCode::OutOfMemory),
            ("out of memory", GpuErrorCode::OutOfMemory),
            ("pagefault", GpuErrorCode::PageFault),
            ("page fault", GpuErrorCode::PageFault),
            ("internal gpu error", GpuErrorCode::Internal),
            ("internal error", GpuErrorCode::Internal),
            ("accessrevoked", GpuErrorCode::AccessRevoked),
            ("access revoked", GpuErrorCode::AccessRevoked),
            ("notpermitted", GpuErrorCode::NotPermitted),
            ("not permitted", GpuErrorCode::NotPermitted),
            ("invalidresource", GpuErrorCode::InvalidResource),
            ("invalid resource", GpuErrorCode::InvalidResource),
            ("devicereset", GpuErrorCode::DeviceReset),
            ("device reset", GpuErrorCode::DeviceReset),
            ("stackoverflow", GpuErrorCode::StackOverflow),
            ("stack overflow", GpuErrorCode::StackOverflow),
        ];
        
        for (pattern, code) in FATAL_ERROR_CODES {
            if error_lower.contains(pattern) && code.is_fatal() {
                return true;
            }
        }
        
        // Strategy 2: Fall back to string pattern matching
        // For driver-specific error messages not covered by Metal API
        const FATAL_PATTERNS: &[&str] = &[
            // Metal device errors
            "device lost",
            "device removed", 
            "gpu hang",
            "gpu reset",
            "gpu error",
            // Memory errors
            "memory allocation failed",
            "buffer too large",
            "storage allocation failed",
            // Shader/compilation errors
            "compilation failed",
            "shader error",
            "function not found",
            "library error",
            // Buffer/data corruption
            "invalid buffer",
            "buffer overrun",
            "corruption detected",
            "null pointer",
            // Command buffer errors
            "command encoder",
            "execution aborted",
            // Generic fatal indicators
            "fatal",
            "unrecoverable",
            "panic",
            // Metal-specific
            "mtlcommandbuffererror",
        ];
        
        FATAL_PATTERNS.iter().any(|pattern| error_lower.contains(pattern))
    }
    
    /// Match batch using parallel processing
    /// 
    /// Uses SIMD-friendly patterns and minimizes allocations
    fn match_batch_parallel(&self, batch: &KeyBatch) -> Vec<Match> {
        let chunk_size = self.config.parallel_chunk_size;
        let data = batch.as_bytes();
        
        data.par_chunks(chunk_size * RawKeyData::SIZE)
            .flat_map(|chunk| {
                // Pre-allocate with estimated capacity (matches are rare)
                let mut matches = Vec::with_capacity(8);
                let key_count = chunk.len() / RawKeyData::SIZE;
                
                for i in 0..key_count {
                    let offset = i * RawKeyData::SIZE;
                    let end = offset + RawKeyData::SIZE;
                    
                    // SAFETY: offset..end is within bounds because:
                    // - i < key_count = chunk.len() / SIZE
                    // - end = (i+1) * SIZE <= key_count * SIZE <= chunk.len()
                    let key = unsafe { RawKeyData::from_bytes_unchecked(&chunk[offset..end]) };
                    
                    if !key.is_valid() {
                        continue;
                    }
                    
                    let match_types = self.matcher.check_key(&key.pubkey_hash, &key.p2sh_hash);
                    
                    for mt in match_types {
                        matches.push(Match::new(key, mt));
                    }
                }
                
                matches
            })
            .collect()
    }
    
    /// Print pipeline banner
    fn print_banner(&self) {
        let matcher_stats = self.matcher.stats();
        
        println!("╔════════════════════════════════════════════════════════════╗");
        println!("║       🚀 INTEGRATED PIPELINE - NASA Grade Architecture     ║");
        println!("╠════════════════════════════════════════════════════════════╣");
        println!("║   ✓ Generator → Bridge → Matcher → Output                  ║");
        println!("║   ✓ Zero-copy batch transfer                               ║");
        println!("║   ✓ Parallel matching with Rayon                           ║");
        println!("║   ✓ O(1) HashSet lookup                                    ║");
        println!("╠════════════════════════════════════════════════════════════╣");
        println!("║  Targets: {:>10} total                                  ║", matcher_stats.total);
        println!("║           {:>10} P2PKH (Legacy)                         ║", matcher_stats.p2pkh);
        println!("║           {:>10} P2SH (SegWit)                          ║", matcher_stats.p2sh);
        println!("║           {:>10} P2WPKH (Bech32)                        ║", matcher_stats.p2wpkh);
        println!("║  Batch:   {:>10} keys                                   ║", self.generator.batch_size());
        
        // Show range info if configured
        if let Some(end) = self.generator.end_offset() {
            let start = self.generator.current_offset();
            let range_size = end.saturating_sub(start);
            println!("╠════════════════════════════════════════════════════════════╣");
            println!("║  📊 RANGE SCAN MODE                                        ║");
            println!("║  Start:   0x{:016x}                          ║", start);
            println!("║  End:     0x{:016x}                          ║", end);
            println!("║  Range:   {} keys                          ║", format_number(range_size));
        }
        
        println!("╚════════════════════════════════════════════════════════════╝");
        println!();
    }
    
    /// Report progress
    fn report_progress(&self, elapsed: Duration) {
        let total = self.generator.total_generated();
        let matches = self.matches_found.load(Ordering::Relaxed);
        let offset = self.generator.current_offset();
        let elapsed_secs = elapsed.as_secs_f64();
        let rate = total as f64 / elapsed_secs;
        
        // Include progress percentage if range is configured
        let progress_str = self.generator.progress_percent()
            .map(|p| format!(" | {:.2}%", p))
            .unwrap_or_default();
        
        println!(
            "⚡ {} keys | {:.2}M/sec | {:.1}M/min | Hits: {} | Offset: 0x{:012x}{}",
            format_number(total),
            rate / 1_000_000.0,
            rate * 60.0 / 1_000_000.0,
            matches,
            offset,
            progress_str
        );
    }
    
    /// Get current stats (can be called during a run from another thread)
    /// 
    /// This is completely lock-free - uses atomic reads only.
    /// No mutex contention even under high-frequency polling.
    #[inline]
    pub fn stats(&self) -> PipelineStats {
        // Lock-free elapsed time calculation
        let start_nanos = self.start_nanos.load(Ordering::Acquire);
        let now_nanos = Instant::now()
            .duration_since(*INSTANT_REFERENCE)
            .as_nanos() as u64;
        let elapsed_nanos = now_nanos.saturating_sub(start_nanos);
        let elapsed_secs = elapsed_nanos as f64 / 1_000_000_000.0;
        
        PipelineStats {
            keys_scanned: self.generator.total_generated(),
            matches_found: self.matches_found.load(Ordering::Relaxed),
            elapsed_secs,
        }
    }
    
    /// Stop the pipeline
    pub fn stop(&self) {
        self.generator.stop();
    }
    
    /// Get the generator reference
    pub fn generator(&self) -> &G {
        &self.generator
    }
    
    /// Get the matcher reference
    pub fn matcher(&self) -> &M {
        &self.matcher
    }
}

// Helper function for formatting numbers
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

// ============================================================================
// DROP IMPLEMENTATION - Graceful Pipeline Shutdown
// ============================================================================

impl<G, M, O> Drop for IntegratedPipeline<G, M, O>
where
    G: KeyGenerator,
    M: Matcher,
    O: MatchOutput,
{
    /// Graceful shutdown with timeout protection
    /// 
    /// Ensures the generator is stopped and resources are cleaned up.
    /// Uses a timeout to prevent infinite hangs if GPU becomes unresponsive.
    fn drop(&mut self) {
        use std::time::{Duration, Instant};
        
        const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
        let start = Instant::now();
        
        // Signal stop to generator
        self.generator.stop();
        
        // Wait briefly for any pending operations
        // The generator's Drop will handle the actual GPU cleanup
        while !self.generator.should_stop() && start.elapsed() < SHUTDOWN_TIMEOUT {
            std::thread::sleep(Duration::from_millis(10));
        }
        
        if start.elapsed() >= SHUTDOWN_TIMEOUT {
            eprintln!("⚠️  Pipeline shutdown timed out after {}ms", SHUTDOWN_TIMEOUT.as_millis());
        }
        
        // Flush output if possible (ignore errors during drop)
        let _ = self.output.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::types::MatchType;
    
    // Mock generator for testing
    struct MockGenerator {
        data: Vec<u8>,
        stop: std::sync::atomic::AtomicBool,
        generated: AtomicU64,
    }
    
    impl MockGenerator {
        fn new(key_count: usize) -> Self {
            Self {
                data: vec![1u8; key_count * RawKeyData::SIZE],
                stop: std::sync::atomic::AtomicBool::new(false),
                generated: AtomicU64::new(0),
            }
        }
    }
    
    impl KeyGenerator for MockGenerator {
        fn batch_size(&self) -> usize {
            self.data.len() / RawKeyData::SIZE
        }
        
        fn generate_batch(&self) -> Result<&[u8], String> {
            self.generated.fetch_add(self.batch_size() as u64, Ordering::Relaxed);
            // Stop after one batch for testing
            self.stop.store(true, Ordering::SeqCst);
            Ok(&self.data)
        }
        
        fn current_offset(&self) -> u64 { 0 }
        fn should_stop(&self) -> bool { self.stop.load(Ordering::SeqCst) }
        fn stop(&self) { self.stop.store(true, Ordering::SeqCst); }
        fn total_generated(&self) -> u64 { self.generated.load(Ordering::Relaxed) }
    }
    
    // Mock matcher for testing
    struct MockMatcher;
    
    impl Matcher for MockMatcher {
        fn check_batch(&self, _batch: &KeyBatch) -> Vec<Match> {
            Vec::new()
        }
        
        fn check_key(&self, _pubkey_hash: &[u8; 20], _p2sh_hash: &[u8; 20]) -> Vec<MatchType> {
            Vec::new()
        }
        
        fn target_count(&self) -> usize { 0 }
        
        fn stats(&self) -> super::super::traits::MatcherStats {
            super::super::traits::MatcherStats::default()
        }
    }
    
    // Mock output for testing
    struct MockOutput;
    
    impl MatchOutput for MockOutput {
        fn on_matches(&self, _matches: &[Match]) -> Result<(), String> { Ok(()) }
        fn flush(&self) -> Result<(), String> { Ok(()) }
        fn total_matches(&self) -> u64 { 0 }
    }
    
    #[test]
    fn test_pipeline_creation() {
        let gen = MockGenerator::new(100);
        let matcher = MockMatcher;
        let output = MockOutput;
        
        let pipeline = IntegratedPipeline::new(gen, matcher, output);
        assert_eq!(pipeline.generator().batch_size(), 100);
    }
}


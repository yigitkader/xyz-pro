//! Integrated Pipeline - Orchestrates Generator and Matcher
//!
//! This is the heart of the bridge - it connects generator and matcher
//! through clean trait interfaces, handling all the orchestration.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rayon::prelude::*;

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
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            report_interval_secs: 2,
            parallel_matching: true,
            parallel_chunk_size: 10_000,
        }
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
    
    // Stats
    matches_found: AtomicU64,
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
        Self {
            generator: Arc::new(generator),
            matcher: Arc::new(matcher),
            output: Arc::new(output),
            config,
            matches_found: AtomicU64::new(0),
        }
    }
    
    /// Run the pipeline
    pub fn run(&self) -> Result<PipelineStats, String> {
        let start_time = Instant::now();
        let mut last_report = Instant::now();
        let report_interval = Duration::from_secs(self.config.report_interval_secs);
        
        self.print_banner();
        
        while !self.generator.should_stop() {
            // 1. Generate batch (zero-copy from GPU)
            let batch_data = self.generator.generate_batch()?;
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
        
        Ok(PipelineStats {
            keys_scanned: self.generator.total_generated(),
            matches_found: self.matches_found.load(Ordering::Relaxed),
            elapsed_secs: elapsed,
        })
    }
    
    /// Match batch using parallel processing
    fn match_batch_parallel(&self, batch: &KeyBatch) -> Vec<Match> {
        let chunk_size = self.config.parallel_chunk_size;
        let data = batch.as_bytes();
        
        data.par_chunks(chunk_size * RawKeyData::SIZE)
            .flat_map(|chunk| {
                let mut matches = Vec::new();
                
                for i in 0..(chunk.len() / RawKeyData::SIZE) {
                    let offset = i * RawKeyData::SIZE;
                    if let Some(key) = RawKeyData::from_bytes(&chunk[offset..]) {
                        if !key.is_valid() {
                            continue;
                        }
                        
                        let match_types = self.matcher.check_key(&key.pubkey_hash, &key.p2sh_hash);
                        
                        for mt in match_types {
                            matches.push(Match::new(key, mt));
                        }
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
        
        println!(
            "⚡ {} keys | {:.2}M/sec | {:.1}M/min | Hits: {} | Offset: 0x{:012x}",
            format_number(total),
            rate / 1_000_000.0,
            rate * 60.0 / 1_000_000.0,
            matches,
            offset
        );
    }
    
    /// Get current stats
    pub fn stats(&self) -> PipelineStats {
        PipelineStats {
            keys_scanned: self.generator.total_generated(),
            matches_found: self.matches_found.load(Ordering::Relaxed),
            elapsed_secs: 0.0, // Would need to track start time
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


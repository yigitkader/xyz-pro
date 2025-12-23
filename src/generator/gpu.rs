//! Ultra-Optimized GPU Key Generator using Metal
//!
//! OPTIMIZATIONS (from main project):
//! 1. Triple buffering with 3 command queues (GPU never idle)
//! 2. Pre-computed wNAF tables (5 additions vs 256)
//! 3. Montgomery batch inversion (1 mod_inv per batch)
//! 4. GLV endomorphism (2x effective throughput)
//! 5. Extended Jacobian coordinates
//! 6. Buffer pool with zero-copy transfer
//! 7. Look-ahead pubkey computation (hides latency)
//!
//! Target: 1 billion keys/minute on Apple Silicon.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};

use metal::{
    Buffer, CommandQueue, ComputePipelineState,
    Device, MTLResourceOptions, MTLSize,
};

use super::{AddressEncoder, GeneratorConfig, GeneratorStats, KeyEntry, OutputWriter};

/// Keys per thread (Montgomery batch size)
const BATCH_SIZE: usize = 32;

/// Output size per key: 32 (privkey) + 20 (pubkey_hash) + 20 (p2sh_hash) = 72 bytes
const OUTPUT_SIZE: usize = 72;

/// wNAF table: 5 windows × 15 entries × 64 bytes (x + y coordinates)
const WNAF_TABLE_SIZE: usize = 75 * 64;

/// Triple buffer set for async pipelining
struct BufferSet {
    queue: CommandQueue,
    seed_buffer: Buffer,
    offset_buffer: Buffer,
    output_buffer: Buffer,
}

/// GPU configuration based on hardware tier
#[derive(Clone)]
struct GpuTier {
    name: String,
    threads_per_dispatch: usize,
    keys_per_dispatch: usize,
    threadgroup_size: usize,
    pipeline_depth: usize,
}

impl GpuTier {
    fn detect(device: &Device, base_batch_size: usize) -> Self {
        let name = device.name().to_string();
        let name_lower = name.to_lowercase();
        let mem_mb = device.recommended_max_working_set_size() / (1024 * 1024);
        
        let (multiplier, pipeline_depth) = if name_lower.contains("ultra") || mem_mb >= 96000 {
            println!("[GPU] ULTRA tier detected: maximum throughput");
            (4, 4)  // 4x threads, 4 pipeline stages
        } else if name_lower.contains("max") || mem_mb >= 48000 {
            println!("[GPU] MAX tier detected: high throughput");
            (3, 3)
        } else if name_lower.contains("pro") || mem_mb >= 16000 {
            println!("[GPU] PRO tier detected: balanced");
            (2, 3)
        } else {
            println!("[GPU] BASE tier detected: conservative");
            (1, 2)
        };
        
        let threads_per_dispatch = (base_batch_size / BATCH_SIZE) * multiplier;
        let keys_per_dispatch = threads_per_dispatch * BATCH_SIZE;
        
        Self {
            name,
            threads_per_dispatch,
            keys_per_dispatch,
            threadgroup_size: 256,
            pipeline_depth,
        }
    }
}

/// Ultra-optimized GPU Key Generator with triple buffering
pub struct GpuKeyGenerator {
    #[allow(dead_code)]
    device: Device,
    pipeline: ComputePipelineState,
    config: GeneratorConfig,
    tier: GpuTier,
    
    // Triple buffering for async pipelining
    buffer_sets: Vec<BufferSet>,
    current_buffer: AtomicUsize,
    
    // Shared read-only buffers
    wnaf_table_buffer: Buffer,
    
    // State
    current_offset: AtomicU64,
    should_stop: Arc<AtomicBool>,
    
    // Stats
    total_generated: AtomicU64,
}

impl GpuKeyGenerator {
    /// Create a new GPU key generator with all optimizations
    pub fn new(config: GeneratorConfig) -> Result<Self, String> {
        let device = Device::system_default()
            .ok_or("No Metal device found")?;
        
        println!("🖥️  GPU: {}", device.name());
        println!("   Max threads per threadgroup: {}", device.max_threads_per_threadgroup().width);
        
        // Detect GPU tier
        let tier = GpuTier::detect(&device, config.batch_size);
        
        // Load and compile shader
        let shader_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/generator/keygen.metal");
        
        let shader_source = std::fs::read_to_string(&shader_path)
            .map_err(|e| format!("Failed to read shader: {}", e))?;
        
        let library = device
            .new_library_with_source(&shader_source, &metal::CompileOptions::new())
            .map_err(|e| format!("Failed to compile shader: {}", e))?;
        
        let function = library
            .get_function("generate_btc_keys", None)
            .map_err(|e| format!("Failed to get kernel function: {}", e))?;
        
        let pipeline = device
            .new_compute_pipeline_state_with_function(&function)
            .map_err(|e| format!("Failed to create pipeline: {}", e))?;
        
        let storage = MTLResourceOptions::StorageModeShared;
        let output_buffer_size = tier.keys_per_dispatch * OUTPUT_SIZE;
        
        // Create triple buffer sets (3 separate command queues for async pipelining)
        println!("   Creating {} command queues for async pipelining", tier.pipeline_depth);
        let mut buffer_sets = Vec::with_capacity(tier.pipeline_depth);
        for i in 0..tier.pipeline_depth {
            buffer_sets.push(BufferSet {
                queue: device.new_command_queue(),
                seed_buffer: device.new_buffer(8, storage),
                offset_buffer: device.new_buffer(4, storage),
                output_buffer: device.new_buffer(output_buffer_size as u64, storage),
            });
            println!("   Queue {}: {} MB output buffer", i, output_buffer_size / (1024 * 1024));
        }
        
        // Generate wNAF table
        println!("📊 Generating wNAF lookup table...");
        let wnaf_table = generate_wnaf_table(tier.keys_per_dispatch);
        let wnaf_table_buffer = device.new_buffer_with_data(
            wnaf_table.as_ptr() as *const _,
            wnaf_table.len() as u64,
            storage,
        );
        println!("   wNAF table ready: {} entries ({} bytes)", 
                 wnaf_table.len() / 64, wnaf_table.len());
        
        // Initialize seed from system time
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        
        // Initialize all seed buffers
        for bs in &buffer_sets {
            unsafe {
                let seed_ptr = bs.seed_buffer.contents() as *mut u64;
                *seed_ptr = seed;
            }
        }
        
        println!("   Threads per dispatch: {}", tier.threads_per_dispatch);
        println!("   Keys per dispatch: {} ({:.2}M)", 
                 tier.keys_per_dispatch, tier.keys_per_dispatch as f64 / 1_000_000.0);
        
        Ok(Self {
            device,
            pipeline,
            config,
            tier,
            buffer_sets,
            current_buffer: AtomicUsize::new(0),
            wnaf_table_buffer,
            current_offset: AtomicU64::new(0),
            should_stop: Arc::new(AtomicBool::new(false)),
            total_generated: AtomicU64::new(0),
        })
    }
    
    /// Set the stop signal
    pub fn stop(&self) {
        self.should_stop.store(true, Ordering::SeqCst);
    }
    
    /// Dispatch a batch on the specified buffer set
    fn dispatch_batch(&self, buf_idx: usize, offset: u64) {
        let bs = &self.buffer_sets[buf_idx];
        
        // Update offset
        unsafe {
            let offset_ptr = bs.offset_buffer.contents() as *mut u32;
            *offset_ptr = offset as u32;
        }
        
        // Create command buffer and encoder
        let command_buffer = bs.queue.new_command_buffer();
        let compute_encoder = command_buffer.new_compute_command_encoder();
        
        compute_encoder.set_compute_pipeline_state(&self.pipeline);
        compute_encoder.set_buffer(0, Some(&bs.seed_buffer), 0);
        compute_encoder.set_buffer(1, Some(&bs.offset_buffer), 0);
        compute_encoder.set_buffer(2, Some(&self.wnaf_table_buffer), 0);
        compute_encoder.set_buffer(3, Some(&bs.output_buffer), 0);
        
        let grid_size = MTLSize::new(self.tier.threads_per_dispatch as u64, 1, 1);
        let threadgroup_size = MTLSize::new(self.tier.threadgroup_size as u64, 1, 1);
        
        compute_encoder.dispatch_threads(grid_size, threadgroup_size);
        compute_encoder.end_encoding();
        
        command_buffer.commit();
    }
    
    /// Wait for a batch to complete and process results
    fn process_batch(&self, buf_idx: usize, encoder: &mut AddressEncoder, batch: &mut Vec<KeyEntry>) {
        let bs = &self.buffer_sets[buf_idx];
        
        // Wait for GPU to finish
        // In triple buffering, this should rarely block since we're 2 batches ahead
        let cb = bs.queue.new_command_buffer();
        cb.commit();
        cb.wait_until_completed();
        
        // Process output (zero-copy from unified memory)
        let output_ptr = bs.output_buffer.contents() as *const u8;
        let output_slice = unsafe {
            std::slice::from_raw_parts(output_ptr, self.tier.keys_per_dispatch * OUTPUT_SIZE)
        };
        
        for i in 0..self.tier.keys_per_dispatch {
            let base = i * OUTPUT_SIZE;
            let privkey = &output_slice[base..base + 32];
            let pubkey_hash = &output_slice[base + 32..base + 52];
            let p2sh_hash = &output_slice[base + 52..base + 72];
            
            // Skip invalid keys (all zeros)
            if privkey.iter().all(|&b| b == 0) {
                continue;
            }
            
            // Convert to KeyEntry
            let mut pk_hash = [0u8; 20];
            let mut p2sh = [0u8; 20];
            pk_hash.copy_from_slice(pubkey_hash);
            p2sh.copy_from_slice(p2sh_hash);
            
            let entry = KeyEntry {
                private_key: hex::encode(privkey),
                p2pkh: encoder.encode_p2pkh_from_hash(&pk_hash),
                p2sh: encoder.encode_p2sh_from_hash(&p2sh),
                p2wpkh: encoder.encode_p2wpkh_from_hash(&pk_hash),
            };
            
            batch.push(entry);
        }
    }
    
    /// Run GPU key generation with async pipelining
    pub fn run(&self, target_keys: Option<u64>) -> Result<GeneratorStats, String> {
        let start_time = Instant::now();
        let mut writer = OutputWriter::new(&self.config.output_dir, self.config.output_format)
            .map_err(|e| format!("Failed to create writer: {}", e))?;
        
        let mut current_batch: Vec<KeyEntry> = Vec::with_capacity(self.config.keys_per_file as usize);
        let mut encoder = AddressEncoder::new();
        
        println!("🚀 Starting Ultra-Optimized GPU Key Generator");
        println!("   Pipeline depth: {} (triple+ buffering)", self.tier.pipeline_depth);
        println!("   Montgomery batch size: {} keys/thread", BATCH_SIZE);
        println!("   Keys per GPU dispatch: {}", self.tier.keys_per_dispatch);
        println!("   Keys per file: {}", self.config.keys_per_file);
        println!();
        
        let mut last_report = Instant::now();
        let report_interval = Duration::from_secs(5);
        
        // ASYNC PIPELINING:
        // 1. Prime the pipeline by dispatching initial batches
        // 2. While GPU computes batch N, process results from batch N-2
        // 3. GPU is never idle!
        
        let depth = self.tier.pipeline_depth;
        let mut pending_offsets: Vec<u64> = Vec::with_capacity(depth);
        
        // Prime the pipeline
        for i in 0..depth {
            if let Some(target) = target_keys {
                if self.total_generated.load(Ordering::Relaxed) >= target {
                    break;
                }
            }
            
            let offset = self.current_offset.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            pending_offsets.push(offset);
            self.dispatch_batch(i, offset);
        }
        
        let mut current_buf = 0;
        
        while !self.should_stop.load(Ordering::SeqCst) {
            // Check target
            if let Some(target) = target_keys {
                if self.total_generated.load(Ordering::Relaxed) >= target {
                    break;
                }
            }
            
            // Process completed batch (oldest in pipeline)
            let process_idx = current_buf % depth;
            self.process_batch(process_idx, &mut encoder, &mut current_batch);
            self.total_generated.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            
            // Dispatch next batch to same slot (now free)
            let next_offset = self.current_offset.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            self.dispatch_batch(process_idx, next_offset);
            
            current_buf += 1;
            
            // Write file when batch is full
            if current_batch.len() >= self.config.keys_per_file as usize {
                let filename = writer.write_batch(&current_batch)
                    .map_err(|e| format!("Failed to write: {}", e))?;
                println!("📁 Written: {} ({} keys)", filename, current_batch.len());
                current_batch.clear();
            }
            
            // Progress report
            if last_report.elapsed() >= report_interval {
                let total = self.total_generated.load(Ordering::Relaxed);
                let elapsed = start_time.elapsed().as_secs_f64();
                let rate = total as f64 / elapsed;
                
                println!(
                    "⚡ GPU Progress: {} keys | {:.2}M/sec | {:.2}M/min | Pending: {}",
                    format_number(total),
                    rate / 1_000_000.0,
                    rate * 60.0 / 1_000_000.0,
                    format_number(current_batch.len() as u64)
                );
                
                last_report = Instant::now();
            }
        }
        
        // Drain remaining pipeline
        for i in 0..depth {
            let idx = (current_buf + i) % depth;
            self.process_batch(idx, &mut encoder, &mut current_batch);
        }
        
        // Write remaining keys
        if !current_batch.is_empty() {
            let filename = writer.write_batch(&current_batch)
                .map_err(|e| format!("Failed to write: {}", e))?;
            println!("📁 Final write: {} ({} keys)", filename, current_batch.len());
        }
        
        let elapsed = start_time.elapsed().as_secs_f64();
        
        Ok(GeneratorStats {
            total_generated: self.total_generated.load(Ordering::Relaxed),
            duplicates_skipped: 0,
            files_written: writer.files_written(),
            elapsed_secs: elapsed,
        })
    }
}

/// Generate wNAF lookup table for fast start point computation
/// Table[window * 15 + (digit-1)] = digit * 2^(4*window) * BATCH_SIZE * G
fn generate_wnaf_table(keys_per_dispatch: usize) -> Vec<u8> {
    use k256::elliptic_curve::PrimeField;
    
    let mut table = vec![0u8; WNAF_TABLE_SIZE];
    
    // Base point offset: BATCH_SIZE * G (each thread processes BATCH_SIZE keys)
    let base_scalar = Scalar::from(BATCH_SIZE as u64);
    let base_point = ProjectivePoint::GENERATOR * base_scalar;
    
    for window in 0..5 {
        // 2^(4*window) multiplier
        let window_multiplier = 1u64 << (4 * window);
        let window_scalar = Scalar::from(window_multiplier);
        let window_base = base_point * window_scalar;
        
        for digit in 1..=15 {
            let digit_scalar = Scalar::from(digit as u64);
            let point = window_base * digit_scalar;
            let affine = point.to_affine();
            let encoded = affine.to_encoded_point(false); // uncompressed
            
            let idx = window * 15 + (digit - 1);
            let offset = idx * 64;
            
            // Store X (32 bytes) + Y (32 bytes) in big-endian
            let x_bytes = encoded.x().unwrap();
            let y_bytes = encoded.y().unwrap();
            
            table[offset..offset + 32].copy_from_slice(x_bytes);
            table[offset + 32..offset + 64].copy_from_slice(y_bytes);
        }
    }
    
    table
}

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

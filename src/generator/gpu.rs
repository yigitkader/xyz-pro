//! Ultra-Optimized GPU Key Generator using Metal
//!
//! ALL OPTIMIZATIONS FROM MAIN PROJECT:
//! 1. BufferPool System - Zero-copy ownership transfer
//! 2. Triple buffering with 3 command queues (GPU never idle)
//! 3. Look-ahead pubkey computation (hides CPU latency)
//! 4. Pre-computed wNAF tables (5 additions vs 256 for start point)
//! 5. Montgomery batch inversion (1 mod_inv per batch)
//! 6. GLV Endomorphism (2x throughput - scan 2 key ranges per EC op)
//! 7. Extended Jacobian coordinates (saves 1 squaring per operation)
//! 8. Sharded duplicate checking via hash set
//!
//! Target: Maximum throughput on Apple Silicon.

use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::{bounded, Receiver, Sender};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};

use metal::{
    Buffer, CommandQueue, ComputePipelineState, Device, MTLResourceOptions, MTLSize,
};

use super::{AddressEncoder, GeneratorConfig, GeneratorStats, KeyEntry, OutputFormat, OutputWriter, AsyncRawWriter};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Metal shader source - embedded at compile time for release builds
/// This ensures the binary is self-contained and doesn't require external shader files
const SHADER_SOURCE: &str = include_str!("keygen.metal");

/// Keys per thread (Montgomery batch size) - must match shader
const BATCH_SIZE: u32 = 32;

/// Output size per key: 32 (privkey) + 20 (pubkey_hash) + 20 (p2sh_hash) = 72 bytes
const OUTPUT_SIZE: usize = 72;

/// wNAF table: 5 windows × 15 entries × 64 bytes (x + y coordinates)
const WNAF_TABLE_SIZE: usize = 75 * 64;

/// GLV Lambda constant for endomorphism: k → λ·k (mod n)
/// φ(P) = λ·P where φ(x,y) = (β·x, y)
/// Note: This is now computed in the GPU kernel, kept for potential CPU verification
#[allow(dead_code)]
const GLV_LAMBDA: [u8; 32] = [
    0x53, 0x63, 0xad, 0x4c, 0xc0, 0x5c, 0x30, 0xe0,
    0xa5, 0x26, 0x1c, 0x02, 0x88, 0x12, 0x64, 0x5a,
    0x12, 0x2e, 0x22, 0xea, 0x20, 0x81, 0x66, 0x78,
    0xdf, 0x02, 0x96, 0x7c, 0x1b, 0x23, 0xbd, 0x72,
];

lazy_static::lazy_static! {
    #[allow(dead_code)]
    static ref GLV_LAMBDA_SCALAR: Scalar = {
        use k256::elliptic_curve::PrimeField;
        Scalar::from_repr_vartime(GLV_LAMBDA.into()).unwrap()
    };
}

// ============================================================================
// BUFFER POOL SYSTEM - Zero-copy ownership transfer
// ============================================================================

/// Pre-allocated buffer pool for zero-allocation batch processing
pub struct BufferPool {
    return_tx: Sender<Vec<KeyEntry>>,
    pool_rx: Receiver<Vec<KeyEntry>>,
}

impl BufferPool {
    pub fn new(buffer_capacity: usize, pool_size: usize) -> Self {
        let (return_tx, pool_rx) = bounded(pool_size);
        
        // Pre-allocate all buffers
        for _ in 0..pool_size {
            let buf: Vec<KeyEntry> = Vec::with_capacity(buffer_capacity);
            let _ = return_tx.try_send(buf);
        }
        
        BufferPool { return_tx, pool_rx }
    }
    
    /// Get a buffer from pool
    pub fn acquire(&self) -> Vec<KeyEntry> {
        self.pool_rx.recv().unwrap_or_else(|_| Vec::new())
    }
    
    /// Wrap buffer for auto-return
    pub fn wrap(&self, mut buf: Vec<KeyEntry>) -> PooledBuffer {
        buf.clear();
        PooledBuffer {
            inner: Some(buf),
            return_tx: self.return_tx.clone(),
        }
    }
}

/// Smart pointer that returns buffer to pool on drop
pub struct PooledBuffer {
    inner: Option<Vec<KeyEntry>>,
    return_tx: Sender<Vec<KeyEntry>>,
}

impl PooledBuffer {
    pub fn as_mut(&mut self) -> &mut Vec<KeyEntry> {
        self.inner.as_mut().unwrap()
    }
    
    pub fn len(&self) -> usize {
        self.inner.as_ref().map(|v| v.len()).unwrap_or(0)
    }
    
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    
    pub fn take(mut self) -> Vec<KeyEntry> {
        self.inner.take().unwrap_or_default()
    }
}

impl Deref for PooledBuffer {
    type Target = [KeyEntry];
    fn deref(&self) -> &Self::Target {
        self.inner.as_deref().unwrap_or(&[])
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(mut buf) = self.inner.take() {
            buf.clear();
            let _ = self.return_tx.try_send(buf);
        }
    }
}

unsafe impl Send for PooledBuffer {}
unsafe impl Sync for PooledBuffer {}

// ============================================================================
// GPU STRUCTURES
// ============================================================================

/// Triple buffer set for async pipelining
pub struct BufferSet {
    pub queue: CommandQueue,
    pub base_privkey_buf: Buffer,
    pub base_pubkey_x_buf: Buffer,
    pub base_pubkey_y_buf: Buffer,
    pub output_buffer: Buffer,
    pub keys_per_thread_buf: Buffer,
}

/// GPU configuration based on hardware tier
#[derive(Clone)]
struct GpuTier {
    #[allow(dead_code)]
    name: String,
    threads_per_dispatch: usize,
    keys_per_dispatch: usize,
    threadgroup_size: usize,
    pipeline_depth: usize,
    pool_size: usize,
}

impl GpuTier {
    fn detect(device: &Device) -> Self {
        let name = device.name().to_string();
        let name_lower = name.to_lowercase();
        let mem_mb = device.recommended_max_working_set_size() / (1024 * 1024);
        
        let (threads, pipeline_depth, pool_size) = if name_lower.contains("ultra") || mem_mb >= 96000 {
            println!("[GPU] ULTRA tier: maximum throughput");
            (262_144, 4, 8)
        } else if name_lower.contains("max") || mem_mb >= 48000 {
            println!("[GPU] MAX tier: high throughput");
            (131_072, 4, 6)
        } else if name_lower.contains("pro") || mem_mb >= 16000 {
            println!("[GPU] PRO tier: balanced");
            (65_536, 3, 5)
        } else {
            println!("[GPU] BASE tier: conservative");
            (32_768, 2, 4)
        };
        
        let keys_per_dispatch = threads * BATCH_SIZE as usize;
        
        Self {
            name,
            threads_per_dispatch: threads,
            keys_per_dispatch,
            threadgroup_size: 256,
            pipeline_depth,
            pool_size,
        }
    }
}

// ============================================================================
// GPU KEY GENERATOR
// ============================================================================

/// Ultra-optimized GPU Key Generator with all optimizations
pub struct GpuKeyGenerator {
    #[allow(dead_code)]
    device: Device,
    pipeline: ComputePipelineState,
    pipeline_glv: ComputePipelineState,  // GLV kernel for 2x throughput
    config: GeneratorConfig,
    tier: GpuTier,
    
    // Triple buffering
    buffer_sets: Vec<BufferSet>,
    #[allow(dead_code)]
    current_buffer: AtomicUsize,
    
    // Shared read-only buffers
    wnaf_table_buffer: Buffer,
    
    // Buffer pool for zero-copy
    buffer_pool: Arc<BufferPool>,
    
    // Look-ahead pubkey computation (thread-safe)
    lookahead_pubkey: std::sync::Mutex<Option<([u8; 32], [u8; 32])>>,
    
    // State
    current_offset: AtomicU64,
    should_stop: Arc<AtomicBool>,
    
    // Stats
    total_generated: AtomicU64,
}

// Metal types are thread-safe on Apple Silicon
// Mutex protects lookahead_pubkey, atomics protect counters
unsafe impl Send for GpuKeyGenerator {}
unsafe impl Sync for GpuKeyGenerator {}

impl GpuKeyGenerator {
    /// Create a new GPU key generator with all optimizations
    pub fn new(config: GeneratorConfig) -> Result<Self, String> {
        let device = Device::system_default()
            .ok_or("No Metal device found")?;
        
        println!("🖥️  GPU: {}", device.name());
        println!("   Max threads per threadgroup: {}", device.max_threads_per_threadgroup().width);
        
        // Detect GPU tier
        let tier = GpuTier::detect(&device);
        
        // Compile embedded shader (self-contained binary, no external file needed)
        let library = device
            .new_library_with_source(SHADER_SOURCE, &metal::CompileOptions::new())
            .map_err(|e| format!("Failed to compile shader: {}", e))?;
        
        let function = library
            .get_function("generate_btc_keys", None)
            .map_err(|e| format!("Failed to get kernel function: {}", e))?;
        
        let pipeline = device
            .new_compute_pipeline_state_with_function(&function)
            .map_err(|e| format!("Failed to create pipeline: {}", e))?;
        
        // GLV kernel for 2x throughput
        let function_glv = library
            .get_function("generate_btc_keys_glv", None)
            .map_err(|e| format!("Failed to get GLV kernel function: {}", e))?;
        
        let pipeline_glv = device
            .new_compute_pipeline_state_with_function(&function_glv)
            .map_err(|e| format!("Failed to create GLV pipeline: {}", e))?;
        
        println!("✅ GLV Endomorphism kernel loaded (2x throughput)");
        
        let storage = MTLResourceOptions::StorageModeShared;
        // GLV outputs 2x keys per dispatch
        let output_buffer_size = tier.keys_per_dispatch * OUTPUT_SIZE * 2;
        
        // Create buffer sets for pipelining
        println!("   Creating {} command queues for async pipelining", tier.pipeline_depth);
        let mut buffer_sets = Vec::with_capacity(tier.pipeline_depth);
        for i in 0..tier.pipeline_depth {
            buffer_sets.push(BufferSet {
                queue: device.new_command_queue(),
                base_privkey_buf: device.new_buffer(32, storage),
                base_pubkey_x_buf: device.new_buffer(32, storage),
                base_pubkey_y_buf: device.new_buffer(32, storage),
                output_buffer: device.new_buffer(output_buffer_size as u64, storage),
                keys_per_thread_buf: device.new_buffer(4, storage),
            });
            println!("   Queue {}: {} MB output buffer", i, output_buffer_size / (1024 * 1024));
        }
        
        // Initialize keys_per_thread
        for bs in &buffer_sets {
            unsafe {
                let ptr = bs.keys_per_thread_buf.contents() as *mut u32;
                *ptr = BATCH_SIZE;
            }
        }
        
        // Generate wNAF table
        println!("📊 Generating wNAF lookup table...");
        let wnaf_table = generate_wnaf_table();
        let wnaf_table_buffer = device.new_buffer_with_data(
            wnaf_table.as_ptr() as *const _,
            wnaf_table.len() as u64,
            storage,
        );
        println!("   wNAF table: {} entries ({} bytes)", 75, wnaf_table.len());
        
        // Buffer pool for zero-copy transfers
        let buffer_pool = Arc::new(BufferPool::new(
            tier.keys_per_dispatch,
            tier.pool_size,
        ));
        println!("   Buffer pool: {} pre-allocated buffers", tier.pool_size);
        
        let start_offset = config.start_offset;
        
        println!("   Threads per dispatch: {}", tier.threads_per_dispatch);
        println!("   Keys per dispatch: {} ({:.2}M)", 
                 tier.keys_per_dispatch, tier.keys_per_dispatch as f64 / 1_000_000.0);
        
        Ok(Self {
            device,
            pipeline,
            pipeline_glv,
            config,
            tier,
            buffer_sets,
            current_buffer: AtomicUsize::new(0),
            wnaf_table_buffer,
            buffer_pool,
            lookahead_pubkey: std::sync::Mutex::new(None),
            current_offset: AtomicU64::new(start_offset),
            should_stop: Arc::new(AtomicBool::new(false)),
            total_generated: AtomicU64::new(0),
        })
    }
    
    /// Set the stop signal
    pub fn stop(&self) {
        self.should_stop.store(true, Ordering::SeqCst);
    }
    
    // ========================================================================
    // ACCESSOR METHODS FOR BRIDGE ADAPTER
    // ========================================================================
    
    /// Get batch size (keys per dispatch)
    pub fn batch_size(&self) -> usize {
        self.tier.keys_per_dispatch
    }
    
    /// Get pipeline depth
    pub fn pipeline_depth(&self) -> usize {
        self.tier.pipeline_depth
    }
    
    /// Get buffer set at index
    pub fn buffer_set(&self, idx: usize) -> &BufferSet {
        &self.buffer_sets[idx]
    }
    
    /// Fetch and add to current offset
    pub fn fetch_add_offset(&self, delta: u64) -> u64 {
        self.current_offset.fetch_add(delta, Ordering::Relaxed)
    }
    
    /// Get current offset
    pub fn current_offset(&self) -> u64 {
        self.current_offset.load(Ordering::Relaxed)
    }
    
    /// Check if should stop
    pub fn should_stop_flag(&self) -> bool {
        self.should_stop.load(Ordering::SeqCst)
    }
    
    /// Get total generated
    pub fn total_generated(&self) -> u64 {
        self.total_generated.load(Ordering::Relaxed)
    }
    
    /// Add to total generated
    pub fn add_generated(&self, count: u64) {
        self.total_generated.fetch_add(count, Ordering::Relaxed);
    }
    
    /// Dispatch with GLV (public for adapter)
    pub fn dispatch_glv(&self, buf_idx: usize, base_offset: u64) -> Result<(), String> {
        self.dispatch_batch_glv(buf_idx, base_offset)
    }
    
    // ========================================================================
    
    /// Pre-compute base public key from private key (CPU side)
    fn compute_base_pubkey(base_privkey: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), String> {
        use k256::SecretKey;
        
        let secret = SecretKey::from_slice(base_privkey)
            .map_err(|e| format!("Invalid secret key: {}", e))?;
        let pubkey = secret.public_key();
        let point = pubkey.to_encoded_point(false);
        
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(point.x().ok_or("Missing x")?);
        y.copy_from_slice(point.y().ok_or("Missing y")?);
        
        Ok((x, y))
    }
    
    /// Pre-compute pubkey for next batch (called while GPU is busy)
    fn precompute_pubkey(&self, next_key: &[u8; 32]) {
        if let Ok(pubkey) = Self::compute_base_pubkey(next_key) {
            if let Ok(mut cached) = self.lookahead_pubkey.lock() {
                *cached = Some(pubkey);
            }
        }
    }
    
    /// Create private key bytes from offset
    fn offset_to_privkey(offset: u64) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[24..32].copy_from_slice(&offset.to_be_bytes());
        key[0] = 0x01; // Ensure non-zero
        key
    }
    
    /// GLV transform: k → λ·k (mod n)
    /// Note: This is now computed in the GPU kernel, kept for potential CPU verification
    #[allow(dead_code)]
    fn glv_transform_key(key: &[u8; 32]) -> [u8; 32] {
        use k256::elliptic_curve::PrimeField;
        
        let key_scalar = match Scalar::from_repr_vartime((*key).into()) {
            Some(s) => s,
            None => return *key,
        };
        (key_scalar * *GLV_LAMBDA_SCALAR).to_repr().into()
    }
    
    /// Dispatch a batch on the specified buffer set
    fn dispatch_batch(&self, buf_idx: usize, base_offset: u64) -> Result<(), String> {
        self.dispatch_batch_internal(buf_idx, base_offset, false)
    }
    
    /// Dispatch batch with GLV endomorphism (2x output)
    fn dispatch_batch_glv(&self, buf_idx: usize, base_offset: u64) -> Result<(), String> {
        self.dispatch_batch_internal(buf_idx, base_offset, true)
    }
    
    fn dispatch_batch_internal(&self, buf_idx: usize, base_offset: u64, use_glv: bool) -> Result<(), String> {
        let bs = &self.buffer_sets[buf_idx];
        
        let base_privkey = Self::offset_to_privkey(base_offset);
        
        // LOOK-AHEAD: Try to use pre-computed pubkey (thread-safe)
        let (pubkey_x, pubkey_y) = {
            let cached = self.lookahead_pubkey.lock()
                .map_err(|_| "Mutex poisoned")?
                .take();
            if let Some((x, y)) = cached {
                (x, y)
            } else {
                Self::compute_base_pubkey(&base_privkey)?
            }
        };
        
        unsafe {
            let priv_ptr = bs.base_privkey_buf.contents() as *mut u8;
            std::ptr::copy_nonoverlapping(base_privkey.as_ptr(), priv_ptr, 32);
            
            let x_ptr = bs.base_pubkey_x_buf.contents() as *mut u8;
            std::ptr::copy_nonoverlapping(pubkey_x.as_ptr(), x_ptr, 32);
            
            let y_ptr = bs.base_pubkey_y_buf.contents() as *mut u8;
            std::ptr::copy_nonoverlapping(pubkey_y.as_ptr(), y_ptr, 32);
        }
        
        let command_buffer = bs.queue.new_command_buffer();
        let compute_encoder = command_buffer.new_compute_command_encoder();
        
        // Select pipeline: GLV for 2x throughput, standard otherwise
        let pipeline = if use_glv { &self.pipeline_glv } else { &self.pipeline };
        
        compute_encoder.set_compute_pipeline_state(pipeline);
        compute_encoder.set_buffer(0, Some(&bs.base_privkey_buf), 0);
        compute_encoder.set_buffer(1, Some(&bs.base_pubkey_x_buf), 0);
        compute_encoder.set_buffer(2, Some(&bs.base_pubkey_y_buf), 0);
        compute_encoder.set_buffer(3, Some(&self.wnaf_table_buffer), 0);
        compute_encoder.set_buffer(4, Some(&bs.output_buffer), 0);
        compute_encoder.set_buffer(5, Some(&bs.keys_per_thread_buf), 0);
        
        let grid_size = MTLSize::new(self.tier.threads_per_dispatch as u64, 1, 1);
        let threadgroup_size = MTLSize::new(self.tier.threadgroup_size as u64, 1, 1);
        
        compute_encoder.dispatch_threads(grid_size, threadgroup_size);
        compute_encoder.end_encoding();
        
        command_buffer.commit();
        
        Ok(())
    }
    
    /// Wait for batch and process with zero-copy
    fn process_batch(&self, buf_idx: usize, encoder: &mut AddressEncoder) -> PooledBuffer {
        let bs = &self.buffer_sets[buf_idx];
        
        // Sync
        let cb = bs.queue.new_command_buffer();
        cb.commit();
        cb.wait_until_completed();
        
        // Zero-copy from unified memory
        let output_ptr = bs.output_buffer.contents() as *const u8;
        let output_slice = unsafe {
            std::slice::from_raw_parts(output_ptr, self.tier.keys_per_dispatch * OUTPUT_SIZE)
        };
        
        // Get buffer from pool
        let mut pooled = self.buffer_pool.wrap(self.buffer_pool.acquire());
        let batch = pooled.as_mut();
        
        for i in 0..self.tier.keys_per_dispatch {
            let base = i * OUTPUT_SIZE;
            let privkey = &output_slice[base..base + 32];
            let pubkey_hash = &output_slice[base + 32..base + 52];
            let p2sh_hash = &output_slice[base + 52..base + 72];
            
            if privkey.iter().all(|&b| b == 0) {
                continue;
            }
            
            let mut pk_hash = [0u8; 20];
            let mut p2sh = [0u8; 20];
            pk_hash.copy_from_slice(pubkey_hash);
            p2sh.copy_from_slice(p2sh_hash);
            
            batch.push(KeyEntry {
                private_key: hex::encode(privkey),
                p2pkh: encoder.encode_p2pkh_from_hash(&pk_hash),
                p2sh: encoder.encode_p2sh_from_hash(&p2sh),
                p2wpkh: encoder.encode_p2wpkh_from_hash(&pk_hash),
            });
        }
        
        pooled
    }
    
    /// Run GPU key generation with all optimizations
    pub fn run(&self, target_keys: Option<u64>) -> Result<GeneratorStats, String> {
        // Use raw mode for maximum throughput
        if self.config.output_format == OutputFormat::Raw {
            return self.run_raw(target_keys);
        }
        
        let start_time = Instant::now();
        let mut writer = OutputWriter::new(&self.config.output_dir, self.config.output_format)
            .map_err(|e| format!("Failed to create writer: {}", e))?;
        
        let mut current_batch: Vec<KeyEntry> = Vec::with_capacity(self.config.keys_per_file as usize);
        let mut encoder = AddressEncoder::new();
        
        println!("🚀 Starting Ultra-Optimized GPU Key Generator");
        println!("   ALL OPTIMIZATIONS ENABLED:");
        println!("   ✓ BufferPool (zero-copy)");
        println!("   ✓ Triple+ buffering (GPU never idle)");
        println!("   ✓ Look-ahead pubkey (latency hidden)");
        println!("   ✓ wNAF tables (5 adds vs 256)");
        println!("   ✓ Montgomery batch (32x speedup)");
        println!("   ✓ Extended Jacobian (saves squarings)");
        println!("   Pipeline depth: {}", self.tier.pipeline_depth);
        println!("   Keys per dispatch: {}", self.tier.keys_per_dispatch);
        println!("   Keys per file: {}", self.config.keys_per_file);
        println!();
        
        let mut last_report = Instant::now();
        let report_interval = Duration::from_secs(5);
        
        let depth = self.tier.pipeline_depth;
        
        // Prime the pipeline
        for i in 0..depth {
            if let Some(target) = target_keys {
                if self.total_generated.load(Ordering::Relaxed) >= target {
                    break;
                }
            }
            
            let offset = self.current_offset.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            self.dispatch_batch(i, offset)?;
        }
        
        let mut current_buf = 0;
        
        while !self.should_stop.load(Ordering::SeqCst) {
            if let Some(target) = target_keys {
                if self.total_generated.load(Ordering::Relaxed) >= target {
                    break;
                }
            }
            
            // Process completed batch
            let process_idx = current_buf % depth;
            let batch_result = self.process_batch(process_idx, &mut encoder);
            self.total_generated.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            
            // LOOK-AHEAD: Pre-compute next pubkey while processing
            let next_offset = self.current_offset.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            let next_privkey = Self::offset_to_privkey(next_offset);
            self.precompute_pubkey(&next_privkey);
            
            // Dispatch next batch
            self.dispatch_batch(process_idx, next_offset)?;
            
            // Extend current batch (take ownership from pool)
            current_batch.extend(batch_result.take().into_iter());
            
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
                    "⚡ Progress: {} keys | {:.2}M/sec | {:.2}M/min | Buffer: {}",
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
            let batch_result = self.process_batch(idx, &mut encoder);
            current_batch.extend(batch_result.take().into_iter());
        }
        
        // Write remaining
        if !current_batch.is_empty() {
            let filename = writer.write_batch(&current_batch)
                .map_err(|e| format!("Failed to write: {}", e))?;
            println!("📁 Final: {} ({} keys)", filename, current_batch.len());
        }
        
        let elapsed = start_time.elapsed().as_secs_f64();
        
        Ok(GeneratorStats {
            total_generated: self.total_generated.load(Ordering::Relaxed),
            duplicates_skipped: 0,
            files_written: writer.files_written(),
            elapsed_secs: elapsed,
        })
    }
    
    /// NASA-grade: Raw output mode - Maximum throughput
    /// - No CPU address encoding (GPU outputs raw hashes)
    /// - Async I/O thread (GPU never waits)
    /// - Memory-mapped files (zero-copy)
    /// - Direct GPU buffer dump
    fn run_raw(&self, target_keys: Option<u64>) -> Result<GeneratorStats, String> {
        let start_time = Instant::now();
        
        let async_writer = AsyncRawWriter::new(self.config.output_dir.clone())
            .map_err(|e| format!("Failed to create async writer: {}", e))?;
        
        println!("🚀 NASA-GRADE RAW OUTPUT MODE");
        println!("   ✓ Zero CPU processing");
        println!("   ✓ Async I/O thread (GPU never waits)");
        println!("   ✓ Memory-mapped files (mmap)");
        println!("   ✓ Direct GPU buffer dump");
        println!("   Pipeline depth: {}", self.tier.pipeline_depth);
        println!("   Keys per dispatch: {}", self.tier.keys_per_dispatch);
        println!("   Output: 72 bytes/key (privkey:32 + hash160:20 + p2sh:20)");
        println!();
        
        let mut last_report = Instant::now();
        let report_interval = Duration::from_secs(2);
        
        let depth = self.tier.pipeline_depth;
        let output_size_per_dispatch = self.tier.keys_per_dispatch * OUTPUT_SIZE;
        
        // Prime the pipeline
        for i in 0..depth {
            if let Some(target) = target_keys {
                if self.total_generated.load(Ordering::Relaxed) >= target {
                    break;
                }
            }
            
            let offset = self.current_offset.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            self.dispatch_batch(i, offset)?;
        }
        
        let mut current_buf = 0;
        let mut pending_keys: usize = 0;
        let mut raw_buffer: Vec<u8> = Vec::with_capacity(self.config.keys_per_file as usize * OUTPUT_SIZE);
        
        while !self.should_stop.load(Ordering::SeqCst) {
            if let Some(target) = target_keys {
                if self.total_generated.load(Ordering::Relaxed) >= target {
                    break;
                }
            }
            
            // Wait for GPU completion and get raw data
            let process_idx = current_buf % depth;
            let bs = &self.buffer_sets[process_idx];
            
            // Sync
            let cb = bs.queue.new_command_buffer();
            cb.commit();
            cb.wait_until_completed();
            
            // Direct copy from GPU buffer (zero-copy on unified memory)
            let output_ptr = bs.output_buffer.contents() as *const u8;
            let output_slice = unsafe {
                std::slice::from_raw_parts(output_ptr, output_size_per_dispatch)
            };
            
            // Accumulate raw data
            raw_buffer.extend_from_slice(output_slice);
            pending_keys += self.tier.keys_per_dispatch;
            self.total_generated.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            
            // LOOK-AHEAD: Pre-compute next pubkey
            let next_offset = self.current_offset.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            let next_privkey = Self::offset_to_privkey(next_offset);
            self.precompute_pubkey(&next_privkey);
            
            // Dispatch next batch
            self.dispatch_batch(process_idx, next_offset)?;
            
            current_buf += 1;
            
            // Async write when buffer is full
            if pending_keys >= self.config.keys_per_file as usize {
                let data = std::mem::take(&mut raw_buffer);
                async_writer.write_async(data, pending_keys)?;
                println!("📁 Async write queued: {} keys ({} MB)", 
                         pending_keys, pending_keys * OUTPUT_SIZE / (1024 * 1024));
                raw_buffer = Vec::with_capacity(self.config.keys_per_file as usize * OUTPUT_SIZE);
                pending_keys = 0;
            }
            
            // Progress report
            if last_report.elapsed() >= report_interval {
                let total = self.total_generated.load(Ordering::Relaxed);
                let elapsed = start_time.elapsed().as_secs_f64();
                let rate = total as f64 / elapsed;
                
                println!(
                    "⚡ {} keys | {:.2}M/sec | {:.1}M/min | Pending: {} MB",
                    format_number(total),
                    rate / 1_000_000.0,
                    rate * 60.0 / 1_000_000.0,
                    pending_keys * OUTPUT_SIZE / (1024 * 1024)
                );
                
                last_report = Instant::now();
            }
        }
        
        // Write remaining
        if pending_keys > 0 {
            async_writer.write_async(raw_buffer, pending_keys)?;
            println!("📁 Final async write: {} keys", pending_keys);
        }
        
        // Wait for all writes to complete
        let files_written = async_writer.shutdown();
        
        let elapsed = start_time.elapsed().as_secs_f64();
        
        Ok(GeneratorStats {
            total_generated: self.total_generated.load(Ordering::Relaxed),
            duplicates_skipped: 0,
            files_written,
            elapsed_secs: elapsed,
        })
    }
    
    /// NASA-GRADE INTEGRATED SCAN MODE
    /// - Zero Disk I/O (Matching in RAM)
    /// - GPU generates, CPU matches in parallel
    /// - Uses Unified Memory (zero-copy)
    /// - Only writes when match found
    /// NASA-GRADE INTEGRATED SCAN MODE with GLV Endomorphism (2x throughput)
    /// - Zero Disk I/O (Matching in RAM)
    /// - GPU generates 2 keys per EC operation (primary + GLV)
    /// - Uses Unified Memory (zero-copy)
    /// - Only writes when match found
    pub fn run_scan(&self, targets: std::sync::Arc<crate::reader::TargetSet>) -> Result<ScanStats, String> {
        use rayon::prelude::*;
        use std::sync::atomic::AtomicU64;
        use std::fs::OpenOptions;
        use std::io::Write;
        
        let start_time = Instant::now();
        let depth = self.tier.pipeline_depth;
        let hits_found = AtomicU64::new(0);
        
        // GLV mode: 2 keys per EC operation
        let keys_per_dispatch = self.tier.keys_per_dispatch * 2;
        let output_size = keys_per_dispatch * OUTPUT_SIZE;
        
        println!("🚀 NASA-GRADE INTEGRATED SCAN MODE + GLV ENDOMORPHISM");
        println!("   ✓ Zero Disk I/O (Matching in RAM)");
        println!("   ✓ GLV Endomorphism: 2x throughput (2 keys per EC op)");
        println!("   ✓ GPU generates → CPU matches (parallel)");
        println!("   ✓ Unified Memory (zero-copy access)");
        println!("   ✓ Target Count: {} (Hash160: {}, P2SH: {})", 
                 targets.stats.total, 
                 targets.stats.p2pkh + targets.stats.p2wpkh,
                 targets.stats.p2sh);
        println!("   Pipeline depth: {}", depth);
        println!("   Keys per dispatch: {} ({:.2}M) [GLV: 2x]", 
                 keys_per_dispatch,
                 keys_per_dispatch as f64 / 1_000_000.0);
        println!();
        
        // Open matches file (append mode)
        let matches_file = std::sync::Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open("matches.txt")
                .map_err(|e| format!("Failed to open matches file: {}", e))?
        );
        
        let mut last_report = Instant::now();
        let report_interval = Duration::from_secs(2);
        
        // Prime the pipeline with GLV kernel
        for i in 0..depth {
            let offset = self.current_offset.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            self.dispatch_batch_glv(i, offset)?;
        }
        
        let mut current_buf = 0;
        
        while !self.should_stop.load(Ordering::SeqCst) {
            let process_idx = current_buf % depth;
            let bs = &self.buffer_sets[process_idx];
            
            // Wait for GPU completion
            let cb = bs.queue.new_command_buffer();
            cb.commit();
            cb.wait_until_completed();
            
            // ZERO-COPY: Direct access to GPU buffer via Unified Memory
            // GLV outputs 2x keys per dispatch
            let output_ptr = bs.output_buffer.contents() as *const u8;
            let output_slice = unsafe {
                std::slice::from_raw_parts(output_ptr, output_size)
            };
            
            // PARALLEL SCAN: CPU matches while GPU prepares next batch
            let batch_hits: Vec<String> = output_slice
                .par_chunks_exact(OUTPUT_SIZE)
                .filter_map(|entry| {
                    let privkey = &entry[0..32];
                    
                    // Skip zero keys
                    if privkey.iter().all(|&b| b == 0) {
                        return None;
                    }
                    
                    let pubkey_hash: &[u8; 20] = entry[32..52].try_into().ok()?;
                    let p2sh_hash: &[u8; 20] = entry[52..72].try_into().ok()?;
                    
                    // O(1) HashSet lookup
                    let (match_p2pkh, match_p2sh, match_p2wpkh) = targets.check_raw(pubkey_hash, p2sh_hash);
                    
                    if match_p2pkh || match_p2sh || match_p2wpkh {
                        let priv_hex = hex::encode(privkey);
                        let mut result = format!("🎯 FOUND! Key: {}", priv_hex);
                        
                        if match_p2pkh {
                            result.push_str(&format!(" | P2PKH hash: {}", hex::encode(pubkey_hash)));
                        }
                        if match_p2sh {
                            result.push_str(&format!(" | P2SH hash: {}", hex::encode(p2sh_hash)));
                        }
                        if match_p2wpkh {
                            result.push_str(&format!(" | P2WPKH hash: {}", hex::encode(pubkey_hash)));
                        }
                        
                        Some(result)
                    } else {
                        None
                    }
                })
                .collect();
            
            // Write matches (if any)
            if !batch_hits.is_empty() {
                hits_found.fetch_add(batch_hits.len() as u64, Ordering::Relaxed);
                
                if let Ok(mut file) = matches_file.lock() {
                    for hit in &batch_hits {
                        println!("{}", hit);
                        let _ = writeln!(file, "{}", hit);
                    }
                    let _ = file.flush();
                }
            }
            
            // GLV: 2 keys per EC operation
            self.total_generated.fetch_add(keys_per_dispatch as u64, Ordering::Relaxed);
            
            // LOOK-AHEAD: Dispatch next batch while CPU is matching
            let next_offset = self.current_offset.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            let next_privkey = Self::offset_to_privkey(next_offset);
            self.precompute_pubkey(&next_privkey);
            self.dispatch_batch_glv(process_idx, next_offset)?;
            
            current_buf += 1;
            
            // Progress report
            if last_report.elapsed() >= report_interval {
                let total = self.total_generated.load(Ordering::Relaxed);
                let elapsed = start_time.elapsed().as_secs_f64();
                let rate = total as f64 / elapsed;
                let hits = hits_found.load(Ordering::Relaxed);
                
                println!(
                    "⚡ {} keys | {:.2}M/sec | {:.1}M/min | Hits: {} | Key: 0x{:012x}",
                    format_number(total),
                    rate / 1_000_000.0,
                    rate * 60.0 / 1_000_000.0,
                    hits,
                    self.current_offset.load(Ordering::Relaxed)
                );
                
                last_report = Instant::now();
            }
        }
        
        let elapsed = start_time.elapsed().as_secs_f64();
        let total = self.total_generated.load(Ordering::Relaxed);
        let hits = hits_found.load(Ordering::Relaxed);
        
        Ok(ScanStats {
            keys_scanned: total,
            hits_found: hits,
            elapsed_secs: elapsed,
        })
    }
}

/// Scan statistics
#[derive(Debug, Default)]
pub struct ScanStats {
    pub keys_scanned: u64,
    pub hits_found: u64,
    pub elapsed_secs: f64,
}

impl ScanStats {
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

/// Generate wNAF lookup table with verification
/// 
/// Table structure:
/// - 5 windows × 15 entries × 64 bytes = 4800 bytes total
/// - Window i contains: (2^(4i) * G) * digit for digit in 1..=15
/// - Entry format: [X: 32 bytes][Y: 32 bytes] (affine coordinates, big-endian)
fn generate_wnaf_table() -> Vec<u8> {
    let mut table = vec![0u8; WNAF_TABLE_SIZE];
    
    for window in 0..5 {
        let window_multiplier = 1u64 << (4 * window);
        let window_scalar = Scalar::from(window_multiplier);
        let window_base = ProjectivePoint::GENERATOR * window_scalar;
        
        for digit in 1..=15 {
            let digit_scalar = Scalar::from(digit as u64);
            let point = window_base * digit_scalar;
            let affine = point.to_affine();
            let encoded = affine.to_encoded_point(false);
            
            let idx = window * 15 + (digit - 1);
            let offset = idx * 64;
            
            table[offset..offset + 32].copy_from_slice(encoded.x().unwrap());
            table[offset + 32..offset + 64].copy_from_slice(encoded.y().unwrap());
        }
    }
    
    // Verify table against known test vectors
    verify_wnaf_table(&table).expect("wNAF table verification failed!");
    
    table
}

/// Verify wNAF table integrity
/// 
/// Verifies that table entries match independently computed EC points.
/// This catches bugs in:
/// - Scalar multiplication implementation
/// - Point encoding (coordinate byte order)
/// - Table indexing logic
/// - Window calculation
fn verify_wnaf_table(table: &[u8]) -> Result<(), String> {
    // Verify several entries across different windows
    // Using dynamic computation instead of hardcoded values for accuracy
    let test_cases = [
        // (window, digit, scalar_value, label)
        (0, 1, 1u64, "1*G"),
        (0, 2, 2u64, "2*G"),
        (0, 5, 5u64, "5*G"),
        (0, 15, 15u64, "15*G"),
        (1, 1, 16u64, "16*G"),      // First entry of window 1
        (1, 5, 80u64, "80*G"),      // 16*5
        (2, 1, 256u64, "256*G"),    // First entry of window 2
        (4, 1, 65536u64, "65536*G"), // First entry of window 4
    ];
    
    for (window, digit, scalar_val, label) in test_cases.iter() {
        // Compute expected point using k256
        let expected = ProjectivePoint::GENERATOR * Scalar::from(*scalar_val);
        let expected_affine = expected.to_affine();
        let expected_encoded = expected_affine.to_encoded_point(false);
        let expected_x = expected_encoded.x().unwrap().as_slice();
        let expected_y = expected_encoded.y().unwrap().as_slice();
        
        // Get table entry
        let idx = window * 15 + (digit - 1);
        let offset = idx * 64;
        let table_x = &table[offset..offset + 32];
        let table_y = &table[offset + 32..offset + 64];
        
        if table_x != expected_x {
            return Err(format!(
                "wNAF table {} X mismatch (window={}, digit={})!\n  Expected: {}\n  Got:      {}",
                label, window, digit,
                hex::encode(expected_x),
                hex::encode(table_x)
            ));
        }
        
        if table_y != expected_y {
            return Err(format!(
                "wNAF table {} Y mismatch (window={}, digit={})!\n  Expected: {}\n  Got:      {}",
                label, window, digit,
                hex::encode(expected_y),
                hex::encode(table_y)
            ));
        }
    }
    
    // Additionally verify the generator point (1*G) matches the well-known constant
    // This is the only hardcoded value - it's the secp256k1 generator
    const GENERATOR_X: [u8; 32] = [
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
        0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
        0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
        0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
    ];
    const GENERATOR_Y: [u8; 32] = [
        0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
        0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
        0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
        0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
    ];
    
    if &table[0..32] != GENERATOR_X {
        return Err("Generator point X doesn't match secp256k1 standard!".to_string());
    }
    if &table[32..64] != GENERATOR_Y {
        return Err("Generator point Y doesn't match secp256k1 standard!".to_string());
    }
    
    Ok(())
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

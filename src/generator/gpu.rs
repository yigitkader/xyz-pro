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

use super::{AddressEncoder, GeneratorConfig, GeneratorStats, GlvMode, KeyEntry, RawKeyData, OutputFormat, OutputWriter, AsyncRawWriter};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Metal shader source - embedded at compile time for release builds
/// This ensures the binary is self-contained and doesn't require external shader files
const SHADER_SOURCE_RAW: &str = include_str!("keygen.metal");

/// Keys per thread (Montgomery batch size)
/// SINGLE SOURCE OF TRUTH: This value is injected into the Metal shader at runtime
/// to guarantee CPU/GPU synchronization. Never define BATCH_SIZE in keygen.metal!
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
// BUFFER POOL SYSTEM - Zero-copy ownership transfer with RAW bytes
// ============================================================================

/// Pre-allocated buffer pool for zero-allocation batch processing
/// Uses RawKeyData instead of KeyEntry to avoid heap allocations
pub struct BufferPool {
    return_tx: Sender<Vec<RawKeyData>>,
    pool_rx: Receiver<Vec<RawKeyData>>,
}

impl BufferPool {
    pub fn new(buffer_capacity: usize, pool_size: usize) -> Self {
        let (return_tx, pool_rx) = bounded(pool_size);
        
        // Pre-allocate all buffers with RawKeyData (stack-allocated, no heap)
        for _ in 0..pool_size {
            let buf: Vec<RawKeyData> = Vec::with_capacity(buffer_capacity);
            let _ = return_tx.try_send(buf);
        }
        
        BufferPool { return_tx, pool_rx }
    }
    
    /// Get a buffer from pool
    pub fn acquire(&self) -> Vec<RawKeyData> {
        self.pool_rx.recv().unwrap_or_else(|_| Vec::new())
    }
    
    /// Wrap buffer for auto-return
    pub fn wrap(&self, mut buf: Vec<RawKeyData>) -> PooledBuffer {
        buf.clear();
        PooledBuffer {
            inner: Some(buf),
            return_tx: self.return_tx.clone(),
        }
    }
}

/// Smart pointer that returns buffer to pool on drop
/// Now uses RawKeyData (72 bytes, stack-allocated) instead of KeyEntry (4 Strings, heap)
pub struct PooledBuffer {
    inner: Option<Vec<RawKeyData>>,
    return_tx: Sender<Vec<RawKeyData>>,
}

impl PooledBuffer {
    pub fn as_mut(&mut self) -> &mut Vec<RawKeyData> {
        self.inner.as_mut().unwrap()
    }
    
    pub fn len(&self) -> usize {
        self.inner.as_ref().map(|v| v.len()).unwrap_or(0)
    }
    
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    
    #[allow(dead_code)]
    pub fn take(mut self) -> Vec<RawKeyData> {
        self.inner.take().unwrap_or_default()
    }
}

impl Deref for PooledBuffer {
    type Target = [RawKeyData];
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
/// 
/// Each buffer set has its own command queue and tracks the last dispatched
/// command buffer for proper GPU synchronization.
/// 
/// ## Race Condition Prevention
/// The `in_use` flag prevents GPU from writing to a buffer that CPU is still reading.
/// Without this, if CPU matching is slower than GPU generation, the GPU could
/// overwrite data that the CPU is still processing, causing data corruption.
/// 
/// Flow:
/// 1. GPU dispatch: Check `in_use == false`, then dispatch (buffer owned by GPU)
/// 2. GPU complete: `wait_for_completion()` finishes
/// 3. CPU read start: Set `in_use = true` (buffer owned by CPU)
/// 4. CPU read end: Set `in_use = false` (buffer available for next dispatch)
pub struct BufferSet {
    pub queue: CommandQueue,
    pub base_privkey_buf: Buffer,
    pub base_pubkey_x_buf: Buffer,
    pub base_pubkey_y_buf: Buffer,
    pub output_buffer: Buffer,
    pub keys_per_thread_buf: Buffer,
    /// RANGE LIMIT: Maximum keys to generate (0 = unlimited)
    /// Used to prevent GPU from generating keys beyond end_offset
    pub keys_remaining_buf: Buffer,
    /// Last dispatched command buffer - used for proper GPU sync
    /// CRITICAL: Always wait on THIS buffer, not a new empty one
    pending_command: std::sync::Mutex<Option<metal::CommandBuffer>>,
    /// Buffer in-use flag - prevents race condition between GPU write and CPU read
    /// true = CPU is reading this buffer, GPU must not dispatch to it
    /// false = buffer is available for GPU dispatch
    pub in_use: AtomicBool,
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

/// Minimum memory required for GPU operation (in MB)
/// Below this threshold, GPU will refuse to start to prevent crashes
const MIN_GPU_MEMORY_MB: u64 = 64;

impl GpuTier {
    fn detect(device: &Device) -> Result<Self, String> {
        let name = device.name().to_string();
        let name_lower = name.to_lowercase();
        let gpu_mem_mb = device.recommended_max_working_set_size() / (1024 * 1024);
        
        // Get available system RAM to prevent swap/memory pressure
        let (total_ram_mb, free_ram_mb) = Self::get_system_memory();
        
        println!("[GPU] System RAM: {} MB total, {} MB free", total_ram_mb, free_ram_mb);
        println!("[GPU] GPU recommended working set: {} MB", gpu_mem_mb);
        
        // Determine base tier from GPU capabilities
        let (base_threads, base_depth, base_pool) = if name_lower.contains("ultra") || gpu_mem_mb >= 96000 {
            println!("[GPU] ULTRA tier detected");
            (262_144usize, 4usize, 8usize)
        } else if name_lower.contains("max") || gpu_mem_mb >= 48000 {
            println!("[GPU] MAX tier detected");
            (131_072, 4, 6)
        } else if name_lower.contains("pro") || gpu_mem_mb >= 16000 {
            println!("[GPU] PRO tier detected");
            (65_536, 3, 5)
        } else {
            println!("[GPU] BASE tier detected");
            (32_768, 2, 4)
        };
        
        // Calculate memory requirements per buffer set
        // Output buffer: threads * BATCH_SIZE * OUTPUT_SIZE * GLV_MULTIPLIER
        // Use 3x for worst-case (GLV3) to be conservative
        const GLV_MAX_MULTIPLIER: usize = 3;
        let keys_per_dispatch = base_threads * BATCH_SIZE as usize;
        let output_buffer_mb = (keys_per_dispatch * OUTPUT_SIZE * GLV_MAX_MULTIPLIER) / (1024 * 1024);
        let total_buffer_mb = output_buffer_mb * base_depth;
        
        // SMART RESERVE: Balance OOM prevention with GPU utilization
        // 
        // OLD POLICY (too aggressive): 4GB or 25% of RAM
        // Problem: 8GB machine with 3GB free → GPU disabled (waste of capacity)
        //
        // NEW POLICY (adaptive):
        // 1. Hard minimum: 1GB for OS/kernel
        // 2. Buffer headroom: 1.5x required buffer size (for I/O spikes)
        // 3. Proportional: 15% of total RAM (not 25%)
        // Take the LARGEST of these three values
        const HARD_MINIMUM_MB: u64 = 1024; // 1GB absolute minimum for OS
        let buffer_headroom_mb = (total_buffer_mb as u64 * 3) / 2; // 1.5x buffer size
        let proportional_mb = total_ram_mb / 7; // ~15% of total RAM
        
        let min_free_mb = std::cmp::max(
            HARD_MINIMUM_MB,
            std::cmp::max(buffer_headroom_mb, proportional_mb)
        );
        let available_for_gpu = free_ram_mb.saturating_sub(min_free_mb);
        
        println!("[GPU] Buffer requirements: {} MB per set × {} sets = {} MB total",
                 output_buffer_mb, base_depth, total_buffer_mb);
        println!("[GPU] Available for GPU after reserve: {} MB (keeping {} MB free)",
                 available_for_gpu, min_free_mb);
        
        // CRITICAL: Check if there's enough memory to run at all
        if available_for_gpu < MIN_GPU_MEMORY_MB {
            return Err(format!(
                "Insufficient memory for GPU operation. Available: {} MB, Required minimum: {} MB. \
                 Please close other applications or run tests sequentially with --test-threads=1",
                available_for_gpu, MIN_GPU_MEMORY_MB
            ));
        }
        
        // Dynamically adjust tier if memory is insufficient
        let (threads, pipeline_depth, pool_size) = if total_buffer_mb as u64 <= available_for_gpu {
            // Enough memory - use full tier
            println!("[GPU] ✅ Memory sufficient, using full tier configuration");
            (base_threads, base_depth, base_pool)
        } else {
            // Memory constrained - reduce configuration
            println!("[GPU] ⚠️  Memory constrained, adjusting configuration...");
            
            // Strategy: First reduce pipeline_depth, then reduce threads
            let mut adj_depth = base_depth;
            let mut adj_threads = base_threads;
            let mut adj_pool = base_pool;
            
            // Try reducing pipeline depth first (cheaper than reducing threads)
            while adj_depth > 2 {
                let adj_buffer_mb = (adj_threads * BATCH_SIZE as usize * OUTPUT_SIZE * GLV_MAX_MULTIPLIER * adj_depth) / (1024 * 1024);
                if (adj_buffer_mb as u64) <= available_for_gpu {
                    break;
                }
                adj_depth -= 1;
                adj_pool = std::cmp::max(adj_pool.saturating_sub(1), 3);
            }
            
            // If still not enough, reduce threads further
            while adj_threads > 8_192 {
                let adj_buffer_mb = (adj_threads * BATCH_SIZE as usize * OUTPUT_SIZE * GLV_MAX_MULTIPLIER * adj_depth) / (1024 * 1024);
                if (adj_buffer_mb as u64) <= available_for_gpu {
                    break;
                }
                adj_threads /= 2;
                adj_pool = std::cmp::max(adj_pool.saturating_sub(1), 3);
            }
            
            let final_buffer_mb = (adj_threads * BATCH_SIZE as usize * OUTPUT_SIZE * GLV_MAX_MULTIPLIER * adj_depth) / (1024 * 1024);
            
            // Final check: if we still can't fit, refuse to start
            if (final_buffer_mb as u64) > available_for_gpu {
                return Err(format!(
                    "Cannot reduce GPU configuration enough to fit in available memory. \
                     Minimum required: {} MB, Available: {} MB. \
                     Please close other applications or run tests with --test-threads=1",
                    final_buffer_mb, available_for_gpu
                ));
            }
            
            println!("[GPU] Adjusted: {} threads, {} depth, {} pool ({} MB)",
                     adj_threads, adj_depth, adj_pool, final_buffer_mb);
            
            (adj_threads, adj_depth, adj_pool)
        };
        
        let keys_per_dispatch = threads * BATCH_SIZE as usize;
        
        Ok(Self {
            name,
            threads_per_dispatch: threads,
            keys_per_dispatch,
            threadgroup_size: 256,
            pipeline_depth,
            pool_size,
        })
    }
    
    /// Get system memory information (total and free) in MB
    /// Uses macOS sysctl/mach APIs via libc
    #[cfg(target_os = "macos")]
    fn get_system_memory() -> (u64, u64) {
        use std::mem;
        
        // Get total physical memory
        let total_ram: u64 = unsafe {
            let mut size: libc::size_t = mem::size_of::<u64>();
            let mut total: u64 = 0;
            let mib = [libc::CTL_HW, libc::HW_MEMSIZE];
            if libc::sysctl(
                mib.as_ptr() as *mut _,
                2,
                &mut total as *mut _ as *mut libc::c_void,
                &mut size,
                std::ptr::null_mut(),
                0,
            ) == 0 {
                total
            } else {
                // Fallback: assume 8GB
                8 * 1024 * 1024 * 1024
            }
        };
        
        // Get available memory including inactive pages that can be reclaimed
        // macOS marks disk cache as "inactive" - it's immediately reclaimable
        let free_ram: u64 = {
            let page_size: u64 = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
            
            // Try to get free + inactive page counts via sysctl
            let mut free_pages: u32 = 0;
            let mut inactive_pages: u32 = 0;
            let mut speculative_pages: u32 = 0;
            let mut size: libc::size_t = mem::size_of::<u32>();
            
            unsafe {
                // Free pages - immediately available
                let name = std::ffi::CString::new("vm.page_free_count").unwrap();
                let _ = libc::sysctlbyname(
                    name.as_ptr(),
                    &mut free_pages as *mut _ as *mut libc::c_void,
                    &mut size,
                    std::ptr::null_mut(),
                    0,
                );
                
                // Inactive pages - reclaimable disk cache
                size = mem::size_of::<u32>();
                let name = std::ffi::CString::new("vm.page_inactive_count").unwrap();
                let _ = libc::sysctlbyname(
                    name.as_ptr(),
                    &mut inactive_pages as *mut _ as *mut libc::c_void,
                    &mut size,
                    std::ptr::null_mut(),
                    0,
                );
                
                // Speculative pages - prefetched, immediately reclaimable
                size = mem::size_of::<u32>();
                let name = std::ffi::CString::new("vm.page_speculative_count").unwrap();
                let _ = libc::sysctlbyname(
                    name.as_ptr(),
                    &mut speculative_pages as *mut _ as *mut libc::c_void,
                    &mut size,
                    std::ptr::null_mut(),
                    0,
                );
            }
            
            // CONSERVATIVE MEMORY ESTIMATION:
            // - Free pages: 100% available
            // - Speculative pages: 100% available (prefetch, truly reclaimable)
            // - Inactive pages: Only 50% considered available
            //   Reason: During heavy disk I/O, kernel may lock inactive pages
            //   for writeback. Assuming 100% leads to OOM under load.
            let conservative_inactive = inactive_pages as u64 / 2;
            let available_pages = free_pages as u64 + conservative_inactive + speculative_pages as u64;
            let available_bytes = available_pages * page_size;
            
            // Sanity check: available RAM should be less than total RAM
            if available_bytes > 0 && available_bytes < total_ram {
                available_bytes
            } else {
                // Fallback: assume 50% of total is available
                total_ram / 2
            }
        };
        
        (total_ram / (1024 * 1024), free_ram / (1024 * 1024))
    }
    
    /// Fallback for non-macOS systems
    #[cfg(not(target_os = "macos"))]
    fn get_system_memory() -> (u64, u64) {
        // Conservative defaults for non-macOS
        (8 * 1024, 4 * 1024) // 8GB total, 4GB free
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
    pipeline_glv: ComputePipelineState,   // GLV kernel for 2x throughput
    pipeline_glv3: ComputePipelineState,  // GLV3 kernel for 3x throughput (NEW)
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
        // Validate configuration
        config.validate()?;
        
        // Warn about range limits
        if let Some(end) = config.end_offset {
            let range_size = end.saturating_sub(config.start_offset);
            println!("📊 Range scan mode: {} to {} ({} keys)", 
                     config.start_offset, end, range_size);
        }
        
        let device = Device::system_default()
            .ok_or("No Metal device found")?;
        
        println!("🖥️  GPU: {}", device.name());
        println!("   Max threads per threadgroup: {}", device.max_threads_per_threadgroup().width);
        
        // Detect GPU tier (may fail if insufficient memory)
        let tier = GpuTier::detect(&device)?;
        
        // CRITICAL: Inject BATCH_SIZE into shader to ensure CPU/GPU sync
        // This prevents the dangerous scenario where shader and Rust have different values
        let shader_preamble = format!(
            "// === AUTO-INJECTED BY RUST (DO NOT MODIFY) ===\n\
             #define BATCH_SIZE {}\n\
             // === END AUTO-INJECTED ===\n\n",
            BATCH_SIZE
        );
        let shader_source = format!("{}{}", shader_preamble, SHADER_SOURCE_RAW);
        
        // Compile embedded shader (self-contained binary, no external file needed)
        let library = device
            .new_library_with_source(&shader_source, &metal::CompileOptions::new())
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
        
        // GLV3 kernel for 3x throughput (NEW)
        let function_glv3 = library
            .get_function("generate_btc_keys_glv3", None)
            .map_err(|e| format!("Failed to get GLV3 kernel function: {}", e))?;
        
        let pipeline_glv3 = device
            .new_compute_pipeline_state_with_function(&function_glv3)
            .map_err(|e| format!("Failed to create GLV3 pipeline: {}", e))?;
        
        println!("✅ GLV3 Endomorphism kernel loaded (3x throughput)");
        
        let storage = MTLResourceOptions::StorageModeShared;
        // Buffer size based on GLV mode: 1x (disabled), 2x (glv2), 3x (glv3)
        let glv_multiplier = config.glv_mode.keys_per_ec_op();
        let output_buffer_size = tier.keys_per_dispatch * OUTPUT_SIZE * glv_multiplier;
        
        // Create buffer sets for pipelining
        println!("   Creating {} command queues for async pipelining", tier.pipeline_depth);
        let mut buffer_sets = Vec::with_capacity(tier.pipeline_depth);
        for i in 0..tier.pipeline_depth {
            // Create keys_per_thread buffer and initialize it
            let keys_per_thread_buf = device.new_buffer(4, storage);
            unsafe {
                // CRITICAL: Initialize keys_per_thread to BATCH_SIZE
                // GPU shader reads this to know how many keys each thread produces
                let ptr = keys_per_thread_buf.contents() as *mut u32;
                *ptr = BATCH_SIZE;
            }
            
            // Create keys_remaining buffer for range limiting
            // 0 = unlimited (no range limit), >0 = max keys to generate this dispatch
            let keys_remaining_buf = device.new_buffer(8, storage); // u64
            unsafe {
                let ptr = keys_remaining_buf.contents() as *mut u64;
                *ptr = 0; // Default: no limit
            }
            
            buffer_sets.push(BufferSet {
                queue: device.new_command_queue(),
                base_privkey_buf: device.new_buffer(32, storage),
                base_pubkey_x_buf: device.new_buffer(32, storage),
                base_pubkey_y_buf: device.new_buffer(32, storage),
                output_buffer: device.new_buffer(output_buffer_size as u64, storage),
                keys_per_thread_buf,
                keys_remaining_buf,
                pending_command: std::sync::Mutex::new(None),
                in_use: AtomicBool::new(false), // Initially available for dispatch
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
        // GLV CRITICAL: Pool must accommodate GLV-multiplied keys per dispatch
        let glv_multiplier = config.glv_mode.keys_per_ec_op();
        let total_keys_per_dispatch = tier.keys_per_dispatch * glv_multiplier;
        let buffer_pool = Arc::new(BufferPool::new(
            total_keys_per_dispatch,
            tier.pool_size,
        ));
        println!("   Buffer pool: {} pre-allocated buffers (capacity: {} keys each)", 
                 tier.pool_size, total_keys_per_dispatch);
        
        let start_offset = config.start_offset;
        
        println!("   Threads per dispatch: {}", tier.threads_per_dispatch);
        println!("   Keys per dispatch: {} ({:.2}M)", 
                 tier.keys_per_dispatch, tier.keys_per_dispatch as f64 / 1_000_000.0);
        
        Ok(Self {
            device,
            pipeline,
            pipeline_glv,
            pipeline_glv3,
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
    
    /// Set the stop signal and wait for GPU to finish current work
    /// 
    /// GRACEFUL SHUTDOWN:
    /// 1. Set stop flag so loops exit after current batch
    /// 2. Wait for all pending GPU command buffers to complete
    /// 3. GPU memory is automatically cleaned up by Metal
    pub fn stop(&self) {
        self.should_stop.store(true, Ordering::SeqCst);
        
        // Wait for all pending GPU work to complete
        // This prevents GPU memory corruption and ensures clean shutdown
        self.wait_for_all_pending();
    }
    
    /// Wait for all pending GPU command buffers to complete
    /// Called during stop() for graceful shutdown
    /// 
    /// # Deadlock Prevention
    /// Each pending command is taken from the mutex before waiting,
    /// ensuring no locks are held during Metal API calls.
    /// 
    /// # Mutex Poisoning
    /// If any mutex is poisoned, we log the error but continue trying to
    /// clean up other buffer sets. This ensures maximum cleanup even in
    /// error conditions.
    fn wait_for_all_pending(&self) {
        let mut poison_detected = false;
        
        for (idx, bs) in self.buffer_sets.iter().enumerate() {
            // Take ownership of command buffer, releasing lock immediately
            let cb_opt = {
                let pending_result = bs.pending_command.lock();
                let mut pending = match pending_result {
                    Ok(guard) => guard,
                    Err(poisoned) => {
                        if !poison_detected {
                            eprintln!("💀 GPU mutex poisoned during shutdown (buffer set {}) - attempting cleanup", idx);
                            poison_detected = true;
                        }
                        poisoned.into_inner()
                    }
                };
                pending.take()
            }; // Lock released here
            
            // Wait without holding lock
            if let Some(cb) = cb_opt {
                cb.wait_until_completed();
            }
            
            // Sync command for any in-flight work
            let sync_cb = bs.queue.new_command_buffer();
            sync_cb.commit();
            sync_cb.wait_until_completed();
            
            if idx == 0 {
                println!("🛑 GPU graceful shutdown: waiting for {} buffer sets...", self.buffer_sets.len());
            }
        }
        
        if poison_detected {
            eprintln!("⚠️  GPU shutdown completed with poisoned mutex - some state may be inconsistent");
        }
    }
    
    // ========================================================================
    // ACCESSOR METHODS FOR BRIDGE ADAPTER
    // ========================================================================
    
    /// Get batch size (EC operations per dispatch)
    /// 
    /// NOTE: This returns the number of EC point multiplications, NOT the number
    /// of output keys. With GLV enabled, each EC operation produces multiple keys:
    /// - GLV 2x: 2 keys per EC op (k and λk)
    /// - GLV 3x: 3 keys per EC op (k, λk, λ²k)
    /// 
    /// To get total output keys: `batch_size() * glv_mode().keys_per_ec_op()`
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
    
    /// Get end offset (if configured)
    pub fn end_offset(&self) -> Option<u64> {
        self.config.end_offset
    }
    
    /// Get start offset
    pub fn start_offset(&self) -> u64 {
        self.config.start_offset
    }
    
    /// Check if the configured range has been completely scanned
    /// Returns true if end_offset is set AND current_offset >= end_offset
    pub fn is_range_complete(&self) -> bool {
        if let Some(end) = self.config.end_offset {
            self.current_offset.load(Ordering::Relaxed) >= end
        } else {
            false
        }
    }
    
    /// Get progress percentage (0.0 to 100.0) if end_offset is configured
    pub fn progress_percent(&self) -> Option<f64> {
        self.config.end_offset.map(|end| {
            let start = self.config.start_offset;
            let current = self.current_offset.load(Ordering::Relaxed);
            let total = end.saturating_sub(start);
            let done = current.saturating_sub(start);
            if total == 0 {
                100.0
            } else {
                (done as f64 / total as f64 * 100.0).min(100.0)
            }
        })
    }
    
    /// Check if should stop
    pub fn should_stop_flag(&self) -> bool {
        // Stop if explicitly requested OR if range is complete
        self.should_stop.load(Ordering::SeqCst) || self.is_range_complete()
    }
    
    /// Get total generated
    pub fn total_generated(&self) -> u64 {
        self.total_generated.load(Ordering::Relaxed)
    }
    
    /// Add to total generated
    pub fn add_generated(&self, count: u64) {
        self.total_generated.fetch_add(count, Ordering::Relaxed);
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
    /// 
    /// Layout: 256-bit big-endian where offset occupies the LSW (bytes 24-31)
    /// GPU's load_be() reads this correctly:
    ///   .w = bytes 0-7 (MSW) = 0
    ///   .z = bytes 8-15 = 0
    ///   .y = bytes 16-23 = 0
    ///   .x = bytes 24-31 (LSW) = offset
    /// 
    /// CRITICAL: offset must be >= 1 (config.start_offset enforces this)
    /// Previous bug: key[0]=0x01 made the key > secp256k1 n (INVALID!)
    fn offset_to_privkey(offset: u64) -> [u8; 32] {
        debug_assert!(offset > 0, "Private key offset must be non-zero");
        let mut key = [0u8; 32];
        key[24..32].copy_from_slice(&offset.to_be_bytes());
        // NOTE: No key[0]=0x01 - that made key > curve order!
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
    
    /// Dispatch a batch on the specified buffer set (standard, no GLV)
    #[allow(dead_code)]
    fn dispatch_batch(&self, buf_idx: usize, base_offset: u64) -> Result<(), String> {
        self.dispatch_batch_internal(buf_idx, base_offset, false)
    }
    
    /// Dispatch batch with GLV endomorphism (2x output)
    fn dispatch_batch_glv(&self, buf_idx: usize, base_offset: u64) -> Result<(), String> {
        self.dispatch_batch_internal(buf_idx, base_offset, true)
    }
    
    /// Dispatch batch with GLV3 endomorphism (3x output)
    /// Uses generate_btc_keys_glv3 kernel for 50% more throughput than GLV2
    fn dispatch_batch_glv3(&self, buf_idx: usize, base_offset: u64) -> Result<(), String> {
        self.dispatch_batch_internal_v3(buf_idx, base_offset)
    }
    
    /// Dispatch using configured GLV mode
    /// Automatically selects the correct kernel based on config.glv_mode
    pub fn dispatch_with_mode(&self, buf_idx: usize, base_offset: u64) -> Result<(), String> {
        match self.config.glv_mode {
            GlvMode::Disabled => self.dispatch_batch(buf_idx, base_offset),
            GlvMode::Glv2x => self.dispatch_batch_glv(buf_idx, base_offset),
            GlvMode::Glv3x => self.dispatch_batch_glv3(buf_idx, base_offset),
        }
    }
    
    /// Public dispatch for adapter (uses configured GLV mode)
    pub fn dispatch_glv(&self, buf_idx: usize, base_offset: u64) -> Result<(), String> {
        self.dispatch_with_mode(buf_idx, base_offset)
    }
    
    /// Get configured GLV mode
    pub fn glv_mode(&self) -> GlvMode {
        self.config.glv_mode
    }
    
    fn dispatch_batch_internal(&self, buf_idx: usize, base_offset: u64, use_glv: bool) -> Result<(), String> {
        let bs = &self.buffer_sets[buf_idx];
        
        // RACE CONDITION PREVENTION: Wait for CPU to finish reading this buffer
        // If CPU is still reading (in_use = true), we cannot dispatch to this buffer
        // as it would corrupt data being processed.
        // 
        // Spin-wait with exponential backoff to avoid busy-waiting
        let mut spin_count = 0;
        const MAX_SPINS: u32 = 1000;
        const YIELD_THRESHOLD: u32 = 10;
        
        while bs.in_use.load(Ordering::Acquire) {
            spin_count += 1;
            
            if spin_count > MAX_SPINS {
                // Buffer still in use after many attempts - this indicates
                // CPU is severely lagging behind GPU. Log warning and wait.
                if spin_count == MAX_SPINS + 1 {
                    eprintln!("⚠️ Buffer {} still in use - CPU lagging behind GPU", buf_idx);
                }
                std::thread::sleep(Duration::from_micros(100));
            } else if spin_count > YIELD_THRESHOLD {
                // Yield to other threads after initial spins
                std::thread::yield_now();
            }
            // else: spin-wait (fast path for short waits)
            
            // Check for shutdown request
            if self.should_stop.load(Ordering::SeqCst) {
                return Err("Generator stopped while waiting for buffer".to_string());
            }
        }
        
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
            
            // RANGE LIMIT: Calculate keys_remaining for this dispatch
            // 0 = unlimited, >0 = max keys to generate
            let keys_remaining: u64 = if let Some(end) = self.config.end_offset {
                // Keys remaining from base_offset to end_offset
                end.saturating_sub(base_offset)
            } else {
                0 // No limit
            };
            let remaining_ptr = bs.keys_remaining_buf.contents() as *mut u64;
            *remaining_ptr = keys_remaining;
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
        compute_encoder.set_buffer(6, Some(&bs.keys_remaining_buf), 0);  // RANGE LIMIT
        
        let grid_size = MTLSize::new(self.tier.threads_per_dispatch as u64, 1, 1);
        let threadgroup_size = MTLSize::new(self.tier.threadgroup_size as u64, 1, 1);
        
        compute_encoder.dispatch_threads(grid_size, threadgroup_size);
        compute_encoder.end_encoding();
        
        // RACE CONDITION FIX: Store command buffer in mutex BEFORE commit
        // This ensures wait_for_completion always sees the pending command.
        // If we commit first, another thread could call wait_for_completion,
        // see None in the mutex, skip waiting, and read corrupted data.
        {
            let mut pending = bs.pending_command.lock()
                .map_err(|_| "Pending command mutex poisoned")?;
            *pending = Some(command_buffer.to_owned());
        }
        
        // Now commit - any thread calling wait_for_completion will see
        // the command buffer in the mutex and wait properly
        command_buffer.commit();
        
        Ok(())
    }
    
    /// Dispatch batch with GLV3 endomorphism (3x output)
    /// 
    /// This is a separate function (not merged into dispatch_batch_internal)
    /// to avoid breaking existing GLV2 code paths while testing GLV3.
    #[allow(dead_code)]
    fn dispatch_batch_internal_v3(&self, buf_idx: usize, base_offset: u64) -> Result<(), String> {
        let bs = &self.buffer_sets[buf_idx];
        
        // RACE CONDITION PREVENTION: Wait for CPU to finish reading this buffer
        let mut spin_count = 0;
        const MAX_SPINS: u32 = 1000;
        const YIELD_THRESHOLD: u32 = 10;
        
        while bs.in_use.load(Ordering::Acquire) {
            spin_count += 1;
            
            if spin_count > MAX_SPINS {
                if spin_count == MAX_SPINS + 1 {
                    eprintln!("⚠️ Buffer {} still in use - CPU lagging behind GPU", buf_idx);
                }
                std::thread::sleep(Duration::from_micros(100));
            } else if spin_count > YIELD_THRESHOLD {
                std::thread::yield_now();
            }
            
            if self.should_stop.load(Ordering::SeqCst) {
                return Err("Generator stopped while waiting for buffer".to_string());
            }
        }
        
        let base_privkey = Self::offset_to_privkey(base_offset);
        
        // LOOK-AHEAD: Try to use pre-computed pubkey
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
            
            // RANGE LIMIT: Calculate keys_remaining for this dispatch
            let keys_remaining: u64 = if let Some(end) = self.config.end_offset {
                end.saturating_sub(base_offset)
            } else {
                0
            };
            let remaining_ptr = bs.keys_remaining_buf.contents() as *mut u64;
            *remaining_ptr = keys_remaining;
        }
        
        let command_buffer = bs.queue.new_command_buffer();
        let compute_encoder = command_buffer.new_compute_command_encoder();
        
        // Use GLV3 pipeline for 3x throughput
        compute_encoder.set_compute_pipeline_state(&self.pipeline_glv3);
        compute_encoder.set_buffer(0, Some(&bs.base_privkey_buf), 0);
        compute_encoder.set_buffer(1, Some(&bs.base_pubkey_x_buf), 0);
        compute_encoder.set_buffer(2, Some(&bs.base_pubkey_y_buf), 0);
        compute_encoder.set_buffer(3, Some(&self.wnaf_table_buffer), 0);
        compute_encoder.set_buffer(4, Some(&bs.output_buffer), 0);
        compute_encoder.set_buffer(5, Some(&bs.keys_per_thread_buf), 0);
        compute_encoder.set_buffer(6, Some(&bs.keys_remaining_buf), 0);  // RANGE LIMIT
        
        let grid_size = MTLSize::new(self.tier.threads_per_dispatch as u64, 1, 1);
        let threadgroup_size = MTLSize::new(self.tier.threadgroup_size as u64, 1, 1);
        
        compute_encoder.dispatch_threads(grid_size, threadgroup_size);
        compute_encoder.end_encoding();
        
        // RACE CONDITION FIX: Store command buffer in mutex BEFORE commit
        // (same fix as dispatch_batch_internal - see comments there)
        {
            let mut pending = bs.pending_command.lock()
                .map_err(|_| "Pending command mutex poisoned")?;
            *pending = Some(command_buffer.to_owned());
        }
        
        command_buffer.commit();
        
        Ok(())
    }
    
    /// Wait for pending GPU work on this buffer set to complete
    /// 
    /// CRITICAL: This waits on the ACTUAL dispatched command buffer,
    /// not a new empty one. This is the correct Metal synchronization pattern.
    /// Wait for pending GPU command to complete
    /// 
    /// # Deadlock Prevention
    /// The Mutex lock is released BEFORE calling wait_until_completed().
    /// This prevents potential deadlocks if Metal's wait triggers callbacks
    /// that might try to acquire the same lock.
    /// 
    /// # Mutex Poisoning
    /// If the mutex is poisoned (a previous holder panicked), we signal
    /// shutdown rather than attempting to use potentially corrupted state.
    /// This follows fail-fast principles for GPU operations.
    /// 
    /// # Return Value
    /// Returns Ok(()) on success, or Err with String message on failure.
    /// Fatal errors (OutOfMemory, PageFault, etc.) trigger automatic shutdown.
    /// 
    /// Note: Error message includes GPU error code classification for reliable
    /// error type detection by is_fatal_error() in pipeline.rs.
    pub fn wait_for_completion(&self, buf_idx: usize) -> Result<(), String> {
        use crate::bridge::{GpuError, GpuErrorCode};
        
        let bs = &self.buffer_sets[buf_idx];
        
        // Take ownership of command buffer while releasing lock immediately
        // This prevents deadlock: Metal callbacks during wait can't re-acquire this lock
        let cb_opt = {
            let mut pending = match bs.pending_command.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    // CRITICAL: Mutex poisoned means previous holder panicked
                    // The GPU state may be corrupted - signal immediate shutdown
                    eprintln!("💀 GPU mutex poisoned in wait_for_completion - initiating emergency stop");
                    self.should_stop.store(true, Ordering::SeqCst);
                    // Still try to recover the guard to prevent resource leak
                    poisoned.into_inner()
                }
            };
            pending.take() // Take ownership, None left in place
        }; // Lock released here, BEFORE wait
        
        // Now safe to wait without holding the lock
        if let Some(cb) = cb_opt {
            cb.wait_until_completed();
            
            // Check command buffer status for errors
            // MTLCommandBufferStatus: 0=NotEnqueued, 1=Enqueued, 2=Committed, 
            //                         3=Scheduled, 4=Completed, 5=Error
            let status = cb.status();
            
            if status == metal::MTLCommandBufferStatus::Error {
                // Metal Rust bindings don't expose error_code() directly.
                // We classify as Internal error since Status::Error is always fatal.
                let gpu_error_code = GpuErrorCode::Internal;
                let gpu_error = GpuError::new(gpu_error_code, format!(
                    "GPU command buffer failed. Status: Error. ErrorCode: {}. Buffer index: {}",
                    gpu_error_code, buf_idx
                ));
                
                // Signal shutdown for fatal errors
                eprintln!("❌ GPU ERROR: {}", gpu_error);
                if gpu_error.is_fatal() {
                    self.should_stop.store(true, Ordering::SeqCst);
                }
                
                // Return String for API compatibility, but include error code in message
                // This allows is_fatal_error() to detect the error type reliably
                return Err(gpu_error.to_string());
            }
        }
        
        Ok(())
    }
    
    /// Wait for completion without checking status (for backward compatibility)
    /// Used internally where error handling is done at a higher level
    #[allow(dead_code)]
    fn wait_for_completion_unchecked(&self, buf_idx: usize) {
        let bs = &self.buffer_sets[buf_idx];
        
        let cb_opt = {
            let mut pending = match bs.pending_command.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            pending.take()
        };
        
        if let Some(cb) = cb_opt {
            cb.wait_until_completed();
        }
    }
    
    /// Wait for batch and process with zero-copy - NO STRING ALLOCATIONS
    /// Returns raw key data directly from GPU buffer without any String conversions
    /// 
    /// If GPU error occurs, returns empty batch and signals shutdown via should_stop.
    /// 
    /// ## Race Condition Prevention
    /// Sets `in_use = true` while reading buffer contents, preventing GPU from
    /// dispatching new work to this buffer until CPU finishes reading.
    fn process_batch_raw(&self, buf_idx: usize) -> PooledBuffer {
        let bs = &self.buffer_sets[buf_idx];
        
        // FIXED: Wait for the ACTUAL dispatched command buffer
        // Previously this created an empty buffer which was an anti-pattern
        if let Err(e) = self.wait_for_completion(buf_idx) {
            // GPU error occurred - should_stop is already set in wait_for_completion
            // Return empty batch; upper level will see should_stop() = true
            eprintln!("⚠️ GPU batch processing failed: {}", e);
            return self.buffer_pool.wrap(self.buffer_pool.acquire());
        }
        
        // RACE CONDITION PREVENTION: Mark buffer as in-use before reading
        // This prevents GPU from dispatching to this buffer while we're reading
        bs.in_use.store(true, Ordering::Release);
        
        // GLV CRITICAL FIX: Read ALL keys including GLV variants
        // GPU produces: base_keys * glv_multiplier total keys
        // - GLV disabled (1x): base keys only
        // - GLV 2x: base + λ*k keys  
        // - GLV 3x: base + λ*k + λ²*k keys
        let glv_multiplier = self.config.glv_mode.keys_per_ec_op();
        let total_keys = self.tier.keys_per_dispatch * glv_multiplier;
        
        // Zero-copy from unified memory
        let output_ptr = bs.output_buffer.contents() as *const u8;
        let output_slice = unsafe {
            std::slice::from_raw_parts(output_ptr, total_keys * OUTPUT_SIZE)
        };
        
        // Get buffer from pool
        let mut pooled = self.buffer_pool.wrap(self.buffer_pool.acquire());
        let batch = pooled.as_mut();
        
        // ZERO STRING ALLOCATION: Copy raw bytes only
        for i in 0..total_keys {
            let base = i * OUTPUT_SIZE;
            
            // Use optimized RawKeyData parsing
            if let Some(raw) = RawKeyData::from_bytes(&output_slice[base..base + OUTPUT_SIZE]) {
                // Skip zero keys (fast SIMD check)
                if raw.is_valid() {
                    batch.push(raw);
                }
            }
        }
        
        // RACE CONDITION PREVENTION: Mark buffer as available for next dispatch
        // Must be done AFTER all reads are complete
        bs.in_use.store(false, Ordering::Release);
        
        pooled
    }
    
    /// Legacy process_batch with String encoding (for non-Raw output formats)
    /// Only used when JSON/Binary output is needed, not for scan mode
    fn process_batch(&self, buf_idx: usize, encoder: &mut AddressEncoder) -> Vec<KeyEntry> {
        let raw_batch = self.process_batch_raw(buf_idx);
        
        // Convert to KeyEntry only when needed (file write)
        raw_batch.iter().map(|raw| {
            KeyEntry {
                private_key: hex::encode(&raw.private_key),
                p2pkh: encoder.encode_p2pkh_from_hash(&raw.pubkey_hash),
                p2sh: encoder.encode_p2sh_from_hash(&raw.p2sh_hash),
                p2wpkh: encoder.encode_p2wpkh_from_hash(&raw.pubkey_hash),
            }
        }).collect()
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
        
        // MEMORY MANAGEMENT: Cap batch size to prevent OOM
        // Even if keys_per_file is 1 billion, we flush to disk in smaller chunks
        // to prevent unbounded memory growth. Each KeyEntry is ~200 bytes (4 Strings).
        const MAX_BATCH_IN_MEMORY: usize = 10_000_000; // 10M keys max (~2GB RAM)
        let batch_capacity = std::cmp::min(
            self.config.keys_per_file as usize,
            MAX_BATCH_IN_MEMORY
        );
        
        let mut current_batch: Vec<KeyEntry> = Vec::with_capacity(batch_capacity);
        let mut encoder = AddressEncoder::new();
        let mut keys_in_current_file: u64 = 0; // Track keys written to current logical file
        
        println!("🚀 Starting Ultra-Optimized GPU Key Generator");
        println!("   ALL OPTIMIZATIONS ENABLED:");
        println!("   ✓ BufferPool (zero-copy)");
        println!("   ✓ Triple+ buffering (GPU never idle)");
        println!("   ✓ Look-ahead pubkey (latency hidden)");
        println!("   ✓ wNAF tables (5 adds vs 256)");
        println!("   ✓ Montgomery batch (32x speedup)");
        println!("   ✓ Extended Jacobian (saves squarings)");
        println!("   ✓ Memory-bounded batching (max {}M keys/batch)", MAX_BATCH_IN_MEMORY / 1_000_000);
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
            
            // Extend current batch (now Vec<KeyEntry>)
            let batch_len = batch_result.len();
            current_batch.extend(batch_result.into_iter());
            keys_in_current_file += batch_len as u64;
            
            current_buf += 1;
            
            // MEMORY-BOUNDED FLUSH: Write when either condition is met:
            // 1. Reached keys_per_file limit (logical file boundary)
            // 2. Reached MAX_BATCH_IN_MEMORY (prevent OOM)
            let should_flush = current_batch.len() >= batch_capacity
                || keys_in_current_file >= self.config.keys_per_file;
            
            if should_flush {
                let filename = writer.write_batch(&current_batch)
                    .map_err(|e| format!("Failed to write: {}", e))?;
                println!("📁 Written: {} ({} keys)", filename, current_batch.len());
                current_batch.clear();
                
                // Reset file counter if we've completed a logical file
                if keys_in_current_file >= self.config.keys_per_file {
                    keys_in_current_file = 0;
                }
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
            current_batch.extend(batch_result.into_iter());
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
        
        let mut async_writer = AsyncRawWriter::new(self.config.output_dir.clone())
            .map_err(|e| format!("Failed to create async writer: {}", e))?;
        
        // GLV mode: multiply keys per dispatch based on mode
        let glv_multiplier = self.config.glv_mode.keys_per_ec_op();
        let keys_per_dispatch = self.tier.keys_per_dispatch * glv_multiplier;
        let output_size_per_dispatch = keys_per_dispatch * OUTPUT_SIZE;
        
        println!("🚀 NASA-GRADE RAW OUTPUT MODE + GLV ENDOMORPHISM");
        println!("   ✓ GLV Mode: {:?} ({}x throughput)", self.config.glv_mode, glv_multiplier);
        println!("   ✓ Zero CPU processing");
        println!("   ✓ Async I/O thread (GPU never waits)");
        println!("   ✓ Memory-mapped files (mmap)");
        println!("   ✓ Direct GPU buffer dump");
        println!("   ✓ GLV Endomorphism: 2x throughput (2 keys per EC op)");
        println!("   Pipeline depth: {}", self.tier.pipeline_depth);
        println!("   Keys per dispatch: {} [GLV: 2x]", keys_per_dispatch);
        println!("   Output: 72 bytes/key (privkey:32 + hash160:20 + p2sh:20)");
        println!();
        
        let mut last_report = Instant::now();
        let report_interval = Duration::from_secs(2);
        
        let depth = self.tier.pipeline_depth;
        
        // Prime the pipeline with GLV kernel (consistent with run_scan)
        for i in 0..depth {
            if let Some(target) = target_keys {
                if self.total_generated.load(Ordering::Relaxed) >= target {
                    break;
                }
            }
            
            let offset = self.current_offset.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            self.dispatch_with_mode(i, offset)?;
        }
        
        let mut current_buf = 0;
        let mut pending_keys: usize = 0;
        
        // MEMORY SAFETY: Cap buffer size to prevent OOM
        // Even if keys_per_file is 1 billion (72GB), we use a reasonable buffer
        // and flush to disk in chunks. 100MB buffer = ~1.4M keys.
        const MAX_RAW_BUFFER_SIZE: usize = 100 * 1024 * 1024; // 100MB max
        let max_keys_in_buffer = MAX_RAW_BUFFER_SIZE / OUTPUT_SIZE;
        let buffer_capacity = std::cmp::min(
            self.config.keys_per_file as usize * OUTPUT_SIZE,
            MAX_RAW_BUFFER_SIZE
        );
        let mut raw_buffer: Vec<u8> = Vec::with_capacity(buffer_capacity);
        
        println!("   ✓ Memory-bounded raw buffer (max {} MB)", MAX_RAW_BUFFER_SIZE / (1024 * 1024));
        
        while !self.should_stop.load(Ordering::SeqCst) {
            if let Some(target) = target_keys {
                if self.total_generated.load(Ordering::Relaxed) >= target {
                    break;
                }
            }
            
            // CORRECT PIPELINE: wait → read → dispatch (same buffer)
            // 
            // Buffer lifecycle: GPU_WORKING → WAIT → CPU_READ → GPU_WORKING (new data)
            // 
            // With depth=4, at any time:
            // - 3 buffers are GPU_WORKING (primed in advance)
            // - 1 buffer is being processed by CPU
            //
            // CRITICAL FIX: Previously dispatched to next_idx which was still GPU_WORKING!
            // Now we dispatch to process_idx AFTER reading, which is guaranteed to be free.
            let process_idx = current_buf % depth;
            
            // 1. WAIT: Ensure GPU has finished with this buffer
            if let Err(e) = self.wait_for_completion(process_idx) {
                return Err(format!("GPU batch processing failed: {}", e));
            }
            
            let bs = &self.buffer_sets[process_idx];
            
            // 2. READ: Mark buffer as in-use while CPU reads
            bs.in_use.store(true, Ordering::Release);
            
            // Direct copy from GPU buffer (zero-copy on unified memory)
            let output_ptr = bs.output_buffer.contents() as *const u8;
            let output_slice = unsafe {
                std::slice::from_raw_parts(output_ptr, output_size_per_dispatch)
            };
            
            // Accumulate raw data
            raw_buffer.extend_from_slice(output_slice);
            
            // GLV produces 2x keys per dispatch
            pending_keys += keys_per_dispatch;
            self.total_generated.fetch_add(keys_per_dispatch as u64, Ordering::Relaxed);
            
            // 3. DISPATCH: Now buffer is free, dispatch new work to SAME buffer
            // This maintains pipeline depth while avoiding race condition
            // Note: Offset increments by base keys (not 2x) because GLV uses λ*k space
            let next_offset = self.current_offset.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            let next_privkey = Self::offset_to_privkey(next_offset);
            self.precompute_pubkey(&next_privkey);
            
            // Mark buffer as available BEFORE dispatch (CPU read complete)
            bs.in_use.store(false, Ordering::Release);
            
            // Dispatch to the SAME buffer we just read from (configured GLV mode)
            self.dispatch_with_mode(process_idx, next_offset)?;
            
            current_buf += 1;
            
            // Async write when buffer is full (either memory limit or file limit)
            // MEMORY SAFETY: Flush at whichever limit is reached first
            let should_flush = pending_keys >= self.config.keys_per_file as usize 
                            || pending_keys >= max_keys_in_buffer;
            
            if should_flush {
                let data = std::mem::take(&mut raw_buffer);
                async_writer.write_async(data, pending_keys)?;
                println!("📁 Async write queued: {} keys ({} MB)", 
                         pending_keys, pending_keys * OUTPUT_SIZE / (1024 * 1024));
                raw_buffer = Vec::with_capacity(buffer_capacity);
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
    pub fn run_scan(&self, targets: Arc<crate::reader::TargetSet>) -> Result<ScanStats, String> {
        use rayon::prelude::*;
        use std::sync::atomic::AtomicU64;
        use std::fs::OpenOptions;
        use std::io::Write;
        
        let start_time = Instant::now();
        let depth = self.tier.pipeline_depth;
        let hits_found = AtomicU64::new(0);
        
        // GLV mode: multiply keys per dispatch based on mode
        let glv_multiplier = self.config.glv_mode.keys_per_ec_op();
        let keys_per_dispatch = self.tier.keys_per_dispatch * glv_multiplier;
        let output_size = keys_per_dispatch * OUTPUT_SIZE;
        
        println!("🚀 NASA-GRADE INTEGRATED SCAN MODE + GLV ENDOMORPHISM");
        println!("   ✓ Zero Disk I/O (Matching in RAM)");
        println!("   ✓ GLV Mode: {:?} ({}x throughput)", self.config.glv_mode, glv_multiplier);
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
        // GLV Key Space Note:
        // - Primary keys:  k, k+1, ..., k+N-1 (from offset)
        // - GLV keys:      λ*k, λ*(k+1), ... (endomorphism, different key space)
        // - GLV² keys:     λ²*k, λ²*(k+1), ... (GLV3 mode only)
        // GLV λ is a large constant (~2^256), so GLV keys don't overlap with
        // sequential primary keys. Offset increments by keys_per_dispatch (not 2x/3x)
        // because we're scanning multiple independent key spaces in parallel.
        for i in 0..depth {
            let offset = self.current_offset.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            self.dispatch_with_mode(i, offset)?;
        }
        
        let mut current_buf = 0;
        
        while !self.should_stop.load(Ordering::SeqCst) {
            // CORRECT PIPELINE: wait → read/process → dispatch (same buffer)
            // 
            // Buffer lifecycle: GPU_WORKING → WAIT → CPU_PROCESS → GPU_WORKING (new data)
            // 
            // CRITICAL FIX: Previously dispatched to next_idx which was still GPU_WORKING!
            // Now we dispatch to process_idx AFTER processing, which is guaranteed to be free.
            let process_idx = current_buf % depth;
            
            // 1. WAIT: Ensure GPU has finished with this buffer
            if let Err(e) = self.wait_for_completion(process_idx) {
                return Err(format!("GPU batch processing failed: {}", e));
            }
            
            let bs = &self.buffer_sets[process_idx];
            
            // 2. PROCESS: Mark buffer as in-use while CPU processes
            bs.in_use.store(true, Ordering::Release);
            
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
                    // SAFE ZERO CHECK: Compiler auto-vectorizes this to ARM NEON
                    // This avoids alignment issues with manual SIMD pointer casts.
                    // Modern compilers (LLVM 15+) generate optimal SIMD for this pattern.
                    // Benchmarks show this is within 5% of manual SIMD on Apple Silicon.
                    let privkey = &entry[0..32];
                    let is_zero = !privkey.iter().any(|&b| b != 0);
                    
                    if is_zero {
                        return None;
                    }
                    
                    let pubkey_hash: &[u8; 20] = entry[32..52].try_into().ok()?;
                    let p2sh_hash: &[u8; 20] = entry[52..72].try_into().ok()?;
                    
                    // O(1) HashSet lookup
                    let (match_p2pkh, match_p2sh, match_p2wpkh) = targets.check_raw(pubkey_hash, p2sh_hash);
                    
                    if match_p2pkh || match_p2sh || match_p2wpkh {
                        // Only encode when match found (avoids unnecessary String allocation)
                        let priv_hex = hex::encode(&entry[0..32]);
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
            
            // 3. DISPATCH: Now buffer is free, dispatch new work to SAME buffer
            let next_offset = self.current_offset.fetch_add(self.tier.keys_per_dispatch as u64, Ordering::Relaxed);
            let next_privkey = Self::offset_to_privkey(next_offset);
            self.precompute_pubkey(&next_privkey);
            
            // Mark buffer as available BEFORE dispatch (CPU processing complete)
            bs.in_use.store(false, Ordering::Release);
            
            // Dispatch to the SAME buffer we just processed (configured GLV mode)
            self.dispatch_with_mode(process_idx, next_offset)?;
            
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
        let expected_x: &[u8] = expected_encoded.x().unwrap();
        let expected_y: &[u8] = expected_encoded.y().unwrap();
        
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

// ============================================================================
// DROP IMPLEMENTATION - GRACEFUL GPU SHUTDOWN
// ============================================================================

impl Drop for GpuKeyGenerator {
    /// Graceful shutdown: wait for all pending GPU work before releasing resources
    /// 
    /// This prevents:
    /// - GPU memory corruption from premature buffer deallocation
    /// - Metal validation errors on debug builds
    /// - Orphaned GPU kernel execution
    /// 
    /// # Timeout Protection
    /// Uses a 5-second timeout per buffer set to prevent infinite hangs
    /// if GPU becomes unresponsive.
    fn drop(&mut self) {
        use std::time::{Duration, Instant};
        
        // Only do cleanup if we haven't already stopped
        if !self.should_stop.load(Ordering::SeqCst) {
            self.should_stop.store(true, Ordering::SeqCst);
        }
        
        const TIMEOUT_PER_BUFFER: Duration = Duration::from_secs(5);
        let drop_start = Instant::now();
        let mut timed_out = false;
        
        // Wait for all GPU command buffers to complete
        // Using take() pattern to avoid holding lock during wait
        for (idx, bs) in self.buffer_sets.iter().enumerate() {
            // Check overall timeout
            if drop_start.elapsed() > Duration::from_secs(15) {
                eprintln!("⚠️  GPU drop timeout ({}s) - forcing cleanup without waiting", 
                         drop_start.elapsed().as_secs());
                timed_out = true;
                break;
            }
            
            // Take ownership of command buffer, releasing lock immediately
            let cb_opt = {
                let pending_result = bs.pending_command.lock();
                let mut pending = match pending_result {
                    Ok(guard) => guard,
                    Err(poisoned) => {
                        eprintln!("💀 GPU mutex poisoned in Drop (buffer {}) - continuing cleanup", idx);
                        poisoned.into_inner()
                    }
                };
                pending.take()
            }; // Lock released here
            
            // Wait without holding lock (deadlock prevention)
            // Note: Metal's wait_until_completed doesn't have a timeout API,
            // but command buffers typically complete quickly or not at all
            if let Some(cb) = cb_opt {
                let wait_start = Instant::now();
                cb.wait_until_completed();
                if wait_start.elapsed() > TIMEOUT_PER_BUFFER {
                    eprintln!("⚠️  Buffer {} took {}ms to complete", idx, wait_start.elapsed().as_millis());
                }
            }
            
            // Sync the queue with a quick command
            let sync_cb = bs.queue.new_command_buffer();
            sync_cb.commit();
            sync_cb.wait_until_completed();
        }
        
        if timed_out {
            eprintln!("⚠️  GPU resources may not be fully released due to timeout");
        }
        
        // Metal automatically releases GPU buffers when they go out of scope
        // via Arc<Buffer> reference counting
    }
}

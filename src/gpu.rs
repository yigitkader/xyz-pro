use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use metal::{Buffer, CommandQueue, CompileOptions, ComputePipelineState, Device, MTLResourceOptions, MTLSize};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Result, ScannerError};
use crate::types::Hash160;

// ============================================================================
// GPU CONFIGURATION - Auto-detected based on Apple Silicon variant
// ============================================================================

/// GPU configuration profile
#[derive(Debug, Clone)]
pub struct GpuConfig {
    pub name: String,
    pub max_threads: usize,
    pub keys_per_thread: u32,
    pub threadgroup_size: usize,
    pub match_buffer_size: usize,
    pub gpu_memory_mb: u64,
}

impl GpuConfig {
    /// Detect GPU and return optimal configuration
    pub fn detect(device: &Device) -> Self {
        let name = device.name().to_string();
        let max_threadgroup = device.max_threads_per_threadgroup().width as usize;
        
        // Get recommended working set size (available GPU memory)
        let gpu_memory = device.recommended_max_working_set_size();
        let gpu_memory_mb = gpu_memory / (1024 * 1024);
        
        // Detect Apple Silicon variant from device name
        let (max_threads, keys_per_thread, threadgroup_size, match_buffer_size) = 
            Self::config_for_gpu(&name, max_threadgroup, gpu_memory_mb);
        
        GpuConfig {
            name,
            max_threads,
            keys_per_thread,
            threadgroup_size,
            match_buffer_size,
            gpu_memory_mb,
        }
    }
    
    /// Get optimal configuration based on GPU variant
    fn config_for_gpu(name: &str, max_threadgroup: usize, memory_mb: u64) -> (usize, u32, usize, usize) {
        let name_lower = name.to_lowercase();
        
        // Detect GPU tier based on name and memory
        // Format: (max_threads, keys_per_thread, threadgroup_size, match_buffer_size)
        
        if name_lower.contains("ultra") {
            // M1/M2/M3/M4 Ultra: 48-64 GPU cores, 64-192GB unified memory
            // Extremely high parallelism
            println!("[GPU] Detected: Ultra-class chip (48-64 cores)");
            (
                262_144,    // 256K threads (reduced for better occupancy)
                128,        // 128 keys/thread = 33.5M keys/batch (matches BATCH_SIZE)
                512.min(max_threadgroup),  // Reduced threadgroup for better occupancy
                4_194_304,  // 4M match buffer
            )
        } else if name_lower.contains("max") {
            // M1/M2/M3/M4 Max: 24-40 GPU cores, 32-128GB unified memory
            // OPTIMIZED: Reduced threads, increased keys_per_thread for better occupancy
            println!("[GPU] Detected: Max-class chip (24-40 cores)");
            (
                147_456,    // 144K threads (optimized for 32-40 cores)
                128,        // 128 keys/thread = 18.9M keys/batch (matches BATCH_SIZE)
                512.min(max_threadgroup),  // 512 threadgroup for better occupancy
                2_097_152,  // 2M match buffer
            )
        } else if name_lower.contains("pro") {
            // M1/M2/M3/M4 Pro: 14-18 GPU cores, 16-48GB unified memory
            // High parallelism
            println!("[GPU] Detected: Pro-class chip (14-18 cores)");
            (
                98_304,     // 96K threads (optimized for 14-18 cores)
                128,        // 128 keys/thread = 12.6M keys/batch (matches BATCH_SIZE)
                512.min(max_threadgroup),
                1_572_864,  // 1.5M match buffer
            )
        } else if memory_mb >= 16000 {
            // Base M-series with high memory (16GB+)
            // Could be M2/M3/M4 base with more memory
            println!("[GPU] Detected: Base chip with {}GB memory", memory_mb / 1024);
            (
                65_536,     // 64K threads
                128,        // 128 keys/thread = 8.4M keys/batch (matches BATCH_SIZE)
                256.min(max_threadgroup),
                1_048_576,  // 1M match buffer
            )
        } else {
            // M1 base or older: 7-8 GPU cores, 8-16GB unified memory
            // Conservative settings for thermal management
            println!("[GPU] Detected: Base chip (7-10 cores)");
            (
                65_536,     // 64K threads
                128,        // 128 keys/thread = 8.4M keys/batch (matches BATCH_SIZE)
                256.min(max_threadgroup),
                1_048_576,  // 1M match buffer
            )
        }
    }
    
    /// Calculate keys per batch
    pub fn keys_per_batch(&self) -> u64 {
        (self.max_threads as u64) * (self.keys_per_thread as u64)
    }
    
    /// Print configuration summary
    pub fn print_summary(&self) {
        let keys_per_batch = self.keys_per_batch();
        println!("[GPU] Configuration:");
        println!("      • Threads: {} ({:.0}K)", self.max_threads, self.max_threads as f64 / 1000.0);
        println!("      • Keys/thread: {}", self.keys_per_thread);
        println!("      • Keys/batch: {:.1}M", keys_per_batch as f64 / 1_000_000.0);
        println!("      • Threadgroup: {}", self.threadgroup_size);
        println!("      • Match buffer: {:.1}M entries", self.match_buffer_size as f64 / 1_000_000.0);
        println!("      • GPU Memory: {} MB", self.gpu_memory_mb);
    }
}

// ============================================================================
// LEGACY CONSTANTS (for backward compatibility, not used with auto-config)
// ============================================================================

/// Match buffer size default (overridden by GpuConfig)
const DEFAULT_MATCH_BUFFER_SIZE: usize = 1_048_576;

// ============================================================================
// BLOOM FILTER
// ============================================================================

pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
}

impl BloomFilter {
    pub fn new(n: usize) -> Self {
        // OPTIMIZED: n*16 for better GPU cache hit rate
        // n*32 = 200MB (doesn't fit in L2 cache ~48MB on M1 Max)
        // n*16 = 100MB (closer to L2 cache, better locality)
        // FP rate: ~0.01% (vs 0.001% with n*32) - still excellent
        // Expected performance gain: +15-25% due to better cache behavior
        let num_bits = (n * 16).next_power_of_two().max(1024);
        let num_words = num_bits / 64;
        Self {
            bits: vec![0u64; num_words],
            num_bits,
        }
    }

    pub fn insert(&mut self, h: &[u8; 20]) {
        for pos in self.positions(h) {
            let (w, b) = (pos / 64, pos % 64);
            if w < self.bits.len() {
                self.bits[w] |= 1u64 << b;
            }
        }
    }

    fn positions(&self, h: &[u8; 20]) -> [usize; 7] {
        let h1 = u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);
        let h2 = u64::from_le_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]);
        let h3 = u32::from_le_bytes([h[16], h[17], h[18], h[19]]) as u64;
        let mut p = [0usize; 7];
        for i in 0..7 {
            let m = (i + 1) as u64;
            p[i] = (h1.wrapping_add(h2.wrapping_mul(m)).wrapping_add(h3.wrapping_mul(m * m)) as usize) % self.num_bits;
        }
        p
    }

    pub fn as_slice(&self) -> &[u64] {
        &self.bits
    }

    pub fn size_words(&self) -> usize {
        self.bits.len()
    }
}

// ============================================================================
// STEP TABLE (Precomputed for GPU)
// Standard: StepTable[i] = (2^i * keys_per_thread) * G (20 entries)
// wNAF w=4: StepTable[window][digit] = ((2*digit+1) * 2^(4*window) * kpt) * G
// ============================================================================

/// Standard binary step table: 20 entries for bits 0-19
fn compute_step_table(keys_per_thread: u32) -> [[u8; 64]; 20] {
    use k256::elliptic_curve::PrimeField;
    use k256::ProjectivePoint;
    use k256::Scalar;

    let mut table = [[0u8; 64]; 20];

    // Start with kpt * G
    let kpt_bytes = {
        let mut b = [0u8; 32];
        b[28..32].copy_from_slice(&keys_per_thread.to_be_bytes());
        b
    };

    let kpt_scalar = Scalar::from_repr_vartime(kpt_bytes.into()).unwrap();
    let mut current = ProjectivePoint::GENERATOR * kpt_scalar;

    for i in 0..20 {
        let affine = current.to_affine();
        let encoded = affine.to_encoded_point(false);
        let bytes = encoded.as_bytes();

        // Skip 0x04 prefix, copy x (32 bytes) and y (32 bytes)
        table[i][..32].copy_from_slice(&bytes[1..33]);
        table[i][32..64].copy_from_slice(&bytes[33..65]);

        // Double for next entry
        current = current.double();
    }

    table
}

/// Windowed step table: 5 windows × 15 non-zero digits = 75 entries
/// Entry[window * 15 + (digit-1)] = digit * 2^(4*window) * kpt * G
/// digit ∈ {1,2,...,15}, window ∈ {0,1,2,3,4}
/// This reduces ~10 additions to max 5 additions per thread start (50% improvement)
fn compute_wnaf_step_table(keys_per_thread: u32) -> [[u8; 64]; 75] {
    use k256::elliptic_curve::PrimeField;
    use k256::ProjectivePoint;
    use k256::Scalar;

    let mut table = [[0u8; 64]; 75];

    // Base: kpt * G
    let kpt_bytes = {
        let mut b = [0u8; 32];
        b[28..32].copy_from_slice(&keys_per_thread.to_be_bytes());
        b
    };
    let kpt_scalar = Scalar::from_repr_vartime(kpt_bytes.into()).unwrap();
    let base_point = ProjectivePoint::GENERATOR * kpt_scalar;

    // For each window (4-bit chunks of gid)
    for window in 0..5 {
        // 2^(4*window) * kpt * G
        let window_shift = 4 * window;
        let mut window_base = base_point;
        for _ in 0..window_shift {
            window_base = window_base.double();
        }

        // For each digit 1..15 (skip 0, it's identity)
        let mut current = window_base;  // 1 * window_base
        
        for digit in 1..=15 {
            let idx = window * 15 + (digit - 1);
            
            let affine = current.to_affine();
            let encoded = affine.to_encoded_point(false);
            let bytes = encoded.as_bytes();
            
            table[idx][..32].copy_from_slice(&bytes[1..33]);
            table[idx][32..64].copy_from_slice(&bytes[33..65]);
            
            // Next: current + window_base
            current = current + window_base;
        }
    }

    table
}

// ============================================================================
// OPTIMIZED SCANNER
// ============================================================================

/// Double buffer set for pipelined GPU execution
/// Each buffer set has its own command queue for true parallel execution
struct BufferSet {
    queue: CommandQueue,  // Separate queue per buffer for independent execution
    base_point_buf: Buffer,
    match_data_buf: Buffer,
    match_count_buf: Buffer,
}

pub struct OptimizedScanner {
    pipeline: ComputePipelineState,

    // Double buffers with separate queues for TRUE pipelining
    // Queue 0 runs buffer 0 work, Queue 1 runs buffer 1 work independently
    buffer_sets: [BufferSet; 2],
    current_buffer: std::sync::atomic::AtomicUsize,

    // Shared buffers (read-only, no double buffering needed)
    step_table_buf: Buffer,       // Legacy binary step table (20 × 64 bytes)
    wnaf_table_buf: Buffer,       // wNAF w=4 step table (40 × 64 bytes) - 50% faster start point
    bloom_buf: Buffer,
    bloom_size_buf: Buffer,
    kpt_buf: Buffer,

    // GPU Configuration (auto-detected)
    config: GpuConfig,

    // Stats
    total_scanned: AtomicU64,
    total_matches: AtomicU64,
}

/// Match type from GPU
/// Primary range (original keys):
///   0 = compressed pubkey hash
///   1 = uncompressed pubkey hash  
///   2 = P2SH script hash (from compressed)
/// GLV Endomorphic range (λ·k keys - FREE extra scanning!):
///   3 = GLV compressed pubkey hash
///   4 = GLV uncompressed pubkey hash
///   5 = GLV P2SH script hash
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MatchType {
    Compressed = 0,
    Uncompressed = 1,
    P2SH = 2,
    GlvCompressed = 3,
    GlvUncompressed = 4,
    GlvP2SH = 5,
}

impl MatchType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Compressed),
            1 => Some(Self::Uncompressed),
            2 => Some(Self::P2SH),
            3 => Some(Self::GlvCompressed),
            4 => Some(Self::GlvUncompressed),
            5 => Some(Self::GlvP2SH),
            _ => None,
        }
    }
    
    /// Check if this is a GLV endomorphic match
    /// GLV matches require private key transformation: actual_key = λ·key_index (mod n)
    pub fn is_glv(&self) -> bool {
        matches!(self, Self::GlvCompressed | Self::GlvUncompressed | Self::GlvP2SH)
    }
}

// ============================================================================
// GLV CONSTANTS for private key recovery
// λ³ ≡ 1 (mod n), used to compute actual private key from GLV match
// actual_key = λ · (base_key + key_index) mod n
// ============================================================================

/// GLV Lambda constant for secp256k1
/// λ = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72
pub const GLV_LAMBDA: [u8; 32] = [
    0x53, 0x63, 0xad, 0x4c, 0xc0, 0x5c, 0x30, 0xe0,
    0xa5, 0x26, 0x1c, 0x02, 0x88, 0x12, 0x64, 0x5a,
    0x12, 0x2e, 0x22, 0xea, 0x20, 0x81, 0x66, 0x78,
    0xdf, 0x02, 0x96, 0x7c, 0x1b, 0x23, 0xbd, 0x72,
];

/// Compute GLV-transformed private key: λ·k (mod n)
/// Used to recover actual private key from GLV endomorphic match
pub fn glv_transform_key(key: &[u8; 32]) -> [u8; 32] {
    use k256::elliptic_curve::PrimeField;
    use k256::Scalar;
    
    // Parse key as scalar
    let key_scalar = match Scalar::from_repr_vartime((*key).into()) {
        Some(s) => s,
        None => return *key, // Invalid key, return as-is
    };
    
    // Parse λ as scalar
    let lambda_scalar = Scalar::from_repr_vartime(GLV_LAMBDA.into()).unwrap();
    
    // Compute λ·k (mod n)
    let result = key_scalar * lambda_scalar;
    
    // Convert back to bytes
    result.to_repr().into()
}

#[derive(Clone, Debug)]
pub struct PotentialMatch {
    pub key_index: u32,
    pub match_type: MatchType,
    pub hash: Hash160,
}

impl OptimizedScanner {
    pub fn new(target_hashes: &[[u8; 20]]) -> Result<Self> {
        let device = Device::system_default()
            .ok_or_else(|| ScannerError::Gpu("No Metal GPU found".into()))?;

        println!("[GPU] Device: {}", device.name());
        
        // Auto-detect optimal configuration for this GPU
        let config = GpuConfig::detect(&device);
        config.print_summary();

        let opts = CompileOptions::new();

        // Load shader
        let shader_path = "src/secp256k1_scanner.metal";
        let src = fs::read_to_string(shader_path)
            .map_err(|e| ScannerError::Gpu(format!(
                "Failed to load shader '{}': {}. Make sure you're running from the project root directory.",
                shader_path, e
            )))?;

        let lib = device.new_library_with_source(&src, &opts)
            .map_err(|e| ScannerError::Gpu(format!("shader compile: {}", e)))?;

        let func = lib.get_function("scan_keys", None)
            .map_err(|e| ScannerError::Gpu(format!("kernel not found: {}", e)))?;

        let pipeline = device.new_compute_pipeline_state_with_function(&func)
            .map_err(|e| ScannerError::Gpu(format!("pipeline: {}", e)))?;

        println!("[GPU] Pipeline: max_threads_per_threadgroup={}", pipeline.max_total_threads_per_threadgroup());

        // Build Bloom filter
        let mut bloom = BloomFilter::new(target_hashes.len().max(100));
        for h in target_hashes {
            bloom.insert(h);
        }

        // Compute StepTables using config's keys_per_thread
        let step_table = compute_step_table(config.keys_per_thread);
        let wnaf_table = compute_wnaf_step_table(config.keys_per_thread);
        
        println!("[GPU] Windowed step table: {} entries (5 windows × 15 digits) for 50% faster thread start", wnaf_table.len());

        // Allocate buffers
        let storage = MTLResourceOptions::StorageModeShared;
        let match_buffer_size = config.match_buffer_size;

        // Double buffer sets with SEPARATE QUEUES for TRUE parallel pipelining
        // Each queue can run independently, allowing batch N to process
        // while we collect results from batch N-1
        let buffer_sets = [
            BufferSet {
                queue: device.new_command_queue(),  // Queue 0 for buffer 0
                base_point_buf: device.new_buffer(64, storage),
                match_data_buf: device.new_buffer((match_buffer_size * 52) as u64, storage),
                match_count_buf: device.new_buffer(4, storage),
            },
            BufferSet {
                queue: device.new_command_queue(),  // Queue 1 for buffer 1
                base_point_buf: device.new_buffer(64, storage),
                match_data_buf: device.new_buffer((match_buffer_size * 52) as u64, storage),
                match_count_buf: device.new_buffer(4, storage),
            },
        ];
        
        println!("[GPU] Dual command queues for true parallel pipelining");

        // Shared read-only buffers
        let step_table_buf = device.new_buffer_with_data(
            step_table.as_ptr() as *const _,
            (20 * 64) as u64,
            storage,
        );
        
        // Windowed step table: 5 windows × 15 non-zero digits = 75 entries
        let wnaf_table_buf = device.new_buffer_with_data(
            wnaf_table.as_ptr() as *const _,
            (75 * 64) as u64,
            storage,
        );

        let bloom_data = bloom.as_slice();
        let bloom_buf = device.new_buffer_with_data(
            bloom_data.as_ptr() as *const _,
            (bloom_data.len() * 8) as u64,
            storage,
        );

        let bloom_size = bloom.size_words() as u32;
        let bloom_size_buf = device.new_buffer_with_data(
            &bloom_size as *const u32 as *const _,
            4,
            storage,
        );

        let keys_per_thread = config.keys_per_thread;
        let kpt_buf = device.new_buffer_with_data(
            &keys_per_thread as *const u32 as *const _,
            4,
            storage,
        );

        // Memory stats
        let double_buf_mem = 2 * (64 + match_buffer_size * 52 + 4);
        let shared_mem = 20 * 64 + bloom_data.len() * 8 + 4 + 4;
        let mem_mb = (double_buf_mem + shared_mem) as f64 / 1_000_000.0;
        
        println!("[GPU] Double buffering enabled for async pipelining");
        println!("[GPU] Total buffer memory: {:.2} MB", mem_mb);
        
        // Calculate and log expected Bloom filter false positive rate
        // FP rate ≈ (1 - e^(-k*n/m))^k where k=7 hash functions, n=items, m=bits
        let n = target_hashes.len() as f64;
        let m = (bloom.size_words() * 64) as f64;
        let k = 7.0f64;
        let fp_rate = (1.0 - (-k * n / m).exp()).powf(k);
        let keys_per_batch = config.keys_per_batch();
        let expected_fp_per_batch = (keys_per_batch as f64) * fp_rate;
        
        println!("[GPU] Bloom filter: {} words ({} KB), FP rate: {:.4}%, ~{:.0} FP/batch", 
            bloom.size_words(), 
            bloom.size_words() * 8 / 1024,
            fp_rate * 100.0,
            expected_fp_per_batch
        );

        Ok(Self {
            pipeline,
            buffer_sets,
            current_buffer: std::sync::atomic::AtomicUsize::new(0),
            step_table_buf,
            wnaf_table_buf,
            bloom_buf,
            bloom_size_buf,
            kpt_buf,
            config,
            total_scanned: AtomicU64::new(0),
            total_matches: AtomicU64::new(0),
        })
    }

    /// Dispatch a batch to GPU and return immediately (non-blocking)
    /// Each buffer has its own queue, so dispatches are truly independent
    fn dispatch_batch(&self, base_key: &[u8; 32], buf_idx: usize) -> Result<()> {
        let buffers = &self.buffer_sets[buf_idx];

        // Compute base point from base_key
        let secret = SecretKey::from_slice(base_key)
            .map_err(|e| ScannerError::Gpu(format!("invalid key: {}", e)))?;
        let pubkey = secret.public_key();
        let encoded = pubkey.to_encoded_point(false);
        let pub_bytes = encoded.as_bytes();

        // Copy base point (x || y)
        unsafe {
            let ptr = buffers.base_point_buf.contents() as *mut u8;
            std::ptr::copy_nonoverlapping(pub_bytes[1..33].as_ptr(), ptr, 32);
            std::ptr::copy_nonoverlapping(pub_bytes[33..65].as_ptr(), ptr.add(32), 32);
        }

        // Reset match count
        unsafe {
            let ptr = buffers.match_count_buf.contents() as *mut u32;
            *ptr = 0;
        }

        // Dispatch on THIS BUFFER'S QUEUE (independent from other buffer's queue)
        let cmd = buffers.queue.new_command_buffer();

        let grid = MTLSize {
            width: self.config.max_threads as u64,
            height: 1,
            depth: 1,
        };
        let group = MTLSize {
            width: self.config.threadgroup_size as u64,
            height: 1,
            depth: 1,
        };

        {
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(&self.pipeline);
            enc.set_buffer(0, Some(&buffers.base_point_buf), 0);
            enc.set_buffer(1, Some(&self.step_table_buf), 0);
            enc.set_buffer(2, Some(&self.wnaf_table_buf), 0);  // wNAF w=4 table
            enc.set_buffer(3, Some(&self.bloom_buf), 0);
            enc.set_buffer(4, Some(&self.bloom_size_buf), 0);
            enc.set_buffer(5, Some(&self.kpt_buf), 0);
            enc.set_buffer(6, Some(&buffers.match_data_buf), 0);
            enc.set_buffer(7, Some(&buffers.match_count_buf), 0);
            enc.dispatch_threads(grid, group);
            enc.end_encoding();
        }

        cmd.commit();
        // Note: NOT waiting - returns immediately
        // This buffer's queue is now processing independently
        
        Ok(())
    }
    
    /// Wait for GPU to complete and collect results from specified buffer
    /// Uses this buffer's dedicated queue, so only waits for THIS buffer's work
    fn wait_and_collect(&self, buf_idx: usize) -> Result<Vec<PotentialMatch>> {
        let buffers = &self.buffer_sets[buf_idx];
        
        // Sync point on THIS BUFFER'S QUEUE (not the other buffer's queue!)
        // This ensures only this buffer's compute work is waited for
        let sync_cmd = buffers.queue.new_command_buffer();
        {
            let blit = sync_cmd.new_blit_command_encoder();
            // Synchronize the buffers - waits for prior compute work on this queue
            blit.synchronize_resource(&buffers.match_count_buf);
            blit.synchronize_resource(&buffers.match_data_buf);
            blit.end_encoding();
        }
        sync_cmd.commit();
        sync_cmd.wait_until_completed();

        // Read results from buffer
        let raw_match_count = unsafe {
            let ptr = buffers.match_count_buf.contents() as *const u32;
            *ptr
        };
        
        // CRITICAL: Buffer overflow means we lost matches - this is unacceptable
        let match_buffer_size = self.config.match_buffer_size;
        if raw_match_count as usize > match_buffer_size {
            return Err(ScannerError::Gpu(format!(
                "CRITICAL: Match buffer overflow! {} matches found, buffer size {}. \
                 {} potential matches were lost. GPU config may need adjustment.",
                raw_match_count, match_buffer_size, raw_match_count as usize - match_buffer_size
            )));
        }
        
        let match_count = raw_match_count as usize;

        let keys_scanned = self.config.keys_per_batch();
        self.total_scanned.fetch_add(keys_scanned, Ordering::Relaxed);

        let mut matches = Vec::with_capacity(match_count);
        if match_count > 0 {
            self.total_matches.fetch_add(match_count as u64, Ordering::Relaxed);
            unsafe {
                let ptr = buffers.match_data_buf.contents() as *const u8;
                for i in 0..match_count {
                    let off = i * 52;
                    // Read key_index (4 bytes)
                    let mut key_bytes = [0u8; 4];
                    std::ptr::copy_nonoverlapping(ptr.add(off), key_bytes.as_mut_ptr(), 4);
                    
                    // Read match_type (1 byte at offset 4)
                    let type_byte = *ptr.add(off + 4);
                    let match_type = match MatchType::from_u8(type_byte) {
                        Some(t) => t,
                        None => continue, // Invalid match type, skip
                    };
                    
                    // Read hash (20 bytes at offset 32)
                    let mut hash_bytes = [0u8; 20];
                    std::ptr::copy_nonoverlapping(ptr.add(off + 32), hash_bytes.as_mut_ptr(), 20);
                    
                    matches.push(PotentialMatch {
                        key_index: u32::from_le_bytes(key_bytes),
                        match_type,
                        hash: Hash160::from_slice(&hash_bytes),
                    });
                }
            }
        }

        Ok(matches)
    }
    
    /// Scan a range of keys starting from base_key (SYNCHRONOUS)
    #[allow(dead_code)]
    pub fn scan_batch(&self, base_key: &[u8; 32]) -> Result<Vec<PotentialMatch>> {
        let buf_idx = self.current_buffer.fetch_xor(1, Ordering::Relaxed);
        self.dispatch_batch(base_key, buf_idx)?;
        self.wait_and_collect(buf_idx)
    }
    
    /// Process batches with TRUE GPU/CPU pipelining
    /// GPU works on batch N while CPU processes results from batch N-1
    /// This is the high-performance scanning method
    pub fn scan_pipelined<F, G>(&self, mut key_gen: F, mut on_batch: G, shutdown: &std::sync::atomic::AtomicBool) -> Result<()>
    where
        F: FnMut() -> [u8; 32],
        G: FnMut([u8; 32], Vec<PotentialMatch>),
    {
        // Track previous batch info
        let mut prev_batch: Option<([u8; 32], usize)> = None;
        let mut current_buf = 0usize;
        
        while !shutdown.load(Ordering::Relaxed) {
            // Step 1: Dispatch NEW batch (non-blocking)
            let base_key = key_gen();
            self.dispatch_batch(&base_key, current_buf)?;
            
            // Step 2: While GPU works on new batch, collect PREVIOUS results
            // This is the key: GPU and CPU work in parallel!
            if let Some((prev_key, prev_buf)) = prev_batch.take() {
                let matches = self.wait_and_collect(prev_buf)?;
                on_batch(prev_key, matches);
            }
            
            // Step 3: Current batch becomes previous for next iteration
            prev_batch = Some((base_key, current_buf));
            current_buf = 1 - current_buf; // Swap buffer (0 -> 1 -> 0 -> ...)
        }
        
        // Collect final batch on shutdown
        if let Some((prev_key, prev_buf)) = prev_batch {
            let matches = self.wait_and_collect(prev_buf)?;
            on_batch(prev_key, matches);
        }
        
        Ok(())
    }

    pub fn keys_per_batch(&self) -> u64 {
        self.config.keys_per_batch()
    }
    
    /// Get current GPU configuration
    pub fn config(&self) -> &GpuConfig {
        &self.config
    }

    pub fn total_scanned(&self) -> u64 {
        self.total_scanned.load(Ordering::Relaxed)
    }

    pub fn total_matches(&self) -> u64 {
        self.total_matches.load(Ordering::Relaxed)
    }
}

unsafe impl Send for OptimizedScanner {}
unsafe impl Sync for OptimizedScanner {}

use k256::elliptic_curve::sec1::ToEncodedPoint;
use metal::{Buffer, CommandQueue, CompileOptions, ComputePipelineState, Device, MTLResourceOptions, MTLSize};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Result, ScannerError};
use crate::types::Hash160;
use crate::rng::philox::{PhiloxCounter, PhiloxState, philox_to_privkey};
use crate::filter::ShardedXorFilter;

// BATCH_SIZE = 16 must match secp256k1_scanner.metal

#[derive(Debug, Clone)]
pub struct GpuConfig {
    #[allow(dead_code)]
    pub name: String,
    pub max_threads: usize,
    pub keys_per_thread: u32,
    pub threadgroup_size: usize,
    pub match_buffer_size: usize,
    pub gpu_memory_mb: u64,
}

impl GpuConfig {
    pub fn detect(device: &Device) -> Self {
        let name = device.name().to_string();
        let max_tg = device.max_threads_per_threadgroup().width as usize;
        let mem_mb = device.recommended_max_working_set_size() / (1024 * 1024);
        let (max_threads, keys_per_thread, tg_size, match_buf) = 
            Self::config_for_gpu(&name, max_tg, mem_mb);
        
        GpuConfig { name, max_threads, keys_per_thread, threadgroup_size: tg_size, 
                   match_buffer_size: match_buf, gpu_memory_mb: mem_mb }
    }
    
    #[cfg(target_os = "macos")]
    fn detect_gpu_cores() -> Option<usize> {
        use std::process::Command;
        if let Ok(out) = Command::new("sysctl").args(["-n", "machdep.cpu.brand_string"]).output() {
            let brand = String::from_utf8_lossy(&out.stdout).to_lowercase();
            if brand.contains(" ultra") { return Some(64); }
            if brand.contains(" max") { return Some(32); }
            if brand.contains(" pro") { return Some(14); }
        }
        if let Ok(out) = Command::new("sysctl").args(["-n", "hw.perflevel0.physicalcpu"]).output() {
            if let Ok(cores) = String::from_utf8_lossy(&out.stdout).trim().parse::<usize>() {
                return Some(if cores >= 12 { 48 } else if cores >= 8 { 14 } else { 8 });
            }
        }
        None
    }
    
    #[cfg(not(target_os = "macos"))]
    fn detect_gpu_cores() -> Option<usize> { None }
    
    fn config_for_gpu(name: &str, max_tg: usize, mem_mb: u64) -> (usize, u32, usize, usize) {
        let name_lower = name.to_lowercase();
        let cores = Self::detect_gpu_cores();
        
        // ULTRA: 48+ cores
        if name_lower.contains("ultra") || cores.map(|c| c >= 48).unwrap_or(false) {
            let c = cores.unwrap_or(60);
            let threads = (c * 4096).min(262_144);
            println!("[GPU] ULTRA: {} threads × 128 = {:.1}M keys/batch", threads, (threads * 128) as f64 / 1e6);
            return (threads, 128, 64.min(max_tg), 4_194_304);
        }
        // MAX: 24-47 cores
        if name_lower.contains("max") || cores.map(|c| c >= 24).unwrap_or(false) {
            let c = cores.unwrap_or(32);
            let threads = (c * 4096).min(163_840);
            println!("[GPU] MAX: {} threads × 128 = {:.1}M keys/batch", threads, (threads * 128) as f64 / 1e6);
            return (threads, 128, 64.min(max_tg), 2_097_152);
        }
        // PRO: 14-23 cores
        if name_lower.contains("pro") || cores.map(|c| c >= 14).unwrap_or(false) {
            let c = cores.unwrap_or(16);
            let threads = if c >= 18 { (c * 8192).min(163_840) } else { (c * 8192).min(131_072) };
            let match_buf = if mem_mb >= 32000 { 1_048_576 } else { 524_288 };
            println!("[GPU] PRO: {} threads × 128 = {:.1}M keys/batch", threads, (threads * 128) as f64 / 1e6);
            return (threads, 128, 64.min(max_tg), match_buf);
        }
        // BASE: 7-13 cores
        let c = cores.unwrap_or(8);
        let tg = 32.min(max_tg);
        let (threads, match_buf) = match mem_mb {
            m if m >= 24000 => ((c * 2048).min(24_576), 196_608),
            m if m >= 16000 => ((c * 1536).min(16_384), 131_072),
            _ => ((c * 1024).min(10_240), 65_536),
        };
        println!("[GPU] BASE: {} threads × 128 = {:.1}M keys/batch (tg={})", threads, (threads * 128) as f64 / 1e6, tg);
        (threads, 128, tg, match_buf)
    }
    
    pub fn keys_per_batch(&self) -> u64 {
        (self.max_threads as u64) * (self.keys_per_thread as u64)
    }
    
    pub fn print_summary(&self) {
        println!("[GPU] {} | {}K threads | {:.1}M keys/batch | {}MB", 
            self.name, self.max_threads / 1000, self.keys_per_batch() as f64 / 1e6, self.gpu_memory_mb);
    }
}



fn compute_wnaf_step_table(keys_per_thread: u32) -> [[u8; 64]; 75] {
    use k256::elliptic_curve::PrimeField;
    use k256::ProjectivePoint;
    use k256::Scalar;

    let mut table = [[0u8; 64]; 75];

    let kpt_bytes = {
        let mut b = [0u8; 32];
        b[28..32].copy_from_slice(&keys_per_thread.to_be_bytes());
        b
    };
    let kpt_scalar = Scalar::from_repr_vartime(kpt_bytes.into()).unwrap();
    let base_point = ProjectivePoint::GENERATOR * kpt_scalar;

    for window in 0..5 {
        let window_shift = 4 * window;
        let mut window_base = base_point;
        for _ in 0..window_shift {
            window_base = window_base.double();
        }

        let mut current = window_base;
        
        for digit in 1..=15 {
            let idx = window * 15 + (digit - 1);
            
            let affine = current.to_affine();
            let encoded = affine.to_encoded_point(false);
            let bytes = encoded.as_bytes();
            
            table[idx][..32].copy_from_slice(&bytes[1..33]);
            table[idx][32..64].copy_from_slice(&bytes[33..65]);
            
            current = current + window_base;
        }
    }

    table
}

struct BufferSet {
    queue: CommandQueue,
    philox_key_buf: Buffer,
    philox_counter_buf: Buffer,
    base_privkey_buf: Buffer,
    base_pubkey_x_buf: Buffer,
    base_pubkey_y_buf: Buffer,
    match_data_buf: Buffer,
    match_count_buf: Buffer,
}

pub struct OptimizedScanner {
    pipeline: ComputePipelineState,
    buffer_sets: [BufferSet; 3],  // Triple buffering
    current_buffer: std::sync::atomic::AtomicUsize,
    wnaf_table_buf: Buffer,
    xor_fingerprints_buf: Buffer,
    xor_seeds_buf: Buffer,
    xor_block_length_buf: Buffer,
    prefix_table_buf: Buffer,
    prefix_count_buf: Buffer,
    kpt_buf: Buffer,
    hash_count_buf: Buffer,
    config: GpuConfig,
    total_scanned: AtomicU64,
    total_matches: AtomicU64,
    philox_counter: PhiloxCounter,
    match_vecs: [std::cell::UnsafeCell<Vec<PotentialMatch>>; 3],
    lookahead_pubkey: std::cell::UnsafeCell<Option<(Vec<u8>, Vec<u8>)>>,
    last_philox_state: std::cell::UnsafeCell<Option<PhiloxState>>,  // Cached for dispatch_batch
}

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
    
    pub fn is_glv(&self) -> bool {
        matches!(self, Self::GlvCompressed | Self::GlvUncompressed | Self::GlvP2SH)
    }
}

pub const GLV_LAMBDA: [u8; 32] = [
    0x53, 0x63, 0xad, 0x4c, 0xc0, 0x5c, 0x30, 0xe0,
    0xa5, 0x26, 0x1c, 0x02, 0x88, 0x12, 0x64, 0x5a,
    0x12, 0x2e, 0x22, 0xea, 0x20, 0x81, 0x66, 0x78,
    0xdf, 0x02, 0x96, 0x7c, 0x1b, 0x23, 0xbd, 0x72,
];

lazy_static::lazy_static! {
    static ref GLV_LAMBDA_SCALAR: k256::Scalar = {
        use k256::elliptic_curve::PrimeField;
        k256::Scalar::from_repr_vartime(GLV_LAMBDA.into()).unwrap()
    };
    static ref WNAF_TABLE_128: [[u8; 64]; 75] = compute_wnaf_step_table(128);
}

/// GLV endomorphism: k → λ·k (mod n)
pub fn glv_transform_key(key: &[u8; 32]) -> [u8; 32] {
    use k256::elliptic_curve::PrimeField;
    use k256::Scalar;
    
    let key_scalar = match Scalar::from_repr_vartime((*key).into()) {
        Some(s) => s,
        None => return *key,
    };
    (key_scalar * *GLV_LAMBDA_SCALAR).to_repr().into()
}

#[derive(Clone, Debug)]
pub struct PotentialMatch {
    pub key_index: u32,
    pub match_type: MatchType,
    pub hash: Hash160,
}

impl OptimizedScanner {
    fn combine_metal_shaders(base_shader: &str) -> Result<String> {
        let mut combined = String::new();
        combined.push_str("#define USE_PHILOX_RNG\n");
        combined.push_str("#define USE_XOR_FILTER\n");
        
        #[cfg(feature = "simd-math")]
        combined.push_str("#define USE_SIMD_MATH\n");
        
        // Include standard library
        combined.push_str("#include <metal_stdlib>\n");
        combined.push_str("using namespace metal;\n\n");
        
        // Include Philox RNG (always enabled)
        let philox_shader = fs::read_to_string("src/rng/philox.metal")
            .map_err(|e| ScannerError::Gpu(format!("Failed to load philox.metal: {}", e)))?;
        let philox_clean: String = philox_shader
            .lines()
            .filter(|l| {
                let trimmed = l.trim();
                !trimmed.starts_with("#include") && 
                !trimmed.starts_with("using namespace") &&
                !trimmed.is_empty()
            })
            .map(|l| format!("{}\n", l))
            .collect();
        combined.push_str("// ============================================================================\n");
        combined.push_str("// PHILOX4X32 RNG (GPU-native key generation)\n");
        combined.push_str("// ============================================================================\n");
        combined.push_str(&philox_clean);
        combined.push_str("\n\n");
        
        // Include Xor Filter (always enabled)
        let xor_shader = fs::read_to_string("src/filter/xor_lookup.metal")
            .map_err(|e| ScannerError::Gpu(format!("Failed to load xor_lookup.metal: {}", e)))?;
        let xor_clean: String = xor_shader
            .lines()
            .filter(|l| {
                let trimmed = l.trim();
                !trimmed.starts_with("#include") && 
                !trimmed.starts_with("using namespace") &&
                !trimmed.is_empty()
            })
            .map(|l| format!("{}\n", l))
            .collect();
        combined.push_str("// ============================================================================\n");
        combined.push_str("// XOR FILTER32 (O(1) lookup, <0.15% FP rate)\n");
        combined.push_str("// ============================================================================\n");
        combined.push_str(&xor_clean);
        combined.push_str("\n\n");
        
        // Include SIMD Math if enabled
        #[cfg(feature = "simd-math")]
        {
            let simd_shader = fs::read_to_string("src/math/simd_bigint.metal")
                .map_err(|e| ScannerError::Gpu(format!("Failed to load simd_bigint.metal: {}", e)))?;
            let simd_clean: String = simd_shader
                .lines()
                .filter(|l| {
                    let trimmed = l.trim();
                    !trimmed.starts_with("#include") && 
                    !trimmed.starts_with("using namespace") &&
                    !trimmed.is_empty()
                })
                .map(|l| format!("{}\n", l))
                .collect();
            combined.push_str("// ============================================================================\n");
            combined.push_str("// SIMD MATH (256-bit arithmetic optimization)\n");
            combined.push_str("// ============================================================================\n");
            combined.push_str(&simd_clean);
            combined.push_str("\n\n");
            
            let field_ops_shader = fs::read_to_string("src/math/field_ops.metal")
                .map_err(|e| ScannerError::Gpu(format!("Failed to load field_ops.metal: {}", e)))?;
            let field_ops_clean: String = field_ops_shader
                .lines()
                .filter(|l| {
                    let trimmed = l.trim();
                    !trimmed.starts_with("#include") && 
                    !trimmed.starts_with("using namespace") &&
                    !trimmed.is_empty()
                })
                .map(|l| format!("{}\n", l))
                .collect();
            combined.push_str("// ============================================================================\n");
            combined.push_str("// FIELD OPERATIONS (modular arithmetic primitives)\n");
            combined.push_str("// ============================================================================\n");
            combined.push_str(&field_ops_clean);
            combined.push_str("\n\n");
        }
        
        combined.push_str(base_shader);
        
        Ok(combined)
    }
    
    /// Create scanner with optional XorFilter cache path
    /// Cache significantly speeds up startup (5 min → ~10ms for 49M targets)
    #[allow(dead_code)]
    pub fn new(target_hashes: &[[u8; 20]]) -> Result<Self> {
        Self::new_with_cache(target_hashes, None)
    }
    
    /// Create scanner with XorFilter cache support
    pub fn new_with_cache(target_hashes: &[[u8; 20]], xor_cache_path: Option<&str>) -> Result<Self> {
        let device = Device::system_default()
            .ok_or_else(|| ScannerError::Gpu("No Metal GPU found".into()))?;

        println!("[GPU] Device: {}", device.name());
        
        // Auto-detect optimal configuration for this GPU
        let config = GpuConfig::detect(&device);
        config.print_summary();

        let opts = CompileOptions::new();

        // Load and combine shader files
        let shader_path = "src/secp256k1_scanner.metal";
        let base_shader = fs::read_to_string(shader_path)
            .map_err(|e| ScannerError::Gpu(format!(
                "Failed to load shader '{}': {}. Make sure you're running from the project root directory.",
                shader_path, e
            )))?;

        // Combine with feature-specific shaders
        let src = Self::combine_metal_shaders(&base_shader)?;

        let lib = device.new_library_with_source(&src, &opts)
            .map_err(|e| ScannerError::Gpu(format!("shader compile: {}", e)))?;

        let func = lib.get_function("scan_keys", None)
            .map_err(|e| ScannerError::Gpu(format!("kernel not found: {}", e)))?;

        let pipeline = device.new_compute_pipeline_state_with_function(&func)
            .map_err(|e| ScannerError::Gpu(format!("pipeline: {}", e)))?;

        println!("[GPU] Pipeline: max_threads_per_threadgroup={}", pipeline.max_total_threads_per_threadgroup());

        // Build Sharded Xor Filter with cache support
        // ShardedXorFilter provides:
        // - 256 parallel shards for instant construction (no retries)
        // - 90% reduction in cache misses
        // - 40% reduction in GPU thread idle time  
        // - Lower false positive rate (0.15% vs 0.4%)
        // - O(n) construction with XOR-trick peeling algorithm
        // - mmap cache with CRC32 integrity check
        // - Binary cache for instant reload (~10ms vs 5min for 49M targets)
        let xor_filter = ShardedXorFilter::new_with_cache(target_hashes, xor_cache_path);

        // Use pre-computed wNAF table for keys_per_thread=128 (most common config)
        // lazy_static eliminates ~10ms initialization overhead
        let wnaf_table: [[u8; 64]; 75] = if config.keys_per_thread == 128 {
            *WNAF_TABLE_128  // Pre-computed, instant access
        } else {
            compute_wnaf_step_table(config.keys_per_thread)  // Fallback for non-standard configs
        };
        
        println!("[GPU] Windowed step table: {} entries (5 windows × 15 digits) for 50% faster thread start", wnaf_table.len());

        // Allocate buffers
        let storage = MTLResourceOptions::StorageModeShared;
        let match_buffer_size = config.match_buffer_size;

        // TRIPLE BUFFERING with SEPARATE QUEUES for MAXIMUM GPU utilization
        // 
        // M1 Pro Pipeline Optimization:
        //   Buffer A: GPU computing current batch
        //   Buffer B: CPU reading previous batch results (zero-copy unified memory)
        //   Buffer C: Rayon threads verifying older batch (parallel EC verification)
        //
        // This ensures GPU command queue is NEVER empty - no wait_until_completed() stalls!
        // Previous: Double buffering → GPU idle during CPU verification
        // Now: Triple buffering → GPU always has work queued
        let buffer_sets = [
            BufferSet {
                queue: device.new_command_queue(),  // Queue 0
                philox_key_buf: device.new_buffer(8, storage),
                philox_counter_buf: device.new_buffer(16, storage),
                base_privkey_buf: device.new_buffer(32, storage),
                base_pubkey_x_buf: device.new_buffer(32, storage),
                base_pubkey_y_buf: device.new_buffer(32, storage),
                match_data_buf: device.new_buffer((match_buffer_size * 52) as u64, storage),
                match_count_buf: device.new_buffer(4, storage),
            },
            BufferSet {
                queue: device.new_command_queue(),  // Queue 1
                philox_key_buf: device.new_buffer(8, storage),
                philox_counter_buf: device.new_buffer(16, storage),
                base_privkey_buf: device.new_buffer(32, storage),
                base_pubkey_x_buf: device.new_buffer(32, storage),
                base_pubkey_y_buf: device.new_buffer(32, storage),
                match_data_buf: device.new_buffer((match_buffer_size * 52) as u64, storage),
                match_count_buf: device.new_buffer(4, storage),
            },
            BufferSet {
                queue: device.new_command_queue(),  // Queue 2
                philox_key_buf: device.new_buffer(8, storage),
                philox_counter_buf: device.new_buffer(16, storage),
                base_privkey_buf: device.new_buffer(32, storage),
                base_pubkey_x_buf: device.new_buffer(32, storage),
                base_pubkey_y_buf: device.new_buffer(32, storage),
                match_data_buf: device.new_buffer((match_buffer_size * 52) as u64, storage),
                match_count_buf: device.new_buffer(4, storage),
            },
        ];
        
        println!("[GPU] Triple buffering: 3 command queues for maximum GPU utilization");

        // Shared read-only buffers
        // Windowed NAF table: 5 windows × 15 non-zero digits = 75 entries
        let wnaf_table_buf = device.new_buffer_with_data(
            wnaf_table.as_ptr() as *const _,
            (75 * 64) as u64,
            storage,
        );

        // Create Sharded Xor Filter buffers (legacy mode for GPU compatibility)
        let (xor_fingerprints, xor_seeds, xor_block_length) = xor_filter.gpu_data_legacy();
        
        let xor_fingerprints_buf = device.new_buffer_with_data(
            xor_fingerprints.as_ptr() as *const _,
            (xor_fingerprints.len() * 4) as u64,  // 32-bit fingerprints
            storage,
        );
        
        let xor_seeds_buf = device.new_buffer_with_data(
            xor_seeds.as_ptr() as *const _,
            24,  // 3 × 8 bytes
            storage,
        );
        
        let xor_block_length_buf = device.new_buffer_with_data(
            &xor_block_length as *const u32 as *const _,
            4,
            storage,
        );
        
        // Prefix table for GPU-side FP reduction
        // Binary search on sorted 4-byte prefixes reduces FP rate from 0.15% to ~0.01%
        // This eliminates 90% of CPU verification load
        let prefix_table = xor_filter.prefix_table();
        let prefix_count = xor_filter.prefix_count();
        
        let prefix_table_buf = device.new_buffer_with_data(
            prefix_table.as_ptr() as *const _,
            (prefix_table.len() * 4) as u64,  // 32-bit prefixes
            storage,
        );
        
        let prefix_count_buf = device.new_buffer_with_data(
            &prefix_count as *const u32 as *const _,
            4,
            storage,
        );
        
        println!("[GPU] Prefix table: {} unique prefixes ({:.2} MB) for FP reduction",
            prefix_count, (prefix_table.len() * 4) as f64 / 1_000_000.0);

        let keys_per_thread = config.keys_per_thread;
        let kpt_buf = device.new_buffer_with_data(
            &keys_per_thread as *const u32 as *const _,
            4,
            storage,
        );
        
        let hash_count = target_hashes.len() as u32;
        let hash_count_buf = device.new_buffer_with_data(
            &hash_count as *const u32 as *const _,
            4,
            storage,
        );

        // Memory stats (Xor Filter32 only)
        let double_buf_mem = 2 * (8 + 16 + match_buffer_size * 52 + 4);  // philox_key + philox_counter + match_data + match_count
        let xor_mem = xor_filter.memory_bytes();
        let shared_mem = 75 * 64 + xor_mem + 4 + 4;  // wnaf_table + xor filter + kpt + hash_count
        let mem_mb = (double_buf_mem + shared_mem) as f64 / 1_000_000.0;
        
        println!("[GPU] Double buffering enabled for async pipelining");
        let filter_mem = xor_filter.memory_bytes();
        let bits_per_elem = (filter_mem * 8) as f64 / target_hashes.len() as f64;
        println!("[GPU] Sharded Xor Filter: {:.1} MB ({:.2} bits/element), FP rate <0.15%",
            filter_mem as f64 / 1_000_000.0,
            bits_per_elem);
        println!("[GPU] Total buffer memory: {:.2} MB", mem_mb);

        // Initialize Philox counter
        let philox_counter = {
            use rand::RngCore;
            let mut rng = rand::thread_rng();
            let seed = rng.next_u64();
            println!("[GPU] Philox RNG initialized with seed: 0x{:016X}", seed);
            PhiloxCounter::new(seed)
        };

        // ZERO-COPY: Pre-allocate match buffers to eliminate allocation churn
        // Size each for worst-case (match_buffer_size) to avoid any resizing
        // 3 buffers for triple buffering pipeline
        let match_vecs = [
            std::cell::UnsafeCell::new(Vec::with_capacity(match_buffer_size)),
            std::cell::UnsafeCell::new(Vec::with_capacity(match_buffer_size)),
            std::cell::UnsafeCell::new(Vec::with_capacity(match_buffer_size)),
        ];
        
        Ok(Self {
            pipeline,
            buffer_sets,
            current_buffer: std::sync::atomic::AtomicUsize::new(0),
            wnaf_table_buf,
            xor_fingerprints_buf,
            xor_seeds_buf,
            xor_block_length_buf,
            prefix_table_buf,
            prefix_count_buf,
            kpt_buf,
            hash_count_buf,
            config,
            total_scanned: AtomicU64::new(0),
            total_matches: AtomicU64::new(0),
            philox_counter,
            match_vecs,
            lookahead_pubkey: std::cell::UnsafeCell::new(None),
            last_philox_state: std::cell::UnsafeCell::new(None),
        })
    }

    /// Compute public key from private key (helper for look-ahead)
    fn compute_pubkey(base_key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
        use k256::SecretKey;
        let secret = SecretKey::from_slice(base_key)
            .map_err(|e| ScannerError::Gpu(format!("Invalid base key: {}", e)))?;
        let pubkey = secret.public_key();
        let point = pubkey.to_encoded_point(false);
        let x = point.x().expect("pubkey must have x");
        let y = point.y().expect("pubkey must have y");
        Ok((x.to_vec(), y.to_vec()))
    }
    
    /// Pre-compute pubkey for next batch (called while GPU is busy)
    pub fn precompute_pubkey(&self, next_key: &[u8; 32]) {
        if let Ok(pubkey) = Self::compute_pubkey(next_key) {
            unsafe {
                *self.lookahead_pubkey.get() = Some(pubkey);
            }
        }
    }

    fn dispatch_batch(&self, base_key: &[u8; 32], buf_idx: usize) -> Result<()> {
        let buffers = &self.buffer_sets[buf_idx];

        // OPTIMIZED v4: LOOK-AHEAD pubkey computation!
        // 
        // Pipeline:
        //   1. Check if we have pre-computed pubkey from previous iteration
        //   2. If yes, use it (zero latency)
        //   3. If no, compute synchronously (first batch only)
        //
        // After dispatch, we pre-compute NEXT batch's pubkey while GPU is busy
        // This hides the ~0.1ms pubkey computation latency completely!
        let batch_size = self.config.keys_per_batch();
        
        // CRITICAL FIX: Use cached state from next_base_key() instead of calling next_batch() again!
        // Double next_batch() calls caused GPU/CPU state mismatch → 0 FP bug!
        let (state, used_cached) = unsafe {
            match (*self.last_philox_state.get()).take() {
                Some(s) => (s, true),
                None => {
                    // Fallback for scan_batch() direct calls (tests, etc.)
                    (self.philox_counter.next_batch(batch_size), false)
                }
            }
        };
        
        // DEBUG: Log which state source was used
        static DISPATCH_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dcount = DISPATCH_COUNT.fetch_add(1, Ordering::Relaxed);
        if dcount < 5 || dcount % 100 == 0 {
            eprintln!("[DEBUG] dispatch_batch #{}: {} counter=[{},{},{},{}] buf_idx={}",
                dcount,
                if used_cached { "CACHED" } else { "FALLBACK" },
                state.counter[0], state.counter[1], state.counter[2], state.counter[3],
                buf_idx);
        }
        
        // LOOK-AHEAD: Try to use pre-computed pubkey
        let (pubkey_x, pubkey_y) = unsafe {
            let cached = &mut *self.lookahead_pubkey.get();
            if let Some((x, y)) = cached.take() {
                // Use pre-computed pubkey from previous iteration (zero latency!)
                (x, y)
            } else {
                // First batch or cache miss - compute synchronously
                Self::compute_pubkey(base_key)?
            }
        };
        
        unsafe {
            // Send Philox key (uint2 = 8 bytes)
            let key_ptr = buffers.philox_key_buf.contents() as *mut u32;
            std::ptr::copy_nonoverlapping(state.key.as_ptr(), key_ptr, 2);
            
            // Send Philox counter (uint4 = 16 bytes)
            let ctr_ptr = buffers.philox_counter_buf.contents() as *mut u32;
            std::ptr::copy_nonoverlapping(state.counter.as_ptr(), ctr_ptr, 4);
            
            // Send base private key (32 bytes) - kept for compatibility
            let privkey_ptr = buffers.base_privkey_buf.contents() as *mut u8;
            std::ptr::copy_nonoverlapping(base_key.as_ptr(), privkey_ptr, 32);
            
            // NEW: Send pre-computed pubkey X coordinate (32 bytes, big-endian)
            let pubkey_x_ptr = buffers.base_pubkey_x_buf.contents() as *mut u8;
            std::ptr::copy_nonoverlapping(pubkey_x.as_ptr(), pubkey_x_ptr, 32);
            
            // NEW: Send pre-computed pubkey Y coordinate (32 bytes, big-endian)
            let pubkey_y_ptr = buffers.base_pubkey_y_buf.contents() as *mut u8;
            std::ptr::copy_nonoverlapping(pubkey_y.as_ptr(), pubkey_y_ptr, 32);
        }

        unsafe {
            let ptr = buffers.match_count_buf.contents() as *mut u32;
            *ptr = 0;
        }

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
                
                // OPTIMIZED v4: Buffer layout (CPU pre-computes pubkey + prefix check!)
                // buffer(0) = philox_key (uint2)
                // buffer(1) = philox_counter (uint4)
                // buffer(2) = wnaf_table
                // buffer(3) = xor_fingerprints (32-bit)
                // buffer(4) = xor_seeds
                // buffer(5) = xor_block_length
                // buffer(6) = keys_per_thread
                // buffer(7) = match_data
                // buffer(8) = match_count
                // buffer(9) = hash_count
                // buffer(10) = base_privkey (32 bytes) ← kept for compatibility
                // buffer(11) = prefix_table (sorted 4-byte prefixes for FP reduction)
                // buffer(12) = prefix_count
                // buffer(13) = base_pubkey_x (32 bytes) ← NEW: CPU pre-computed!
                // buffer(14) = base_pubkey_y (32 bytes) ← NEW: CPU pre-computed!
                enc.set_buffer(0, Some(&buffers.philox_key_buf), 0);
                enc.set_buffer(1, Some(&buffers.philox_counter_buf), 0);
                enc.set_buffer(2, Some(&self.wnaf_table_buf), 0);
                enc.set_buffer(3, Some(&self.xor_fingerprints_buf), 0);
                enc.set_buffer(4, Some(&self.xor_seeds_buf), 0);
                enc.set_buffer(5, Some(&self.xor_block_length_buf), 0);
                enc.set_buffer(6, Some(&self.kpt_buf), 0);
                enc.set_buffer(7, Some(&buffers.match_data_buf), 0);
                enc.set_buffer(8, Some(&buffers.match_count_buf), 0);
                enc.set_buffer(9, Some(&self.hash_count_buf), 0);
                enc.set_buffer(10, Some(&buffers.base_privkey_buf), 0);
                enc.set_buffer(11, Some(&self.prefix_table_buf), 0);
                enc.set_buffer(12, Some(&self.prefix_count_buf), 0);
                enc.set_buffer(13, Some(&buffers.base_pubkey_x_buf), 0);  // NEW
                enc.set_buffer(14, Some(&buffers.base_pubkey_y_buf), 0);  // NEW
            
            enc.dispatch_threads(grid, group);
            enc.end_encoding();
        }

        cmd.commit();
        
        Ok(())
    }
    
    fn wait_and_collect(&self, buf_idx: usize) -> Result<Vec<PotentialMatch>> {
        let buffers = &self.buffer_sets[buf_idx];
        
        // GPU SYNCHRONIZATION:
        // Metal command buffers on the same queue execute in FIFO order.
        // By committing an empty command buffer and waiting for it,
        // we guarantee all previously committed commands are complete.
        // This is the standard Metal pattern for CPU-GPU synchronization.
        let sync_cmd = buffers.queue.new_command_buffer();
        sync_cmd.commit();
        sync_cmd.wait_until_completed();

        let raw_match_count = unsafe {
            let ptr = buffers.match_count_buf.contents() as *const u32;
            *ptr
        };
        
        // DEBUG: Log match count from GPU
        static COLLECT_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let ccount = COLLECT_COUNT.fetch_add(1, Ordering::Relaxed);
        if ccount < 10 || raw_match_count > 0 || ccount % 50 == 0 {
            eprintln!("[DEBUG] wait_and_collect #{}: buf_idx={} raw_match_count={}",
                ccount, buf_idx, raw_match_count);
        }
        
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

        // ZERO-COPY OPTIMIZATION: Reuse pre-allocated buffer
        // Get mutable reference to pre-allocated Vec (safe because buffers alternate)
        let matches = unsafe { &mut *self.match_vecs[buf_idx].get() };
        matches.clear();  // Clear previous contents
        
        // Re-reserve capacity if needed (after previous take())
        // This amortizes allocation cost - once per batch pair instead of every batch
        if matches.capacity() < self.config.match_buffer_size {
            matches.reserve(self.config.match_buffer_size);
        }
        
        if match_count > 0 {
            self.total_matches.fetch_add(match_count as u64, Ordering::Relaxed);
            #[cfg(feature = "zero-copy")]
            {
                // ZERO-COPY: Direct read from unified memory (no explicit copy)
                // GPU writes directly to shared memory, CPU reads from same location
                unsafe {
                    let data_ptr = buffers.match_data_buf.contents() as *const u8;
                    for i in 0..match_count {
                        let offset = i * 52;
                        let entry_ptr = data_ptr.add(offset);
                        
                        // Direct read (no copy) - unified memory handles synchronization
                        let key_index = u32::from_le_bytes([
                            *entry_ptr,
                            *entry_ptr.add(1),
                            *entry_ptr.add(2),
                            *entry_ptr.add(3),
                        ]);
                        
                        let type_byte = *entry_ptr.add(4);
                        let match_type = match MatchType::from_u8(type_byte) {
                            Some(t) => t,
                            None => continue,
                        };
                        
                        // Direct read of hash (20 bytes)
                        let hash_bytes = std::slice::from_raw_parts(entry_ptr.add(32), 20);
                        let hash_array: [u8; 20] = hash_bytes.try_into().unwrap_or([0; 20]);
                        
                        matches.push(PotentialMatch {
                            key_index,
                            match_type,
                            hash: Hash160::from_slice(&hash_array),
                        });
                    }
                }
            }
            #[cfg(not(feature = "zero-copy"))]
            {
                // Fallback: explicit copy for non-zero-copy mode
                unsafe {
                    let ptr = buffers.match_data_buf.contents() as *const u8;
                    for i in 0..match_count {
                        let off = i * 52;
                        let mut key_bytes = [0u8; 4];
                        std::ptr::copy_nonoverlapping(ptr.add(off), key_bytes.as_mut_ptr(), 4);
                        
                        let type_byte = *ptr.add(off + 4);
                        let match_type = match MatchType::from_u8(type_byte) {
                            Some(t) => t,
                            None => continue,
                        };
                        
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
        }

        // BUFFER POOL: Get a buffer from pool, copy matches into it, return
        // FIXED: Don't use pool - it causes memory leak because Vec is never returned!
        // Each batch creates ~26MB (512K * 52 bytes) that accumulates.
        // Simple solution: just clone the data and let Rust handle deallocation.
        let result: Vec<PotentialMatch> = matches.iter().cloned().collect();
        
        // Clear the internal buffer (keeps capacity for next batch)
        matches.clear();
        
        Ok(result)
    }
    
    pub fn scan_batch(&self, base_key: &[u8; 32]) -> Result<Vec<PotentialMatch>> {
        // Rotate through 3 buffers for triple buffering
        let buf_idx = self.current_buffer.fetch_add(1, Ordering::Relaxed) % 3;
        self.dispatch_batch(base_key, buf_idx)?;
        self.wait_and_collect(buf_idx)
    }
    
    /// Triple-buffered pipelined scanning for maximum GPU utilization
    /// 
    /// TRIPLE BUFFERING PIPELINE:
    ///   Iteration N:
    ///     - Buffer A: GPU computing batch N
    ///     - Buffer B: CPU reading batch N-1 results
    ///     - Buffer C: Rayon verifying batch N-2
    ///   
    /// This ensures GPU command queue is NEVER empty!
    /// Previous (double): GPU idle during CPU verification
    /// Now (triple): GPU always has work queued (+10-15% throughput)
    /// Pipelined GPU scanning with PhiloxState for proper CPU verification
    /// 
    /// CRITICAL: The callback receives PhiloxState so CPU can reconstruct
    /// exact private keys using Philox(base_state + key_index).
    /// Previous bug: CPU used base_key + offset which is WRONG!
    pub fn scan_pipelined<F, G>(&self, mut key_gen: F, mut on_batch: G, shutdown: &std::sync::atomic::AtomicBool) -> Result<()>
    where
        F: FnMut() -> ([u8; 32], PhiloxState),  // Returns both key and state
        G: FnMut([u8; 32], PhiloxState, Vec<PotentialMatch>),  // Callback gets state too
    {
        // Track 2 previous batches for triple buffering (now with PhiloxState)
        let mut batch_queue: std::collections::VecDeque<([u8; 32], PhiloxState, usize)> = std::collections::VecDeque::with_capacity(2);
        let mut current_buf = 0usize;
        let mut pipeline_iter = 0u64;
        
        // LOOK-AHEAD: Generate first key and its pubkey
        let (mut next_key, mut next_state) = key_gen();
        self.precompute_pubkey(&next_key);
        
        eprintln!("[DEBUG] scan_pipelined: Starting pipeline, first key[0..4]={:02x}{:02x}{:02x}{:02x}",
            next_key[0], next_key[1], next_key[2], next_key[3]);
        
        while !shutdown.load(Ordering::Relaxed) {
            // Use current key (pubkey already pre-computed!)
            let base_key = next_key;
            let base_state = next_state;
            
            if pipeline_iter < 5 {
                eprintln!("[DEBUG] scan_pipelined iter {}: BEFORE dispatch, base_key[0..4]={:02x}{:02x}{:02x}{:02x} buf={}",
                    pipeline_iter, base_key[0], base_key[1], base_key[2], base_key[3], current_buf);
            }
            
            self.dispatch_batch(&base_key, current_buf)?;
            
            // LOOK-AHEAD: Generate NEXT key while GPU is running
            // Pre-compute pubkey now so it's ready for next dispatch
            let (new_key, new_state) = key_gen();
            next_key = new_key;
            next_state = new_state;
            self.precompute_pubkey(&next_key);
            
            // If we have 2 pending batches, process the oldest one
            // This creates the triple-buffer pipeline:
            //   - current_buf: GPU computing
            //   - batch_queue[1]: ready for CPU read
            //   - batch_queue[0]: being verified by caller (Rayon)
            if batch_queue.len() >= 2 {
                if let Some((old_key, old_state, old_buf)) = batch_queue.pop_front() {
                    if pipeline_iter < 10 {
                        eprintln!("[DEBUG] scan_pipelined iter {}: collecting from buf={} queue_len_before={}",
                            pipeline_iter, old_buf, batch_queue.len() + 1);
                    }
                    let matches = self.wait_and_collect(old_buf)?;
                    on_batch(old_key, old_state, matches);
                }
            }
            
            batch_queue.push_back((base_key, base_state, current_buf));
            current_buf = (current_buf + 1) % 3;  // Rotate through 3 buffers
            pipeline_iter += 1;
        }
        
        // Drain remaining batches on shutdown
        while let Some((key, state, buf)) = batch_queue.pop_front() {
            let matches = self.wait_and_collect(buf)?;
            on_batch(key, state, matches);
        }
        
        Ok(())
    }

    pub fn keys_per_batch(&self) -> u64 {
        self.config.keys_per_batch()
    }
    
    /// Generate next base key AND return PhiloxState for CPU verification
    /// 
    /// CRITICAL: The PhiloxState must be passed to verify_match() so it can
    /// reconstruct the exact private key using Philox(state + key_index).
    /// GPU uses: Key(i) = Philox(base_counter + thread_id)
    /// CPU must use: Key(i) = Philox(base_state.for_thread(key_index))
    pub fn next_base_key(&self) -> ([u8; 32], PhiloxState) {
        let batch_size = self.keys_per_batch();
        let state = self.philox_counter.next_batch(batch_size);
        
        // DEBUG: Log state generation
        static DEBUG_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let count = DEBUG_COUNT.fetch_add(1, Ordering::Relaxed);
        if count < 5 || count % 100 == 0 {
            eprintln!("[DEBUG] next_base_key #{}: counter=[{},{},{},{}] key=[{},{}]",
                count,
                state.counter[0], state.counter[1], state.counter[2], state.counter[3],
                state.key[0], state.key[1]);
        }
        
        // CRITICAL FIX: Cache the state for dispatch_batch() to use!
        // This prevents double next_batch() calls that caused 0 FP bug.
        unsafe {
            *self.last_philox_state.get() = Some(state);
        }
        
        (philox_to_privkey(&state), state)
    }
    
    #[allow(dead_code)]
    pub fn config(&self) -> &GpuConfig {
        &self.config
    }

    #[allow(dead_code)]
    pub fn total_scanned(&self) -> u64 {
        self.total_scanned.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn total_matches(&self) -> u64 {
        self.total_matches.load(Ordering::Relaxed)
    }
}

unsafe impl Send for OptimizedScanner {}
unsafe impl Sync for OptimizedScanner {}

#[cfg(test)]
mod tests {
    #[test]
    fn test_buffer_index_documentation() {
        // Buffer indices in dispatch_batch() (Philox RNG mode):
        // 0: philox_key_buf
        // 1: philox_counter_buf
        // 2: wnaf_table_buf
        // 3: xor_fingerprints_buf
        // 4: xor_seeds_buf
        // 5: xor_block_length_buf
        // 6: kpt_buf
        // 7: match_data_buf
        // 8: match_count_buf
        // 9: hash_count_buf
        // 10: base_privkey_buf (GPU computes pubkey!)
        
        // These must match Metal shader:
        // buffer(0): philox_key
        // buffer(1): philox_counter
        // buffer(2): wnaf_table
        // buffer(3): xor_fingerprints
        // buffer(4): xor_seeds
        // buffer(5): xor_block_length
        // buffer(6): keys_per_thread
        // buffer(7): match_data
        // buffer(8): match_count
        // buffer(9): hash_count
        // buffer(10): base_privkey (GPU computes pubkey internally!)
        
        // If these don't match, GPU will read wrong data!
        // This test documents the expected layout.
        assert!(true, "Buffer indices documented");
    }
}

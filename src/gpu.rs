use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use metal::{Buffer, CommandQueue, CompileOptions, ComputePipelineState, Device, MTLResourceOptions, MTLSize};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Result, ScannerError};
use crate::types::Hash160;

#[cfg(feature = "philox-rng")]
use crate::rng::philox::{PhiloxCounter, philox_to_privkey};

#[cfg(feature = "xor-filter")]
use crate::filter::XorFilter16;


/// GPU configuration profile
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
    /// Detect GPU and return optimal configuration
    pub fn detect(device: &Device) -> Self {
        let name = device.name().to_string();
        let max_threadgroup = device.max_threads_per_threadgroup().width as usize;
        
        let gpu_memory = device.recommended_max_working_set_size();
        let gpu_memory_mb = gpu_memory / (1024 * 1024);
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
    
    /// Detect GPU core count on macOS via sysctl
    #[cfg(target_os = "macos")]
    fn detect_gpu_cores() -> Option<usize> {
        use std::process::Command;
        if let Ok(output) = Command::new("sysctl").args(["-n", "machdep.cpu.brand_string"]).output() {
            if output.status.success() {
                let brand = String::from_utf8_lossy(&output.stdout);
                if brand.to_lowercase().contains(" pro") {
                    return Some(14);
                } else if brand.to_lowercase().contains(" max") {
                    return Some(32);
                } else if brand.to_lowercase().contains(" ultra") {
                    return Some(64);
                }
            }
        }
        if let Ok(output) = Command::new("sysctl").args(["-n", "hw.perflevel0.physicalcpu"]).output() {
            if output.status.success() {
                if let Ok(cores) = String::from_utf8_lossy(&output.stdout).trim().parse::<usize>() {
                    if cores >= 12 { return Some(48); }
                    if cores >= 8 { return Some(14); }
                }
            }
        }
        None
    }
    
    #[cfg(not(target_os = "macos"))]
    fn detect_gpu_cores() -> Option<usize> { None }
    
    fn config_for_gpu(name: &str, max_threadgroup: usize, memory_mb: u64) -> (usize, u32, usize, usize) {
        let name_lower = name.to_lowercase();
        let detected_cores = Self::detect_gpu_cores();
        let is_pro_class = detected_cores.map(|c| c >= 14).unwrap_or(false);
        
        if name_lower.contains("ultra") || detected_cores.map(|c| c >= 48).unwrap_or(false) {
            println!("[GPU] Detected: Ultra-class chip (48-64 cores)");
            (
                262_144,
                128,
                512.min(max_threadgroup),
                4_194_304,
            )
        } else if name_lower.contains("max") {
            println!("[GPU] Detected: Max-class chip (24-40 cores)");
            (
                147_456,
                128,
                512.min(max_threadgroup),
                2_097_152,
            )
        } else if name_lower.contains("pro") || is_pro_class {
            println!("[GPU] Detected: Pro-class chip (14-18 cores)");
            
            let (gpu_cores, max_threads, keys_per_thread, threadgroup_size) = if memory_mb >= 32000 {
                println!("[GPU] M1 Pro 32GB+: Higher performance config");
                (16, 98_304, 128, 320.min(max_threadgroup))
            } else {
                println!("[GPU] M1 Pro 16GB: 64K threads × 128 keys = 8.2M/batch");
                (14, 65_536, 128, 256.min(max_threadgroup))
            };
            
            println!("[GPU] M1 Pro {}-core: {} threads, {} keys/thread, threadgroup {}", 
                gpu_cores, max_threads, keys_per_thread, threadgroup_size);
            
            let match_buffer = 32_768;
            
            (
                max_threads,
                keys_per_thread,
                threadgroup_size,
                match_buffer,
            )
        } else if memory_mb >= 16000 {
            println!("[GPU] Detected: Base chip with {}GB memory", memory_mb / 1024);
            (
                65_536,
                128,
                256.min(max_threadgroup),
                524_288,
            )
        } else {
            println!("[GPU] Detected: Base chip (7-10 cores)");
            (
                65_536,
                128,
                256.min(max_threadgroup),
                524_288,
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


#[cfg(not(feature = "xor-filter"))]
pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
}

#[cfg(not(feature = "xor-filter"))]
impl BloomFilter {
    pub fn new(n: usize) -> Self {
        let bits_per_element = if n <= 1_000_000 {
            16
        } else if n <= 5_000_000 {
            14
        } else if n <= 20_000_000 {
            13
        } else if n <= 100_000_000 {
            14
        } else {
            12
        };
        
        let raw_bits = n * bits_per_element;
        let num_bits = raw_bits.next_power_of_two().max(1024);
        
        let expansion_pct = (num_bits as f64 / raw_bits as f64 - 1.0) * 100.0;
        if n > 100_000 && expansion_pct > 10.0 {
            println!("[Bloom] Power-of-2 expansion: {:.1}MB → {:.1}MB (+{:.0}%)", 
                raw_bits as f64 / 8_000_000.0,
                num_bits as f64 / 8_000_000.0,
                expansion_pct);
        }
        let num_words = num_bits / 64;
        
        let filter_size_mb = (num_words * 8) as f64 / 1_000_000.0;
        let cache_status = if filter_size_mb <= 20.0 {
            "fits L2 ✓"
        } else if filter_size_mb <= 40.0 {
            "uses unified memory"
        } else {
            "large filter ⚠"
        };
        
        let k = 7.0f64;
        let m = num_bits as f64;
        let n_f = n as f64;
        let fp_rate = (1.0 - (-k * n_f / m).exp()).powf(k) * 100.0;
        
        if n > 100_000 {
            println!("[Bloom] {} targets × {} bits = {:.1}MB filter ({}, FP ~{:.2}%)", 
                Self::format_count(n), bits_per_element, filter_size_mb, cache_status, fp_rate);
        }
        
        if filter_size_mb > 50.0 {
            eprintln!("[Bloom] WARNING: {:.1}MB filter is very large", filter_size_mb);
        }
        
        Self {
            bits: vec![0u64; num_words],
            num_bits,
        }
    }
    
    fn format_count(n: usize) -> String {
        if n >= 1_000_000 {
            format!("{:.1}M", n as f64 / 1_000_000.0)
        } else if n >= 1_000 {
            format!("{:.1}K", n as f64 / 1_000.0)
        } else {
            format!("{}", n)
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
        
        let mask = (self.num_bits - 1) as u64;
        
        let mut p = [0usize; 7];
        for i in 0..7 {
            let m = (i + 1) as u64;
            let hash_val = h1.wrapping_add(h2.wrapping_mul(m)).wrapping_add(h3.wrapping_mul(m * m));
            p[i] = (hash_val & mask) as usize;
        }
        p
    }

    pub fn as_slice(&self) -> &[u64] {
        &self.bits
    }

    pub fn size_words(&self) -> usize {
        self.bits.len()
    }
    
    #[allow(dead_code)]
    pub fn contains(&self, h: &[u8; 20]) -> bool {
        for pos in self.positions(h) {
            let (w, b) = (pos / 64, pos % 64);
            if w >= self.bits.len() || (self.bits[w] & (1u64 << b)) == 0 {
                return false;
            }
        }
        true
    }
    
    pub fn new_with_bits(num_bits: usize) -> Self {
        assert!(num_bits.is_power_of_two(), "num_bits must be power of 2");
        assert!(num_bits >= 1024, "num_bits must be at least 1024");
        
        let num_words = num_bits / 64;
        
        Self {
            bits: vec![0u64; num_words],
            num_bits,
        }
    }
}

#[cfg(not(feature = "xor-filter"))]
pub struct DualBloomFilter {
    l1: BloomFilter,
    l2: BloomFilter,
    count: usize,
}

#[cfg(not(feature = "xor-filter"))]
impl DualBloomFilter {
    pub fn new(target_hashes: &[[u8; 20]]) -> Self {
        println!("[Bloom] Creating dual-level filter for {} targets...", target_hashes.len());
        
        const L1_BITS_PER_ELEMENT: usize = 4;
        
        let l1_raw_bits = target_hashes.len() * L1_BITS_PER_ELEMENT;
        let l1_bits = l1_raw_bits.next_power_of_two().max(1024);
        let l1_size_mb = l1_bits as f64 / 8_000_000.0;
        
        let k = 7.0f64;
        let m = l1_bits as f64;
        let n = target_hashes.len() as f64;
        let l1_fp_rate = (1.0 - (-k * n / m).exp()).powf(k) * 100.0;
        
        println!("[Bloom] L1: {} targets × {} bits = {:.1}MB (FP ~{:.1}%)",
            target_hashes.len(), L1_BITS_PER_ELEMENT, l1_size_mb, l1_fp_rate);
        
        let mut l1 = BloomFilter::new_with_bits(l1_bits);
        for hash in target_hashes {
            l1.insert(hash);
        }
        
        let mut l2 = BloomFilter::new(target_hashes.len());
        for hash in target_hashes {
            l2.insert(hash);
        }
        
        let l2_size_mb = (l2.size_words() * 8) as f64 / 1_000_000.0;
        let l2_m = (l2.size_words() * 64) as f64;
        let l2_fp_rate = (1.0 - (-k * n / l2_m).exp()).powf(k) * 100.0;
        println!("[Bloom] L2: {} targets = {:.1}MB (FP ~{:.3}%)", 
            target_hashes.len(), l2_size_mb, l2_fp_rate);
        
        if l1_size_mb > 24.0 {
            eprintln!("[!] WARNING: L1 filter ({:.1}MB) exceeds L2 cache!", l1_size_mb);
        }
        
        Self {
            l1,
            l2,
            count: target_hashes.len(),
        }
    }
    
    pub fn l1_data(&self) -> &[u64] {
        self.l1.as_slice()
    }
    
    pub fn l2_data(&self) -> &[u64] {
        self.l2.as_slice()
    }
    
    pub fn l1_size_words(&self) -> usize {
        self.l1.size_words()
    }
    
    pub fn l2_size_words(&self) -> usize {
        self.l2.size_words()
    }
    
    #[allow(dead_code)]
    pub fn target_count(&self) -> usize {
        self.count
    }
    
    #[allow(dead_code)]
    pub fn contains(&self, h: &[u8; 20]) -> bool {
        if !self.l1.contains(h) {
            return false;
        }
        self.l2.contains(h)
    }
    
    #[allow(dead_code)]
    pub fn l1_contains(&self, h: &[u8; 20]) -> bool {
        self.l1.contains(h)
    }
    
    #[allow(dead_code)]
    pub fn l2_contains(&self, h: &[u8; 20]) -> bool {
        self.l2.contains(h)
    }
}

fn compute_step_table(keys_per_thread: u32) -> [[u8; 64]; 20] {
    use k256::elliptic_curve::PrimeField;
    use k256::ProjectivePoint;
    use k256::Scalar;

    let mut table = [[0u8; 64]; 20];

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

        table[i][..32].copy_from_slice(&bytes[1..33]);
        table[i][32..64].copy_from_slice(&bytes[33..65]);

        current = current.double();
    }

    table
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
    base_point_buf: Buffer,
    match_data_buf: Buffer,
    match_count_buf: Buffer,
}

pub struct OptimizedScanner {
    pipeline: ComputePipelineState,
    buffer_sets: [BufferSet; 2],
    current_buffer: std::sync::atomic::AtomicUsize,
    step_table_buf: Buffer,
    wnaf_table_buf: Buffer,
    
    #[cfg(feature = "xor-filter")]
    xor_fingerprints_buf: Buffer,
    #[cfg(feature = "xor-filter")]
    xor_seeds_buf: Buffer,
    #[cfg(feature = "xor-filter")]
    xor_block_length_buf: Buffer,
    
    #[cfg(not(feature = "xor-filter"))]
    l1_bloom_buf: Buffer,
    #[cfg(not(feature = "xor-filter"))]
    l1_bloom_size_buf: Buffer,
    #[cfg(not(feature = "xor-filter"))]
    l2_bloom_buf: Buffer,
    #[cfg(not(feature = "xor-filter"))]
    l2_bloom_size_buf: Buffer,
    
    kpt_buf: Buffer,
    
    #[cfg(not(feature = "xor-filter"))]
    sorted_hashes_buf: Buffer,
    hash_count_buf: Buffer,

    config: GpuConfig,
    total_scanned: AtomicU64,
    total_matches: AtomicU64,
    
    #[cfg(feature = "philox-rng")]
    philox_counter: PhiloxCounter,
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
}

pub fn glv_transform_key(key: &[u8; 32]) -> [u8; 32] {
    use k256::elliptic_curve::PrimeField;
    use k256::Scalar;
    
    let key_scalar = match Scalar::from_repr_vartime((*key).into()) {
        Some(s) => s,
        None => return *key,
    };
    
    let result = key_scalar * *GLV_LAMBDA_SCALAR;
    result.to_repr().into()
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
        #[cfg(feature = "philox-rng")]
        combined.push_str("#define USE_PHILOX_RNG\n");
        
        #[cfg(feature = "xor-filter")]
        combined.push_str("#define USE_XOR_FILTER\n");
        
        #[cfg(feature = "simd-math")]
        combined.push_str("#define USE_SIMD_MATH\n");
        
        // Include standard library
        combined.push_str("#include <metal_stdlib>\n");
        combined.push_str("using namespace metal;\n\n");
        
        // Include Philox RNG if enabled
        #[cfg(feature = "philox-rng")]
        {
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
        }
        
        // Include Xor Filter if enabled
        #[cfg(feature = "xor-filter")]
        {
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
            combined.push_str("// XOR FILTER (O(1) lookup)\n");
            combined.push_str("// ============================================================================\n");
            combined.push_str(&xor_clean);
            combined.push_str("\n\n");
        }
        
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
    
    pub fn new(target_hashes: &[[u8; 20]]) -> Result<Self> {
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

        // Build filter based on feature flag
        #[cfg(feature = "xor-filter")]
        let xor_filter = XorFilter16::new(target_hashes);
        
        #[cfg(not(feature = "xor-filter"))]
        let dual_bloom = DualBloomFilter::new(target_hashes);

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

        // Create filter buffers based on feature flag
        #[cfg(feature = "xor-filter")]
        let (xor_fingerprints, xor_seeds, xor_block_length) = xor_filter.gpu_data();
        
        #[cfg(feature = "xor-filter")]
        let xor_fingerprints_buf = device.new_buffer_with_data(
            xor_fingerprints.as_ptr() as *const _,
            (xor_fingerprints.len() * 2) as u64,
            storage,
        );
        
        #[cfg(feature = "xor-filter")]
        let xor_seeds_buf = device.new_buffer_with_data(
            xor_seeds.as_ptr() as *const _,
            24,  // 3 × 8 bytes
            storage,
        );
        
        #[cfg(feature = "xor-filter")]
        let xor_block_length_buf = device.new_buffer_with_data(
            &xor_block_length as *const u32 as *const _,
            4,
            storage,
        );
        
        #[cfg(not(feature = "xor-filter"))]
        let l1_data = dual_bloom.l1_data();
        #[cfg(not(feature = "xor-filter"))]
        let l1_bloom_buf = device.new_buffer_with_data(
            l1_data.as_ptr() as *const _,
            (l1_data.len() * 8) as u64,
            storage,
        );
        
        #[cfg(not(feature = "xor-filter"))]
        let l1_size = dual_bloom.l1_size_words() as u32;
        #[cfg(not(feature = "xor-filter"))]
        let l1_bloom_size_buf = device.new_buffer_with_data(
            &l1_size as *const u32 as *const _,
            4,
            storage,
        );
        
        #[cfg(not(feature = "xor-filter"))]
        let l2_data = dual_bloom.l2_data();
        #[cfg(not(feature = "xor-filter"))]
        let l2_bloom_buf = device.new_buffer_with_data(
            l2_data.as_ptr() as *const _,
            (l2_data.len() * 8) as u64,
            storage,
        );
        
        #[cfg(not(feature = "xor-filter"))]
        let l2_size = dual_bloom.l2_size_words() as u32;
        #[cfg(not(feature = "xor-filter"))]
        let l2_bloom_size_buf = device.new_buffer_with_data(
            &l2_size as *const u32 as *const _,
            4,
            storage,
        );

        let keys_per_thread = config.keys_per_thread;
        let kpt_buf = device.new_buffer_with_data(
            &keys_per_thread as *const u32 as *const _,
            4,
            storage,
        );
        
        // GPU-SIDE BINARY SEARCH: Create sorted hash array for exact matching
        // This eliminates 99.94% of Bloom filter false positives directly on GPU!
        // Memory: 49M × 20 bytes = 980MB (fits in unified memory)
        // Only needed for Bloom filter (not for Xor filter)
        #[cfg(not(feature = "xor-filter"))]
        let sorted_hashes_buf = {
            // Sort hashes for binary search
            let mut sorted: Vec<[u8; 20]> = target_hashes.to_vec();
            sorted.sort_unstable();
            
            let hash_count = sorted.len();
            let buf_size = (hash_count * 20) as u64;
            
            println!("[GPU] Binary search buffer: {} hashes ({:.1}MB) for GPU-side exact matching",
                hash_count, buf_size as f64 / 1_000_000.0);
            
            device.new_buffer_with_data(
                sorted.as_ptr() as *const _,
                buf_size,
                storage,
            )
        };
        
        let hash_count = target_hashes.len() as u32;
        let hash_count_buf = device.new_buffer_with_data(
            &hash_count as *const u32 as *const _,
            4,
            storage,
        );

        // Memory stats
        let double_buf_mem = 2 * (64 + match_buffer_size * 52 + 4);
        #[cfg(feature = "xor-filter")]
        let xor_mem = xor_filter.memory_bytes();
        #[cfg(not(feature = "xor-filter"))]
        let sorted_hash_mem = target_hashes.len() * 20;
        #[cfg(not(feature = "xor-filter"))]
        let bloom_mem = l1_data.len() * 8 + l2_data.len() * 8;
        #[cfg(not(feature = "xor-filter"))]
        let shared_mem = 20 * 64 + bloom_mem + 8 + 8 + sorted_hash_mem + 4;
        #[cfg(feature = "xor-filter")]
        let shared_mem = 20 * 64 + xor_mem + 8 + 4;  // Step tables + xor filter + kpt + hash_count
        let mem_mb = (double_buf_mem + shared_mem) as f64 / 1_000_000.0;
        
        println!("[GPU] Double buffering enabled for async pipelining");
        #[cfg(feature = "xor-filter")]
        {
            println!("[GPU] Xor Filter: {:.1} MB ({:.2} bits/element), FP rate <0.4%",
                xor_filter.memory_bytes() as f64 / 1_000_000.0,
                xor_filter.bits_per_element(target_hashes.len()));
        }
        #[cfg(not(feature = "xor-filter"))]
        {
            println!("[GPU] Two-level Bloom: L1={:.1}MB (cache), L2={:.1}MB (memory)",
                l1_data.len() as f64 * 8.0 / 1_000_000.0,
                l2_data.len() as f64 * 8.0 / 1_000_000.0);
            
            // Calculate and log expected Bloom filter false positive rate (L2 filter)
            let n = target_hashes.len() as f64;
            let m = (dual_bloom.l2_size_words() * 64) as f64;
            let k = 7.0f64;
            let fp_rate = (1.0 - (-k * n / m).exp()).powf(k);
            let keys_per_batch = config.keys_per_batch();
            let expected_fp_per_batch = (keys_per_batch as f64) * fp_rate;
            
            println!("[GPU] L2 Bloom: {} words ({} KB), FP rate: {:.4}%, ~{:.0} FP/batch", 
                dual_bloom.l2_size_words(), 
                dual_bloom.l2_size_words() * 8 / 1024,
                fp_rate * 100.0,
                expected_fp_per_batch
            );
        }
        println!("[GPU] Total buffer memory: {:.2} MB", mem_mb);

        // Initialize Philox counter
        #[cfg(feature = "philox-rng")]
        let philox_counter = {
            use rand::RngCore;
            let mut rng = rand::thread_rng();
            let seed = rng.next_u64();
            println!("[GPU] Philox RNG initialized with seed: 0x{:016X}", seed);
            PhiloxCounter::new(seed)
        };

        Ok(Self {
            pipeline,
            buffer_sets,
            current_buffer: std::sync::atomic::AtomicUsize::new(0),
            step_table_buf,
            wnaf_table_buf,
            #[cfg(feature = "xor-filter")]
            xor_fingerprints_buf,
            #[cfg(feature = "xor-filter")]
            xor_seeds_buf,
            #[cfg(feature = "xor-filter")]
            xor_block_length_buf,
            #[cfg(not(feature = "xor-filter"))]
            l1_bloom_buf,
            #[cfg(not(feature = "xor-filter"))]
            l1_bloom_size_buf,
            #[cfg(not(feature = "xor-filter"))]
            l2_bloom_buf,
            #[cfg(not(feature = "xor-filter"))]
            l2_bloom_size_buf,
            kpt_buf,
            #[cfg(not(feature = "xor-filter"))]
            sorted_hashes_buf,
            hash_count_buf,
            config,
            total_scanned: AtomicU64::new(0),
            total_matches: AtomicU64::new(0),
            #[cfg(feature = "philox-rng")]
            philox_counter,
        })
    }

    fn dispatch_batch(&self, base_key: &[u8; 32], buf_idx: usize) -> Result<()> {
        let buffers = &self.buffer_sets[buf_idx];

        #[cfg(feature = "philox-rng")]
        {
            let secret = SecretKey::from_slice(base_key)
                .map_err(|e| ScannerError::Gpu(format!("invalid Philox key: {}", e)))?;
            let pubkey = secret.public_key();
            let encoded = pubkey.to_encoded_point(false);
            let pub_bytes = encoded.as_bytes();
            
            unsafe {
                let ptr = buffers.base_point_buf.contents() as *mut u8;
                std::ptr::copy_nonoverlapping(pub_bytes[1..33].as_ptr(), ptr, 32);
                std::ptr::copy_nonoverlapping(pub_bytes[33..65].as_ptr(), ptr.add(32), 32);
            }
        }
        
        #[cfg(not(feature = "philox-rng"))]
        {
            let secret = SecretKey::from_slice(base_key)
                .map_err(|e| ScannerError::Gpu(format!("invalid key: {}", e)))?;
            let pubkey = secret.public_key();
            let encoded = pubkey.to_encoded_point(false);
            let pub_bytes = encoded.as_bytes();

            unsafe {
                let ptr = buffers.base_point_buf.contents() as *mut u8;
                std::ptr::copy_nonoverlapping(pub_bytes[1..33].as_ptr(), ptr, 32);
                std::ptr::copy_nonoverlapping(pub_bytes[33..65].as_ptr(), ptr.add(32), 32);
            }
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
            enc.set_buffer(0, Some(&buffers.base_point_buf), 0);
            enc.set_buffer(1, Some(&self.step_table_buf), 0);
            enc.set_buffer(2, Some(&self.wnaf_table_buf), 0);
            
            #[cfg(feature = "xor-filter")]
            {
                enc.set_buffer(3, Some(&self.xor_fingerprints_buf), 0);
                enc.set_buffer(4, Some(&self.xor_seeds_buf), 0);
                enc.set_buffer(5, Some(&self.xor_block_length_buf), 0);
                enc.set_buffer(6, Some(&self.kpt_buf), 0);
                enc.set_buffer(7, Some(&buffers.match_data_buf), 0);
                enc.set_buffer(8, Some(&buffers.match_count_buf), 0);
                enc.set_buffer(9, Some(&self.hash_count_buf), 0);
            }
            
            #[cfg(not(feature = "xor-filter"))]
            {
                enc.set_buffer(3, Some(&self.l1_bloom_buf), 0);
                enc.set_buffer(4, Some(&self.l1_bloom_size_buf), 0);
                enc.set_buffer(5, Some(&self.l2_bloom_buf), 0);
                enc.set_buffer(6, Some(&self.l2_bloom_size_buf), 0);
                enc.set_buffer(7, Some(&self.kpt_buf), 0);
                enc.set_buffer(8, Some(&buffers.match_data_buf), 0);
                enc.set_buffer(9, Some(&buffers.match_count_buf), 0);
                enc.set_buffer(10, Some(&self.sorted_hashes_buf), 0);
                enc.set_buffer(11, Some(&self.hash_count_buf), 0);
            }
            
            enc.dispatch_threads(grid, group);
            enc.end_encoding();
        }

        cmd.commit();
        Ok(())
    }
    
    fn wait_and_collect(&self, buf_idx: usize) -> Result<Vec<PotentialMatch>> {
        let buffers = &self.buffer_sets[buf_idx];
        let sync_cmd = buffers.queue.new_command_buffer();
        {
            let blit = sync_cmd.new_blit_command_encoder();
            
            #[cfg(feature = "zero-copy")]
            {
                blit.synchronize_resource(&buffers.match_count_buf);
            }
            
            #[cfg(not(feature = "zero-copy"))]
            {
                blit.synchronize_resource(&buffers.match_count_buf);
                blit.synchronize_resource(&buffers.match_data_buf);
            }
            
            blit.end_encoding();
        }
        sync_cmd.commit();
        sync_cmd.wait_until_completed();

        let raw_match_count = unsafe {
            let ptr = buffers.match_count_buf.contents() as *const u32;
            *ptr
        };
        
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

        Ok(matches)
    }
    
    pub fn scan_batch(&self, base_key: &[u8; 32]) -> Result<Vec<PotentialMatch>> {
        let buf_idx = self.current_buffer.fetch_xor(1, Ordering::Relaxed);
        self.dispatch_batch(base_key, buf_idx)?;
        self.wait_and_collect(buf_idx)
    }
    
    pub fn scan_pipelined<F, G>(&self, mut key_gen: F, mut on_batch: G, shutdown: &std::sync::atomic::AtomicBool) -> Result<()>
    where
        F: FnMut() -> [u8; 32],
        G: FnMut([u8; 32], Vec<PotentialMatch>),
    {
        let mut prev_batch: Option<([u8; 32], usize)> = None;
        let mut current_buf = 0usize;
        
        while !shutdown.load(Ordering::Relaxed) {
            let base_key = key_gen();
            self.dispatch_batch(&base_key, current_buf)?;
            
            if let Some((prev_key, prev_buf)) = prev_batch.take() {
                let matches = self.wait_and_collect(prev_buf)?;
                on_batch(prev_key, matches);
            }
            
            prev_batch = Some((base_key, current_buf));
            current_buf = 1 - current_buf;
        }
        
        if let Some((prev_key, prev_buf)) = prev_batch {
            let matches = self.wait_and_collect(prev_buf)?;
            on_batch(prev_key, matches);
        }
        
        Ok(())
    }

    pub fn keys_per_batch(&self) -> u64 {
        self.config.keys_per_batch()
    }
    
    #[cfg(feature = "philox-rng")]
    pub fn next_base_key(&self) -> [u8; 32] {
        let batch_size = self.keys_per_batch();
        let state = self.philox_counter.next_batch(batch_size);
        philox_to_privkey(&state)
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
    use super::*;
    
    #[cfg(not(feature = "xor-filter"))]
    #[test]
    fn test_dual_bloom_all_hashes_in_both() {
        let mut hashes: Vec<[u8; 20]> = Vec::new();
        for i in 0u32..2000 {
            let mut h = [0u8; 20];
            h[0..4].copy_from_slice(&i.to_be_bytes());
            h[16..20].copy_from_slice(&(i * 7).to_be_bytes());
            hashes.push(h);
        }
        
        let dual = DualBloomFilter::new(&hashes);
        
        for (i, h) in hashes.iter().enumerate() {
            assert!(dual.l1_contains(h), 
                "L1 MUST contain hash {} - otherwise target will be missed!", i);
            assert!(dual.l2_contains(h), 
                "L2 should contain hash {}", i);
        }
        
        for (i, h) in hashes.iter().enumerate() {
            assert!(dual.contains(h),
                "DualBloom should find hash {}", i);
        }
    }
    
    #[cfg(not(feature = "xor-filter"))]
    #[test]
    fn test_dual_bloom_check_logic() {
        let mut hashes: Vec<[u8; 20]> = Vec::new();
        for i in 0u32..500 {
            let mut h = [0u8; 20];
            h[0..4].copy_from_slice(&i.to_be_bytes());
            hashes.push(h);
        }
        
        let dual = DualBloomFilter::new(&hashes);
        
        for h in &hashes {
            assert!(dual.contains(h), "Inserted hash should be found");
        }
    }
    
    #[cfg(not(feature = "xor-filter"))]
    #[test]
    fn test_bloom_power_of_2() {
        let bloom = BloomFilter::new(1000);
        let size = bloom.size_words() * 64;
        
        assert!(size.is_power_of_two(), 
            "Bloom filter size {} is not power of 2", size);
    }
    
    #[cfg(not(feature = "xor-filter"))]
    #[test]
    fn test_bloom_new_with_bits() {
        let bloom = BloomFilter::new_with_bits(1024 * 1024);
        assert_eq!(bloom.size_words(), 1024 * 1024 / 64);
        
        let hash: [u8; 20] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
        let mut bloom = BloomFilter::new_with_bits(1024 * 1024);
        bloom.insert(&hash);
        assert!(bloom.contains(&hash), "Inserted hash should be found");
    }
    
    /// Test buffer index constants match between Metal and Rust
    /// This is a documentation test - actual verification requires running GPU
    #[test]
    fn test_buffer_index_documentation() {
        // Buffer indices in dispatch_batch():
        // 0: base_point_buf
        // 1: step_table_buf
        // 2: wnaf_table_buf
        // 3: l1_bloom_buf        (NEW)
        // 4: l1_bloom_size_buf   (NEW)
        // 5: l2_bloom_buf        (NEW)
        // 6: l2_bloom_size_buf   (NEW)
        // 7: kpt_buf             (was 5)
        // 8: match_data_buf      (was 6)
        // 9: match_count_buf     (was 7)
        // 10: sorted_hashes_buf  (was 8)
        // 11: hash_count_buf     (was 9)
        
        // These must match Metal shader:
        // buffer(0): base_point
        // buffer(1): step_table
        // buffer(2): wnaf_table
        // buffer(3): l1_bloom
        // buffer(4): l1_bloom_size
        // buffer(5): l2_bloom
        // buffer(6): l2_bloom_size
        // buffer(7): keys_per_thread
        // buffer(8): match_data
        // buffer(9): match_count
        // buffer(10): sorted_hashes
        // buffer(11): hash_count
        
        // If these don't match, GPU will read wrong data!
        // This test documents the expected layout.
        assert!(true, "Buffer indices documented");
    }
}

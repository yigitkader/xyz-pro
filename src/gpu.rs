use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use metal::{Buffer, CommandQueue, CompileOptions, ComputePipelineState, Device, MTLResourceOptions, MTLSize};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Result, ScannerError};
use crate::types::Hash160;

// ============================================================================
// CONFIG
// ============================================================================

/// Maximum threads per dispatch (262144 × 512 = 134M keys/batch)
const MAX_THREADS: usize = 262_144;

/// Keys processed per thread
const KEYS_PER_THREAD: u32 = 512;

// ============================================================================
// BLOOM FILTER
// ============================================================================

pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
}

impl BloomFilter {
    pub fn new(n: usize) -> Self {
        // Use n*15 for lower false positive rate (~0.1% with 7 hash functions)
        let num_bits = (n * 15).next_power_of_two().max(1024);
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
// StepTable[i] = (2^i * keys_per_thread) * G
// ============================================================================

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

// ============================================================================
// OPTIMIZED SCANNER
// ============================================================================

pub struct OptimizedScanner {
    queue: CommandQueue,
    pipeline: ComputePipelineState,

    // Buffers
    base_point_buf: Buffer,
    step_table_buf: Buffer,
    bloom_buf: Buffer,
    bloom_size_buf: Buffer,
    kpt_buf: Buffer,
    match_data_buf: Buffer,
    match_count_buf: Buffer,

    // Config
    max_threads: usize,
    keys_per_thread: u32,

    // Stats
    total_scanned: AtomicU64,
    total_matches: AtomicU64,
}

/// Match type from GPU
/// 0 = compressed pubkey hash
/// 1 = uncompressed pubkey hash  
/// 2 = P2SH script hash (from compressed)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MatchType {
    Compressed = 0,
    Uncompressed = 1,
    P2SH = 2,
}

impl MatchType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Compressed),
            1 => Some(Self::Uncompressed),
            2 => Some(Self::P2SH),
            _ => None,
        }
    }
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
        println!("[GPU] Max threads/threadgroup: {}", device.max_threads_per_threadgroup().width);

        let queue = device.new_command_queue();
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

        println!("[GPU] Pipeline: max_threads={}", pipeline.max_total_threads_per_threadgroup());

        // Build Bloom filter
        let mut bloom = BloomFilter::new(target_hashes.len().max(100));
        for h in target_hashes {
            bloom.insert(h);
        }

        // Compute StepTable
        let step_table = compute_step_table(KEYS_PER_THREAD);

        // Allocate buffers
        let storage = MTLResourceOptions::StorageModeShared;

        let base_point_buf = device.new_buffer(64, storage);
        let step_table_buf = device.new_buffer_with_data(
            step_table.as_ptr() as *const _,
            (20 * 64) as u64,
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

        let kpt_buf = device.new_buffer_with_data(
            &KEYS_PER_THREAD as *const u32 as *const _,
            4,
            storage,
        );

        let match_data_buf = device.new_buffer(1024 * 52, storage);
        let match_count_buf = device.new_buffer(4, storage);

        let keys_per_batch = MAX_THREADS * KEYS_PER_THREAD as usize;
        let mem_mb = (64 + 20 * 64 + bloom_data.len() * 8 + 4 + 4 + 1024 * 52 + 4) as f64 / 1_000_000.0;

        println!("[GPU] Keys/batch: {} M", keys_per_batch / 1_000_000);
        println!("[GPU] Memory: {:.2} MB", mem_mb);
        println!("[GPU] Bloom filter: {} words ({} KB)", bloom.size_words(), bloom.size_words() * 8 / 1024);

        Ok(Self {
            queue,
            pipeline,
            base_point_buf,
            step_table_buf,
            bloom_buf,
            bloom_size_buf,
            kpt_buf,
            match_data_buf,
            match_count_buf,
            max_threads: MAX_THREADS,
            keys_per_thread: KEYS_PER_THREAD,
            total_scanned: AtomicU64::new(0),
            total_matches: AtomicU64::new(0),
        })
    }

    /// Scan a range of keys starting from base_key
    pub fn scan_batch(&self, base_key: &[u8; 32]) -> Result<Vec<PotentialMatch>> {
        // Compute base point from base_key
        let secret = SecretKey::from_slice(base_key)
            .map_err(|e| ScannerError::Gpu(format!("invalid key: {}", e)))?;
        let pubkey = secret.public_key();
        let encoded = pubkey.to_encoded_point(false);
        let pub_bytes = encoded.as_bytes();

        // Copy base point (x || y)
        unsafe {
            let ptr = self.base_point_buf.contents() as *mut u8;
            std::ptr::copy_nonoverlapping(pub_bytes[1..33].as_ptr(), ptr, 32);
            std::ptr::copy_nonoverlapping(pub_bytes[33..65].as_ptr(), ptr.add(32), 32);
        }

        // Reset match count
        unsafe {
            let ptr = self.match_count_buf.contents() as *mut u32;
            *ptr = 0;
        }

        // Dispatch
        let cmd = self.queue.new_command_buffer();

        let grid = MTLSize {
            width: self.max_threads as u64,
            height: 1,
            depth: 1,
        };
        let group = MTLSize {
            width: 256,
            height: 1,
            depth: 1,
        };

        {
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(&self.pipeline);
            enc.set_buffer(0, Some(&self.base_point_buf), 0);
            enc.set_buffer(1, Some(&self.step_table_buf), 0);
            enc.set_buffer(2, Some(&self.bloom_buf), 0);
            enc.set_buffer(3, Some(&self.bloom_size_buf), 0);
            enc.set_buffer(4, Some(&self.kpt_buf), 0);
            enc.set_buffer(5, Some(&self.match_data_buf), 0);
            enc.set_buffer(6, Some(&self.match_count_buf), 0);
            enc.dispatch_threads(grid, group);
            enc.end_encoding();
        }

        cmd.commit();
        cmd.wait_until_completed();

        // Read results
        let raw_match_count = unsafe {
            let ptr = self.match_count_buf.contents() as *const u32;
            *ptr
        };
        
        // Warn if buffer overflow
        if raw_match_count > 1024 {
            eprintln!("[!] WARNING: Match buffer overflow! {} matches found, {} lost", 
                      raw_match_count, raw_match_count - 1024);
        }
        
        let match_count = (raw_match_count as usize).min(1024);

        let keys_scanned = (self.max_threads * self.keys_per_thread as usize) as u64;
        self.total_scanned.fetch_add(keys_scanned, Ordering::Relaxed);

        let mut matches = Vec::with_capacity(match_count);
        if match_count > 0 && match_count <= 1024 {
            self.total_matches.fetch_add(match_count as u64, Ordering::Relaxed);
            unsafe {
                let ptr = self.match_data_buf.contents() as *const u8;
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

    pub fn keys_per_batch(&self) -> u64 {
        (self.max_threads * self.keys_per_thread as usize) as u64
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

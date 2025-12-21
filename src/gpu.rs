use metal::{
    Buffer, CommandQueue, CompileOptions, ComputePipelineState, Device, MTLResourceOptions, MTLSize,
};
use std::fs;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use crate::crypto::hash160;
use crate::error::{Result, ScannerError};
use crate::types::Hash160;

// ============================================================================
// CONFIG
// ============================================================================

const MAX_BATCH: usize = 65536;
const NUM_BUFFERS: usize = 3;
const THREADS: u64 = 256;
const VERIFY_INTERVAL: usize = 1000;

// ============================================================================
// BUFFER
// ============================================================================

struct GpuBuffer {
    // Compressed (33 bytes)
    comp_in: Buffer,
    comp_sha: Buffer,
    comp_out: Buffer,
    // Uncompressed (65 bytes)
    uncomp_in: Buffer,
    uncomp_sha: Buffer,
    uncomp_out: Buffer,
}

impl GpuBuffer {
    fn new(device: &Device, cap: usize) -> Self {
        let opts = MTLResourceOptions::StorageModeShared;
        Self {
            comp_in: device.new_buffer((cap * 33) as u64, opts),
            comp_sha: device.new_buffer((cap * 32) as u64, opts),
            comp_out: device.new_buffer((cap * 20) as u64, opts),
            uncomp_in: device.new_buffer((cap * 65) as u64, opts),
            uncomp_sha: device.new_buffer((cap * 32) as u64, opts),
            uncomp_out: device.new_buffer((cap * 20) as u64, opts),
        }
    }
}

// ============================================================================
// GPU HASHER
// ============================================================================

pub struct GpuHasher {
    queue: CommandQueue,
    sha256_33: ComputePipelineState,
    sha256_65: ComputePipelineState,
    ripemd160: ComputePipelineState,
    buffers: Vec<GpuBuffer>,
    capacity: usize,
    buf_idx: AtomicUsize,
    batch_count: AtomicUsize,
    total: AtomicU64,
}

impl GpuHasher {
    pub fn new() -> Result<Self> {
        let device = Device::system_default()
            .ok_or_else(|| ScannerError::Gpu("No Metal GPU".into()))?;

        println!("[i] GPU: {}", device.name());

        let queue = device.new_command_queue();
        let opts = CompileOptions::new();

        let sha256_33 = Self::load(&device, &opts, "sha256_33", "sha256_hash")?;
        let sha256_65 = Self::load(&device, &opts, "sha256_65", "sha256_hash_65")?;
        let ripemd160 = Self::load(&device, &opts, "ripemd160", "ripemd160_hash")?;

        let buffers: Vec<GpuBuffer> = (0..NUM_BUFFERS)
            .map(|_| GpuBuffer::new(&device, MAX_BATCH))
            .collect();

        let mem = NUM_BUFFERS * MAX_BATCH * (33 + 32 + 20 + 65 + 32 + 20);
        println!("[i] GPU Memory: {:.2} MB", mem as f64 / 1_000_000.0);

        Ok(Self {
            queue,
            sha256_33,
            sha256_65,
            ripemd160,
            buffers,
            capacity: MAX_BATCH,
            buf_idx: AtomicUsize::new(0),
            batch_count: AtomicUsize::new(0),
            total: AtomicU64::new(0),
        })
    }

    fn load(device: &Device, opts: &CompileOptions, file: &str, func: &str) -> Result<ComputePipelineState> {
        let src = fs::read_to_string(format!("src/{}.metal", file))
            .map_err(|e| ScannerError::Gpu(format!("{}.metal: {}", file, e)))?;

        let lib = device.new_library_with_source(&src, opts)
            .map_err(|e| ScannerError::Gpu(format!("{}: {}", file, e)))?;

        let function = lib.get_function(func, None)
            .map_err(|e| ScannerError::Gpu(format!("{}: {}", func, e)))?;

        device.new_compute_pipeline_state_with_function(&function)
            .map_err(|e| ScannerError::Gpu(format!("pipeline: {}", e)))
    }

    /// Compute Hash160 for both compressed and uncompressed pubkeys
    pub fn compute(&self, comp: &[[u8; 33]], uncomp: &[[u8; 65]]) -> Result<(Vec<Hash160>, Vec<Hash160>)> {
        let count = comp.len();
        if count == 0 || count != uncomp.len() {
            return Ok((Vec::new(), Vec::new()));
        }
        if count > self.capacity {
            return Err(ScannerError::Gpu("Batch too large".into()));
        }

        let idx = self.buf_idx.fetch_add(1, Ordering::SeqCst) % NUM_BUFFERS;
        let buf = &self.buffers[idx];

        // Copy to GPU
        unsafe {
            let ptr33 = buf.comp_in.contents() as *mut u8;
            let ptr65 = buf.uncomp_in.contents() as *mut u8;
            for i in 0..count {
                std::ptr::copy_nonoverlapping(comp[i].as_ptr(), ptr33.add(i * 33), 33);
                std::ptr::copy_nonoverlapping(uncomp[i].as_ptr(), ptr65.add(i * 65), 65);
            }
        }

        let cmd = self.queue.new_command_buffer();
        let grid = MTLSize { width: count as u64, height: 1, depth: 1 };
        let group = MTLSize { width: THREADS.min(count as u64), height: 1, depth: 1 };

        // SHA256 compressed
        {
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(&self.sha256_33);
            enc.set_buffer(0, Some(&buf.comp_in), 0);
            enc.set_buffer(1, Some(&buf.comp_sha), 0);
            enc.dispatch_threads(grid, group);
            enc.end_encoding();
        }

        // SHA256 uncompressed
        {
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(&self.sha256_65);
            enc.set_buffer(0, Some(&buf.uncomp_in), 0);
            enc.set_buffer(1, Some(&buf.uncomp_sha), 0);
            enc.dispatch_threads(grid, group);
            enc.end_encoding();
        }

        // RIPEMD160 compressed
        {
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(&self.ripemd160);
            enc.set_buffer(0, Some(&buf.comp_sha), 0);
            enc.set_buffer(1, Some(&buf.comp_out), 0);
            enc.dispatch_threads(grid, group);
            enc.end_encoding();
        }

        // RIPEMD160 uncompressed
        {
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(&self.ripemd160);
            enc.set_buffer(0, Some(&buf.uncomp_sha), 0);
            enc.set_buffer(1, Some(&buf.uncomp_out), 0);
            enc.dispatch_threads(grid, group);
            enc.end_encoding();
        }

        cmd.commit();
        cmd.wait_until_completed();

        // Read results
        let mut comp_hashes = Vec::with_capacity(count);
        let mut uncomp_hashes = Vec::with_capacity(count);

        unsafe {
            let p1 = buf.comp_out.contents() as *const u8;
            let p2 = buf.uncomp_out.contents() as *const u8;
            for i in 0..count {
                let mut h1 = [0u8; 20];
                let mut h2 = [0u8; 20];
                std::ptr::copy_nonoverlapping(p1.add(i * 20), h1.as_mut_ptr(), 20);
                std::ptr::copy_nonoverlapping(p2.add(i * 20), h2.as_mut_ptr(), 20);
                comp_hashes.push(Hash160::from_slice(&h1));
                uncomp_hashes.push(Hash160::from_slice(&h2));
            }
        }

        self.total.fetch_add(count as u64, Ordering::Relaxed);
        let batch = self.batch_count.fetch_add(1, Ordering::Relaxed);

        // Verify periodically
        if batch % VERIFY_INTERVAL == 0 && !comp.is_empty() {
            let cpu = hash160(&comp[0]);
            if cpu != *comp_hashes[0].as_bytes() {
                return Err(ScannerError::Gpu("GPU/CPU hash mismatch".into()));
            }
        }

        Ok((comp_hashes, uncomp_hashes))
    }
}

unsafe impl Send for GpuHasher {}
unsafe impl Sync for GpuHasher {}

// ============================================================================
// BLOOM FILTER
// ============================================================================

pub struct BloomFilter {
    bits: Vec<u64>,
    num_words: usize,
}

impl BloomFilter {
    pub fn new(n: usize) -> Self {
        let total_bits = n * 10; // ~1% false positive
        let num_words = ((total_bits + 63) / 64).max(1);
        Self {
            bits: vec![0u64; num_words],
            num_words,
        }
    }

    pub fn add(&mut self, h: &[u8; 20]) {
        for pos in self.positions(h) {
            let (w, b) = ((pos / 64) as usize, pos % 64);
            if w < self.num_words {
                self.bits[w] |= 1u64 << b;
            }
        }
    }

    pub fn check(&self, h: &[u8; 20]) -> bool {
        for pos in self.positions(h) {
            let (w, b) = ((pos / 64) as usize, pos % 64);
            if w >= self.num_words || (self.bits[w] & (1u64 << b)) == 0 {
                return false;
            }
        }
        true
    }

    fn positions(&self, h: &[u8; 20]) -> [u64; 7] {
        let h1 = u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);
        let h2 = u64::from_le_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]);
        let h3 = u32::from_le_bytes([h[16], h[17], h[18], h[19]]) as u64;
        let total = (self.num_words * 64) as u64;

        let mut p = [0u64; 7];
        for i in 0..7 {
            let m = (i + 1) as u64;
            p[i] = h1.wrapping_add(h2.wrapping_mul(m))
                     .wrapping_add(h3.wrapping_mul(m * m)) % total;
        }
        p
    }
}

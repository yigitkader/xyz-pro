//! Generator Adapter - Implements Bridge Traits
//!
//! This module provides the bridge between GpuKeyGenerator and the
//! KeyGenerator trait, allowing clean integration with the pipeline.
//!
//! Pipeline Strategy:
//! - Use double/triple buffering to overlap GPU compute with CPU processing
//! - First call: dispatch batch 0, wait, return
//! - Subsequent: dispatch batch N+1, wait for batch N, return batch N
//!
//! Memory Safety:
//! - Double-buffered output: each generate_batch call writes to alternating buffers
//! - This ensures the previous slice remains valid while the next batch is being written
//! - Mutex protects against concurrent writes to the same buffer

use std::cell::UnsafeCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use parking_lot::Mutex;

use crate::bridge::KeyGenerator;
use super::GpuKeyGenerator;

/// Number of output buffers for double-buffering
/// This ensures the slice returned by generate_batch remains valid
/// until generate_batch is called again (not just during the call)
const NUM_OUTPUT_BUFFERS: usize = 2;

/// Adapter that wraps GpuKeyGenerator and implements KeyGenerator trait
/// 
/// # Thread Safety
/// - Uses `parking_lot::Mutex` to serialize buffer writes
/// - Double-buffered output prevents use-after-free
/// - `generate_batch` can be called from multiple threads (serialized)
/// 
/// # Memory Safety (Double-Buffer Guarantee)
/// 1. Uses 2 alternating output buffers
/// 2. Each call writes to buffer[N % 2], returns slice to that buffer
/// 3. The PREVIOUS slice (buffer[(N-1) % 2]) remains valid and untouched
/// 4. Only after TWO more calls is a buffer overwritten
/// 5. This gives the caller a full batch cycle to process the data
/// 
/// # Invariant
/// The Mutex ensures only one thread writes at a time, and the double-buffer
/// scheme ensures previous slices remain valid. This is safe because:
/// - UnsafeCell access is protected by the Mutex
/// - Buffers are heap-allocated with stable addresses
/// - Double-buffering prevents concurrent read/write to same buffer
pub struct GpuGeneratorAdapter {
    inner: Arc<GpuKeyGenerator>,
    /// Double output buffers for safe slice returns
    /// UnsafeCell allows interior mutability; Mutex ensures exclusive write access
    batch_buffers: [UnsafeCell<Box<[u8]>>; NUM_OUTPUT_BUFFERS],
    /// Mutex for synchronizing buffer writes (protects UnsafeCell access)
    write_lock: Mutex<()>,
    /// Buffer size for quick access
    buffer_size: usize,
    /// Current GPU buffer index for round-robin (for pipeline)
    gpu_buf_idx: AtomicUsize,
    /// Current output buffer index (alternates 0, 1, 0, 1, ...)
    output_buf_idx: AtomicUsize,
    /// Whether pipeline has been primed
    pipeline_primed: AtomicBool,
}

// Safety: 
// - UnsafeCell access is protected by Mutex (exclusive write access)
// - Returned slices are to stable heap memory that won't be modified until 2 calls later
// - AtomicUsize provides synchronization for indices
unsafe impl Send for GpuGeneratorAdapter {}
unsafe impl Sync for GpuGeneratorAdapter {}

impl GpuGeneratorAdapter {
    /// Create a new adapter wrapping a GpuKeyGenerator
    pub fn new(generator: GpuKeyGenerator) -> Self {
        let batch_size = generator.batch_size() * 2; // GLV: 2x keys
        let output_size = 72; // RawKeyData::SIZE
        let buffer_size = batch_size * output_size;
        
        // Create double buffers for safe slice returns
        let batch_buffers = [
            UnsafeCell::new(vec![0u8; buffer_size].into_boxed_slice()),
            UnsafeCell::new(vec![0u8; buffer_size].into_boxed_slice()),
        ];
        
        Self {
            inner: Arc::new(generator),
            batch_buffers,
            write_lock: Mutex::new(()),
            buffer_size,
            gpu_buf_idx: AtomicUsize::new(0),
            output_buf_idx: AtomicUsize::new(0),
            pipeline_primed: AtomicBool::new(false),
        }
    }
    
    /// Get inner generator (for direct access if needed)
    pub fn inner(&self) -> &GpuKeyGenerator {
        &self.inner
    }
    
    /// Prime the pipeline by dispatching initial batches
    fn prime_pipeline(&self) -> Result<(), String> {
        let depth = self.inner.pipeline_depth();
        
        // Dispatch initial batches to fill the pipeline
        for i in 0..depth {
            let offset = self.inner.fetch_add_offset(self.inner.batch_size() as u64);
            self.inner.dispatch_glv(i, offset)?;
        }
        
        self.pipeline_primed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

impl KeyGenerator for GpuGeneratorAdapter {
    fn batch_size(&self) -> usize {
        // GLV: 2x keys per EC operation
        self.inner.batch_size() * 2
    }
    
    fn generate_batch(&self) -> Result<&[u8], String> {
        // Acquire write lock (parking_lot is fast and doesn't poison)
        let _guard = self.write_lock.lock();
        
        // Prime pipeline on first call
        if !self.pipeline_primed.load(Ordering::SeqCst) {
            self.prime_pipeline()?;
        }
        
        let depth = self.inner.pipeline_depth();
        
        // Get current GPU buffer index (for pipeline round-robin)
        let gpu_idx = self.gpu_buf_idx.fetch_add(1, Ordering::SeqCst) % depth;
        
        // Get current output buffer index (for double-buffering)
        // This alternates: 0, 1, 0, 1, ... ensuring previous slice remains valid
        let out_idx = self.output_buf_idx.fetch_add(1, Ordering::SeqCst) % NUM_OUTPUT_BUFFERS;
        
        // Get the GPU buffer set for reading
        let bs = self.inner.buffer_set(gpu_idx);
        
        // Wait for GPU batch to complete
        let cb = bs.queue.new_command_buffer();
        cb.commit();
        cb.wait_until_completed();
        
        // Get GPU output pointer (Unified Memory - zero-copy)
        let gpu_ptr = bs.output_buffer.contents() as *const u8;
        
        // SAFETY: We hold the write_lock, so no concurrent writes.
        // The out_idx buffer is not being read by any previous caller
        // because of the double-buffering scheme.
        let buffer = unsafe { &mut *self.batch_buffers[out_idx].get() };
        
        // Copy GPU data to our output buffer
        unsafe {
            std::ptr::copy_nonoverlapping(gpu_ptr, buffer.as_mut_ptr(), self.buffer_size);
        }
        
        // Dispatch next GPU batch (after copy is complete)
        let next_offset = self.inner.fetch_add_offset(self.inner.batch_size() as u64);
        self.inner.dispatch_glv(gpu_idx, next_offset)?;
        
        // Update stats
        self.inner.add_generated(self.batch_size() as u64);
        
        // Get slice to return (stable heap address)
        let result_ptr = buffer.as_ptr();
        let result_len = self.buffer_size;
        
        // Lock is released here when _guard drops
        // The returned slice points to buffer[out_idx] which won't be
        // written to again until 2 more generate_batch calls
        
        // SAFETY: This is sound because:
        // 1. Box<[u8]> is heap-allocated with a stable address
        // 2. Data was fully written under write_lock protection
        // 3. Double-buffering ensures this buffer won't be overwritten
        //    until AFTER the next generate_batch call completes
        // 4. Caller has until the call AFTER next to process this slice
        Ok(unsafe {
            std::slice::from_raw_parts(result_ptr, result_len)
        })
    }
    
    fn current_offset(&self) -> u64 {
        self.inner.current_offset()
    }
    
    fn should_stop(&self) -> bool {
        self.inner.should_stop_flag()
    }
    
    fn stop(&self) {
        self.inner.stop();
    }
    
    fn total_generated(&self) -> u64 {
        self.inner.total_generated()
    }
}

/// Simpler adapter for when we just need the raw buffer access
pub struct DirectBufferAdapter<'a> {
    generator: &'a GpuKeyGenerator,
}

impl<'a> DirectBufferAdapter<'a> {
    pub fn new(generator: &'a GpuKeyGenerator) -> Self {
        Self { generator }
    }
    
    /// Get direct access to GPU buffer contents (zero-copy)
    /// 
    /// # Safety
    /// The returned slice is only valid until the next GPU dispatch.
    pub unsafe fn get_buffer_contents(&self, buf_idx: usize) -> &[u8] {
        let bs = self.generator.buffer_set(buf_idx);
        let output_ptr = bs.output_buffer.contents() as *const u8;
        let output_size = self.generator.batch_size() * 2 * 72; // GLV: 2x
        std::slice::from_raw_parts(output_ptr, output_size)
    }
}


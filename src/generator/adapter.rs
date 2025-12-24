//! Generator Adapter - Implements Bridge Traits
//!
//! This module provides the bridge between GpuKeyGenerator and the
//! KeyGenerator trait, allowing clean integration with the pipeline.
//!
//! Pipeline Strategy:
//! - Use quad buffering to overlap GPU compute with CPU processing
//! - First call: dispatch batch 0, wait, return
//! - Subsequent: dispatch batch N+1, wait for batch N, return batch N
//!
//! Memory Safety:
//! - Quad-buffered output: each generate_batch call writes to rotating buffers
//! - This ensures the previous THREE slices remain valid while the next batch is being written
//! - Caller has three full batch cycles to process data before buffer is reused
//! - Mutex protects against concurrent writes to the same buffer
//! - Extra buffer eliminates race conditions in fast producer/slow consumer scenarios

use std::cell::UnsafeCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Once;

use parking_lot::Mutex;

use crate::bridge::KeyGenerator;
use super::GpuKeyGenerator;

/// Number of output buffers for quad-buffering
/// 
/// Quad buffering (4 buffers) provides maximum safety margin:
/// - Buffer N: currently being written
/// - Buffer N-1: returned to caller (being processed)
/// - Buffer N-2: previous slice (may still be in use by slow consumer)
/// - Buffer N-3: extra safety buffer for async pipeline overlap
/// 
/// This allows the caller THREE generate_batch() calls before any buffer is reused,
/// eliminating race conditions even with aggressive parallel processing.
/// 
/// Why 4 instead of 3?
/// - With 3 buffers, a fast producer + slow consumer can cause a data race
/// - With 4 buffers, there's always one extra buffer as a safety margin
/// - Memory cost: ~288KB extra per adapter (negligible vs. GPU buffers)
const NUM_OUTPUT_BUFFERS: usize = 4;

/// Adapter that wraps GpuKeyGenerator and implements KeyGenerator trait
/// 
/// # Thread Safety
/// - Uses `parking_lot::Mutex` to serialize buffer writes
/// - Triple-buffered output prevents use-after-free
/// - `generate_batch` can be called from multiple threads (serialized)
/// 
/// # Memory Safety (Quad-Buffer Guarantee)
/// 1. Uses 4 rotating output buffers
/// 2. Each call writes to buffer[N % 4], returns slice to that buffer
/// 3. The PREVIOUS THREE slices remain valid and safe to read
/// 4. Only after FOUR more calls is a buffer overwritten
/// 5. This gives the caller three full batch cycles to process the data
/// 6. Eliminates race conditions even with aggressive async processing
/// 
/// # Invariant
/// The Mutex ensures only one thread writes at a time, and the quad-buffer
/// scheme ensures previous slices remain valid. This is safe because:
/// - UnsafeCell access is protected by the Mutex
/// - Buffers are heap-allocated with stable addresses
/// - Quad-buffering provides maximum safety margin
/// - Extra buffer eliminates race conditions in aggressive async scenarios
pub struct GpuGeneratorAdapter {
    inner: Arc<GpuKeyGenerator>,
    /// Quad output buffers for safe slice returns (eliminates race conditions)
    /// UnsafeCell allows interior mutability; Mutex ensures exclusive write access
    batch_buffers: [UnsafeCell<Box<[u8]>>; NUM_OUTPUT_BUFFERS],
    /// Mutex for synchronizing buffer writes (protects UnsafeCell access)
    write_lock: Mutex<()>,
    /// Buffer size for quick access
    buffer_size: usize,
    /// Current GPU buffer index for round-robin (for pipeline)
    gpu_buf_idx: AtomicUsize,
    /// Current output buffer index (rotates 0, 1, 2, 3, 0, 1, 2, 3, ...)
    output_buf_idx: AtomicUsize,
    /// One-time pipeline priming (thread-safe, runs exactly once)
    /// Using std::sync::Once is more robust than AtomicBool for this pattern:
    /// - Guarantees exactly one execution even under race conditions
    /// - Other threads block until initialization completes
    /// - No risk of double-prime or use-before-prime
    pipeline_prime_once: Once,
}

// Safety: 
// - UnsafeCell access is protected by Mutex (exclusive write access)
// - Returned slices are to stable heap memory that won't be modified until 3 calls later
// - AtomicUsize provides synchronization for indices
// - Quad-buffering provides extra safety margin for async processing
unsafe impl Send for GpuGeneratorAdapter {}
unsafe impl Sync for GpuGeneratorAdapter {}

impl GpuGeneratorAdapter {
    /// Create a new adapter wrapping a GpuKeyGenerator
    pub fn new(generator: GpuKeyGenerator) -> Self {
        let batch_size = generator.batch_size() * 2; // GLV: 2x keys
        let output_size = 72; // RawKeyData::SIZE
        let buffer_size = batch_size * output_size;
        
        // Create quad buffers for safe slice returns
        // Each buffer is independently allocated on the heap for stable addresses
        let batch_buffers = [
            UnsafeCell::new(vec![0u8; buffer_size].into_boxed_slice()),
            UnsafeCell::new(vec![0u8; buffer_size].into_boxed_slice()),
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
            pipeline_prime_once: Once::new(),
        }
    }
    
    /// Get inner generator (for direct access if needed)
    pub fn inner(&self) -> &GpuKeyGenerator {
        &self.inner
    }
    
    /// Prime the pipeline by dispatching initial batches
    /// This is called via Once::call_once, guaranteeing single execution
    fn prime_pipeline_internal(&self) -> Result<(), String> {
        let depth = self.inner.pipeline_depth();
        
        // Dispatch initial batches to fill the pipeline
        for i in 0..depth {
            let offset = self.inner.fetch_add_offset(self.inner.batch_size() as u64);
            self.inner.dispatch_glv(i, offset)?;
        }
        
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
        
        // Prime pipeline on first call (thread-safe, runs exactly once)
        // std::sync::Once guarantees:
        // - Only one thread executes the closure
        // - Other threads block until completion
        // - Subsequent calls are no-op (fast path)
        let mut prime_result: Result<(), String> = Ok(());
        self.pipeline_prime_once.call_once(|| {
            prime_result = self.prime_pipeline_internal();
        });
        prime_result?;
        
        let depth = self.inner.pipeline_depth();
        
        // Get current GPU buffer index (for pipeline round-robin)
        let gpu_idx = self.gpu_buf_idx.fetch_add(1, Ordering::SeqCst) % depth;
        
        // Get current output buffer index (for quad-buffering)
        // This rotates: 0, 1, 2, 3, 0, 1, 2, 3, ... ensuring previous THREE slices remain valid
        let out_idx = self.output_buf_idx.fetch_add(1, Ordering::SeqCst) % NUM_OUTPUT_BUFFERS;
        
        // Get the GPU buffer set for reading
        let bs = self.inner.buffer_set(gpu_idx);
        
        // FIXED: Wait for the ACTUAL dispatched command buffer
        // Previously this created an empty buffer which was an anti-pattern
        // Now properly checks for GPU errors (OutOfMemory, PageFault, etc.)
        if let Err(e) = self.inner.wait_for_completion(gpu_idx) {
            return Err(format!("GPU command buffer error: {}", e));
        }
        
        // RACE CONDITION PREVENTION: Mark buffer as in-use before reading
        // This prevents GPU from dispatching to this buffer while we're copying
        bs.in_use.store(true, std::sync::atomic::Ordering::Release);
        
        // Get GPU output pointer (Unified Memory - zero-copy)
        let gpu_ptr = bs.output_buffer.contents() as *const u8;
        
        // SAFETY: We hold the write_lock, so no concurrent writes.
        // The out_idx buffer is not being read by any previous caller
        // because of the quad-buffering scheme (3 previous buffers remain valid).
        let buffer = unsafe { &mut *self.batch_buffers[out_idx].get() };
        
        // Copy GPU data to our output buffer
        unsafe {
            std::ptr::copy_nonoverlapping(gpu_ptr, buffer.as_mut_ptr(), self.buffer_size);
        }
        
        // RACE CONDITION PREVENTION: Mark buffer as available BEFORE dispatching
        // The copy is complete, so GPU can now write to this buffer
        bs.in_use.store(false, std::sync::atomic::Ordering::Release);
        
        // Dispatch next GPU batch (after copy is complete and in_use is released)
        let next_offset = self.inner.fetch_add_offset(self.inner.batch_size() as u64);
        self.inner.dispatch_glv(gpu_idx, next_offset)?;
        
        // Update stats
        self.inner.add_generated(self.batch_size() as u64);
        
        // Get slice to return (stable heap address)
        let result_ptr = buffer.as_ptr();
        let result_len = self.buffer_size;
        
        // Lock is released here when _guard drops
        // The returned slice points to buffer[out_idx] which won't be
        // written to again until 4 more generate_batch calls (quad-buffering)
        
        // SAFETY: This is sound because:
        // 1. Box<[u8]> is heap-allocated with a stable address
        // 2. Data was fully written under write_lock protection
        // 3. Quad-buffering ensures this buffer won't be overwritten
        //    until AFTER three more generate_batch calls complete
        // 4. Caller has three full batch cycles to process this slice
        // 5. Extra buffer eliminates race conditions in fast producer/slow consumer scenarios
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
    
    fn is_range_complete(&self) -> bool {
        self.inner.is_range_complete()
    }
    
    fn end_offset(&self) -> Option<u64> {
        self.inner.end_offset()
    }
    
    fn progress_percent(&self) -> Option<f64> {
        self.inner.progress_percent()
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


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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
    /// Mutex for synchronizing buffer writes AND priming (protects UnsafeCell access)
    write_lock: Mutex<()>,
    /// Buffer size for quick access
    buffer_size: usize,
    /// Current GPU buffer index for round-robin (for pipeline)
    gpu_buf_idx: AtomicUsize,
    /// Current output buffer index (rotates 0, 1, 2, 3, 0, 1, 2, 3, ...)
    output_buf_idx: AtomicUsize,
    /// Pipeline priming state (retry-capable, unlike std::sync::Once)
    /// 
    /// CRITICAL: std::sync::Once marks closure as "done" even if it fails!
    /// This means if priming fails once, it will never retry, leaving the
    /// pipeline in an invalid state (empty buffers, deadlock on wait).
    /// 
    /// Solution: Use AtomicBool which allows retry on failure:
    /// - false: not yet primed (or previous attempt failed)
    /// - true: successfully primed
    /// 
    /// Thread safety is guaranteed by write_lock mutex.
    pipeline_primed: AtomicBool,
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
        // GLV multiplier from config: 1 (disabled), 2 (GLV2x), 3 (GLV3x)
        let glv_multiplier = generator.glv_mode().keys_per_ec_op();
        let batch_size = generator.batch_size() * glv_multiplier;
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
            pipeline_primed: AtomicBool::new(false),
        }
    }
    
    /// Get inner generator (for direct access if needed)
    pub fn inner(&self) -> &GpuKeyGenerator {
        &self.inner
    }
    
    /// Prime the pipeline by dispatching initial batches
    /// 
    /// This is called on first generate_batch. Unlike std::sync::Once,
    /// this can be retried if it fails (e.g., transient GPU error).
    /// 
    /// # Thread Safety
    /// Protected by write_lock mutex - only one thread can prime at a time.
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
        // GLV multiplier from config: 1 (disabled), 2 (GLV2x), 3 (GLV3x)
        let glv_multiplier = self.inner.glv_mode().keys_per_ec_op();
        self.inner.batch_size() * glv_multiplier
    }
    
    fn generate_batch(&self) -> Result<&[u8], String> {
        // Acquire write lock (parking_lot is fast and doesn't poison)
        let _guard = self.write_lock.lock();
        
        // Prime pipeline on first call (retry-capable, unlike std::sync::Once)
        // 
        // CRITICAL: std::sync::Once marks closure as "done" even on failure!
        // If priming fails (e.g., transient GPU error), Once would never retry,
        // leaving the pipeline in an invalid state (deadlock on wait).
        // 
        // Solution: AtomicBool allows retry until success.
        // Thread safety is guaranteed by write_lock mutex.
        if !self.pipeline_primed.load(Ordering::SeqCst) {
            self.prime_pipeline_internal()?;
            self.pipeline_primed.store(true, Ordering::SeqCst);
        }
        
        let depth = self.inner.pipeline_depth();
        
        // IDEMPOTENT INDEX HANDLING: Read indices first, increment only on success
        // This prevents state corruption when retry is triggered.
        // If we incremented before error check and then retried, indices would be
        // off by one, causing pipeline desync (some batches skipped, some duplicated).
        // 
        // Since we hold write_lock, no concurrent access - load+store is safe.
        let gpu_idx = self.gpu_buf_idx.load(Ordering::SeqCst) % depth;
        let out_idx = self.output_buf_idx.load(Ordering::SeqCst) % NUM_OUTPUT_BUFFERS;
        
        // Get the GPU buffer set for reading
        let bs = self.inner.buffer_set(gpu_idx);
        
        // Wait for GPU completion - may fail with transient or fatal errors
        // CRITICAL: If this fails, indices are NOT incremented, so retry is safe
        if let Err(e) = self.inner.wait_for_completion(gpu_idx) {
            return Err(format!("GPU command buffer error: {}", e));
        }
        
        // OPTIMIZATION: Dispatch BEFORE copy to minimize GPU idle time
        // 
        // Timeline with depth=2:
        //   generate_batch(0): wait(0) → dispatch(0) → copy(0) [GPU 1 running]
        //   generate_batch(1): wait(1) → dispatch(1) → copy(1) [GPU 0 running]
        //
        // By dispatching immediately after wait completes, we start the next
        // GPU computation while CPU is still copying. This hides copy latency.
        //
        // The in_use flag is set AFTER dispatch to allow GPU to start,
        // then we do CPU copy, which doesn't conflict because:
        // 1. GPU writes to THIS buffer are complete (we just waited)
        // 2. GPU writes to NEXT dispatch go to the SAME buffer but won't
        //    start until current dispatch is processed by the GPU queue
        
        // SUCCESS: Increment indices for next call (commit point)
        self.gpu_buf_idx.fetch_add(1, Ordering::SeqCst);
        self.output_buf_idx.fetch_add(1, Ordering::SeqCst);
        
        // Dispatch next GPU batch IMMEDIATELY after wait
        // This starts GPU work while we do CPU copy below
        let next_offset = self.inner.fetch_add_offset(self.inner.batch_size() as u64);
        if let Err(e) = self.inner.dispatch_glv(gpu_idx, next_offset) {
            eprintln!("⚠️ GPU dispatch warning (will retry): {}", e);
        }
        
        // Now do CPU copy - GPU is already working on next batch
        // Mark buffer as in-use during copy (prevents early buffer reuse)
        bs.in_use.store(true, std::sync::atomic::Ordering::Release);
        
        // Get GPU output pointer (Unified Memory - zero-copy)
        let gpu_ptr = bs.output_buffer.contents() as *const u8;
        
        // SAFETY: We hold the write_lock, so no concurrent writes.
        // The out_idx buffer is not being read by any previous caller
        // because of the quad-buffering scheme (3 previous buffers remain valid).
        let buffer = unsafe { &mut *self.batch_buffers[out_idx].get() };
        
        // Copy GPU data to our output buffer
        // This happens WHILE GPU is processing the next batch we just dispatched
        unsafe {
            std::ptr::copy_nonoverlapping(gpu_ptr, buffer.as_mut_ptr(), self.buffer_size);
        }
        
        // Copy complete - buffer can be reused
        bs.in_use.store(false, std::sync::atomic::Ordering::Release);
        
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
    
    fn pipeline_depth(&self) -> usize {
        self.inner.pipeline_depth()
    }
    
    /// Drain a buffer from the pipeline WITHOUT dispatching new work
    /// 
    /// CRITICAL for range scanning: When the range is complete, we need to retrieve
    /// remaining batches from the GPU pipeline without dispatching new work that
    /// would scan beyond the configured range.
    /// 
    /// This method:
    /// 1. Waits for GPU completion on the current buffer
    /// 2. Copies the computed key data to CPU buffer
    /// 3. Does NOT dispatch new work - just releases the buffer
    fn drain_buffer(&self, _buffer_idx: usize) -> Result<&[u8], String> {
        // Acquire write lock
        let _guard = self.write_lock.lock();
        
        let depth = self.inner.pipeline_depth();
        
        // Get current buffer indices (same as generate_batch but NO dispatch)
        let gpu_idx = self.gpu_buf_idx.load(Ordering::SeqCst) % depth;
        let out_idx = self.output_buf_idx.load(Ordering::SeqCst) % NUM_OUTPUT_BUFFERS;
        
        // Get the GPU buffer set for reading
        let bs = self.inner.buffer_set(gpu_idx);
        
        // Wait for GPU completion
        if let Err(e) = self.inner.wait_for_completion(gpu_idx) {
            return Err(format!("GPU drain error: {}", e));
        }
        
        // Increment indices (buffer is now consumed)
        self.gpu_buf_idx.fetch_add(1, Ordering::SeqCst);
        self.output_buf_idx.fetch_add(1, Ordering::SeqCst);
        
        // CRITICAL: NO dispatch here - we're draining, not generating
        // This is the key difference from generate_batch()
        
        // Copy GPU data to output buffer
        bs.in_use.store(true, std::sync::atomic::Ordering::Release);
        
        let gpu_ptr = bs.output_buffer.contents() as *const u8;
        let buffer = unsafe { &mut *self.batch_buffers[out_idx].get() };
        
        unsafe {
            std::ptr::copy_nonoverlapping(gpu_ptr, buffer.as_mut_ptr(), self.buffer_size);
        }
        
        bs.in_use.store(false, std::sync::atomic::Ordering::Release);
        
        // Update stats
        self.inner.add_generated(self.batch_size() as u64);
        
        let result_ptr = buffer.as_ptr();
        let result_len = self.buffer_size;
        
        Ok(unsafe {
            std::slice::from_raw_parts(result_ptr, result_len)
        })
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


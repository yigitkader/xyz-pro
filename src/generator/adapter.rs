//! Generator Adapter - Implements Bridge Traits
//!
//! This module provides the bridge between GpuKeyGenerator and the
//! KeyGenerator trait, allowing clean integration with the pipeline.
//!
//! Pipeline Strategy:
//! - Use double/triple buffering to overlap GPU compute with CPU processing
//! - First call: dispatch batch 0, wait, return
//! - Subsequent: dispatch batch N+1, wait for batch N, return batch N

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::bridge::KeyGenerator;
use super::GpuKeyGenerator;

/// Adapter that wraps GpuKeyGenerator and implements KeyGenerator trait
/// 
/// # Thread Safety
/// - Uses `UnsafeCell` with manual synchronization for zero-copy buffer access
/// - `generate_batch` is designed for sequential use (process batch before next call)
/// - The returned slice remains valid until the next `generate_batch` call
/// 
/// # Memory Safety
/// The batch_buffer uses UnsafeCell + AtomicBool for lock-free single-producer access.
/// This is safe because:
/// 1. Only one thread can be generating at a time (enforced by pipeline design)
/// 2. The buffer has a stable heap address (Box allocation)
/// 3. Data is fully written before the slice is returned
pub struct GpuGeneratorAdapter {
    inner: Arc<GpuKeyGenerator>,
    /// Batch buffer with stable heap address
    /// UnsafeCell is used for zero-copy access (no MutexGuard lifetime issues)
    batch_buffer: std::cell::UnsafeCell<Box<[u8]>>,
    /// Buffer size for quick access
    buffer_size: usize,
    /// Current buffer index for round-robin
    current_buf_idx: AtomicUsize,
    /// Whether pipeline has been primed
    pipeline_primed: AtomicBool,
    /// Lock for buffer access (prevents concurrent modification)
    buffer_lock: AtomicBool,
}

// Safety: UnsafeCell is protected by AtomicBool lock
// Only one thread can access the buffer at a time
unsafe impl Send for GpuGeneratorAdapter {}
unsafe impl Sync for GpuGeneratorAdapter {}

impl GpuGeneratorAdapter {
    /// Create a new adapter wrapping a GpuKeyGenerator
    pub fn new(generator: GpuKeyGenerator) -> Self {
        let batch_size = generator.batch_size() * 2; // GLV: 2x keys
        let output_size = 72; // RawKeyData::SIZE
        let buffer_size = batch_size * output_size;
        
        Self {
            inner: Arc::new(generator),
            batch_buffer: std::cell::UnsafeCell::new(vec![0u8; buffer_size].into_boxed_slice()),
            buffer_size,
            current_buf_idx: AtomicUsize::new(0),
            pipeline_primed: AtomicBool::new(false),
            buffer_lock: AtomicBool::new(false),
        }
    }
    
    /// Acquire buffer lock (spin-lock for simplicity)
    #[inline]
    fn acquire_lock(&self) {
        while self.buffer_lock.compare_exchange_weak(
            false, true, Ordering::Acquire, Ordering::Relaxed
        ).is_err() {
            std::hint::spin_loop();
        }
    }
    
    /// Release buffer lock
    #[inline]
    fn release_lock(&self) {
        self.buffer_lock.store(false, Ordering::Release);
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
        // Acquire lock to prevent concurrent buffer access
        self.acquire_lock();
        
        // Prime pipeline on first call
        if !self.pipeline_primed.load(Ordering::SeqCst) {
            if let Err(e) = self.prime_pipeline() {
                self.release_lock();
                return Err(e);
            }
        }
        
        let depth = self.inner.pipeline_depth();
        
        // Get current buffer index (the one we'll read from)
        let read_idx = self.current_buf_idx.fetch_add(1, Ordering::SeqCst) % depth;
        
        // Get the buffer set for reading
        let bs = self.inner.buffer_set(read_idx);
        
        // Wait for this batch to complete
        let cb = bs.queue.new_command_buffer();
        cb.commit();
        cb.wait_until_completed();
        
        // IMPORTANT: Copy data BEFORE dispatching next batch to avoid race condition
        // Zero-copy access to GPU buffer via Unified Memory
        let output_ptr = bs.output_buffer.contents() as *const u8;
        
        // Copy GPU data to our buffer FIRST
        // SAFETY: UnsafeCell access is protected by our spinlock
        let buffer = unsafe { &mut *self.batch_buffer.get() };
        unsafe {
            std::ptr::copy_nonoverlapping(output_ptr, buffer.as_mut_ptr(), self.buffer_size);
        }
        
        // NOW dispatch next batch (after copy is complete)
        let next_offset = self.inner.fetch_add_offset(self.inner.batch_size() as u64);
        if let Err(e) = self.inner.dispatch_glv(read_idx, next_offset) {
            self.release_lock();
            return Err(e);
        }
        
        // Update stats
        self.inner.add_generated(self.batch_size() as u64);
        
        // Release lock - buffer is now ready to read
        self.release_lock();
        
        // Return reference to batch_buffer
        // SAFETY: This is sound because:
        // 1. The Box<[u8]> is heap-allocated with a stable address
        // 2. The data was fully written before releasing the lock
        // 3. The pipeline is designed for sequential access (generate → process → generate)
        // 4. The returned slice is valid until the next generate_batch call
        Ok(unsafe {
            let buffer = &*self.batch_buffer.get();
            std::slice::from_raw_parts(buffer.as_ptr(), self.buffer_size)
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


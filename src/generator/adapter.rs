//! Generator Adapter - Implements Bridge Traits
//!
//! This module provides the bridge between GpuKeyGenerator and the
//! KeyGenerator trait, allowing clean integration with the pipeline.

use std::sync::Arc;
use std::cell::UnsafeCell;

use crate::bridge::KeyGenerator;
use super::GpuKeyGenerator;

/// Adapter that wraps GpuKeyGenerator and implements KeyGenerator trait
pub struct GpuGeneratorAdapter {
    inner: Arc<GpuKeyGenerator>,
    /// Current batch buffer (for zero-copy access)
    current_batch: UnsafeCell<Vec<u8>>,
    /// Current buffer index for round-robin
    current_buf_idx: UnsafeCell<usize>,
}

// Safety: We handle synchronization manually through the inner GpuKeyGenerator
unsafe impl Send for GpuGeneratorAdapter {}
unsafe impl Sync for GpuGeneratorAdapter {}

impl GpuGeneratorAdapter {
    /// Create a new adapter wrapping a GpuKeyGenerator
    pub fn new(generator: GpuKeyGenerator) -> Self {
        let batch_size = generator.batch_size() * 2; // GLV: 2x keys
        let output_size = 72; // RawKeyData::SIZE
        
        Self {
            inner: Arc::new(generator),
            current_batch: UnsafeCell::new(vec![0u8; batch_size * output_size]),
            current_buf_idx: UnsafeCell::new(0),
        }
    }
    
    /// Get inner generator (for direct access if needed)
    pub fn inner(&self) -> &GpuKeyGenerator {
        &self.inner
    }
}

impl KeyGenerator for GpuGeneratorAdapter {
    fn batch_size(&self) -> usize {
        // GLV: 2x keys per EC operation
        self.inner.batch_size() * 2
    }
    
    fn generate_batch(&self) -> Result<&[u8], String> {
        
        let depth = self.inner.pipeline_depth();
        
        // Get current buffer index (round-robin)
        let buf_idx = unsafe {
            let idx = &mut *self.current_buf_idx.get();
            let current = *idx;
            *idx = (current + 1) % depth;
            current
        };
        
        // Dispatch next batch with GLV
        let offset = self.inner.fetch_add_offset(self.inner.batch_size() as u64);
        self.inner.dispatch_glv(buf_idx, offset)?;
        
        // Wait for completion and get data
        let bs = self.inner.buffer_set(buf_idx);
        
        // Wait for GPU
        let cb = bs.queue.new_command_buffer();
        cb.commit();
        cb.wait_until_completed();
        
        // Zero-copy access to GPU buffer
        let output_ptr = bs.output_buffer.contents() as *const u8;
        let output_size = self.batch_size() * 72;
        
        // Copy to our buffer (required for lifetime safety)
        let batch = unsafe { &mut *self.current_batch.get() };
        unsafe {
            std::ptr::copy_nonoverlapping(output_ptr, batch.as_mut_ptr(), output_size);
        }
        
        // Update stats
        self.inner.add_generated(self.batch_size() as u64);
        
        Ok(batch)
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


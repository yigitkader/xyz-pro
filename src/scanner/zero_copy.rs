// src/scanner/zero_copy.rs
// Zero-Copy Architecture: Eliminate CPU-GPU memory copies
// Uses unified memory with atomic pointers for lock-free operation

use metal::{Buffer, MTLResourceOptions};
use std::sync::atomic::{AtomicU32, Ordering};

/// Zero-copy match buffer manager
/// 
/// Uses unified memory (MTLStorageModeShared) with atomic operations
/// to eliminate explicit memory copies between GPU and CPU.
/// 
/// Architecture:
/// - GPU writes matches directly to shared memory
/// - CPU reads directly from same memory location
/// - Atomic counters ensure thread-safe access
/// - No explicit synchronization needed (unified memory handles it)
pub struct ZeroCopyMatchBuffer {
    /// Match data buffer (shared between GPU and CPU)
    data_buf: Buffer,
    /// Atomic match count (GPU writes, CPU reads)
    count_buf: Buffer,
    /// Maximum matches (buffer size / match size)
    max_matches: u32,
    /// Match size in bytes (52 bytes: 4 key_index + 1 type + 20 hash + 27 padding)
    match_size: u32,
}

impl ZeroCopyMatchBuffer {
    /// Create new zero-copy match buffer
    pub fn new(device: &metal::Device, max_matches: u32) -> Self {
        let match_size = 52u32; // Must match GPU kernel match format
        let data_size = (max_matches as u64) * (match_size as u64);
        
        // Use shared storage mode for zero-copy
        let storage = MTLResourceOptions::StorageModeShared;
        
        let data_buf = device.new_buffer(data_size, storage);
        let count_buf = device.new_buffer(4, storage); // u32
        
        // Initialize count to zero
        unsafe {
            let ptr = count_buf.contents() as *mut u32;
            *ptr = 0;
        }
        
        Self {
            data_buf,
            count_buf,
            max_matches,
            match_size,
        }
    }
    
    /// Get match data buffer (for GPU)
    pub fn data_buffer(&self) -> &Buffer {
        &self.data_buf
    }
    
    /// Get match count buffer (for GPU)
    pub fn count_buffer(&self) -> &Buffer {
        &self.count_buf
    }
    
    /// Read matches directly from shared memory (zero-copy)
    /// Returns (count, matches)
    /// 
    /// This is the key optimization: CPU reads directly from GPU's memory
    /// without any explicit copy operation.
    pub fn read_matches(&self) -> (u32, Vec<MatchEntry>) {
        // Read atomic count
        let count = unsafe {
            let ptr = self.count_buf.contents() as *const AtomicU32;
            (*ptr).load(Ordering::Acquire)
        };
        
        // Clamp to max_matches (safety check)
        let count = count.min(self.max_matches);
        
        if count == 0 {
            return (0, Vec::new());
        }
        
        // Read matches directly from shared memory
        let mut matches = Vec::with_capacity(count as usize);
        unsafe {
            let data_ptr = self.data_buf.contents() as *const u8;
            
            for i in 0..count {
                let offset = (i as u64) * (self.match_size as u64);
                let entry_ptr = data_ptr.add(offset as usize);
                
                // Parse match entry (52 bytes)
                let key_index = u32::from_le_bytes([
                    *entry_ptr,
                    *entry_ptr.add(1),
                    *entry_ptr.add(2),
                    *entry_ptr.add(3),
                ]);
                
                let match_type = *entry_ptr.add(4);
                let hash = {
                    let mut h = [0u8; 20];
                    std::ptr::copy_nonoverlapping(
                        entry_ptr.add(32),
                        h.as_mut_ptr(),
                        20,
                    );
                    h
                };
                
                matches.push(MatchEntry {
                    key_index,
                    match_type,
                    hash,
                });
            }
        }
        
        (count, matches)
    }
    
    /// Reset match count (for next batch)
    /// Note: GPU will overwrite, but we reset for safety
    pub fn reset(&self) {
        unsafe {
            let ptr = self.count_buf.contents() as *mut AtomicU32;
            (*ptr).store(0, Ordering::Release);
        }
    }
    
    /// Get buffer size in bytes
    pub fn size_bytes(&self) -> u64 {
        (self.max_matches as u64) * (self.match_size as u64)
    }
    
    /// Get max matches (for testing)
    pub fn max_matches(&self) -> u32 {
        self.max_matches
    }
    
    /// Get match size (for testing)
    pub fn match_size(&self) -> u32 {
        self.match_size
    }
}

/// Match entry structure (matches GPU format)
#[derive(Clone, Debug)]
pub struct MatchEntry {
    pub key_index: u32,
    pub match_type: u8,
    pub hash: [u8; 20],
}

impl MatchEntry {
    /// Convert to PotentialMatch (for compatibility with existing code)
    pub fn to_potential_match(&self) -> crate::gpu::PotentialMatch {
        use crate::gpu::{MatchType, PotentialMatch};
        use crate::types::Hash160;
        
        let match_type = match self.match_type {
            0 => MatchType::Compressed,
            1 => MatchType::Uncompressed,
            2 => MatchType::P2SH,
            3 => MatchType::GlvCompressed,
            4 => MatchType::GlvUncompressed,
            5 => MatchType::GlvP2SH,
            _ => MatchType::Compressed, // Default fallback
        };
        
        PotentialMatch {
            key_index: self.key_index,
            match_type,
            hash: Hash160::from_slice(&self.hash),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_zero_copy_buffer_creation() {
        let device = match metal::Device::system_default() {
            Some(d) => d,
            None => {
                // Skip test if no Metal GPU available
                println!("Skipping test: No Metal GPU available");
                return;
            }
        };
        let buffer = ZeroCopyMatchBuffer::new(&device, 1000);
        
        assert_eq!(buffer.max_matches(), 1000);
        assert_eq!(buffer.match_size(), 52);
        assert_eq!(buffer.size_bytes(), 52000);
    }
    
    #[test]
    fn test_match_entry_conversion() {
        let entry = MatchEntry {
            key_index: 12345,
            match_type: 0,
            hash: [0xAB; 20],
        };
        
        let potential = entry.to_potential_match();
        assert_eq!(potential.key_index, 12345);
    }
}


//! Shared Data Types for Bridge
//!
//! These types are the contract between Generator and Reader.
//! Neither module should depend on the other's implementation details.
//!
//! ## Zero-Copy Support
//! When `zero-copy` feature is enabled, provides direct GPU buffer access
//! without any memory copies. The `KeyBatch` struct provides a lifetime-safe
//! view into unified memory.

/// Raw key data - the minimal unit of data exchanged
/// Layout: [privkey: 32 bytes][pubkey_hash: 20 bytes][p2sh_hash: 20 bytes]
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct RawKeyData {
    /// Private key (32 bytes, big-endian)
    pub private_key: [u8; 32],
    /// RIPEMD160(SHA256(compressed_pubkey)) - used for P2PKH and P2WPKH
    pub pubkey_hash: [u8; 20],
    /// RIPEMD160(SHA256(0x0014 || pubkey_hash)) - used for P2SH-P2WPKH
    pub p2sh_hash: [u8; 20],
}

impl RawKeyData {
    /// Size of RawKeyData in bytes
    pub const SIZE: usize = 72;
    
    /// Create from raw bytes - zero-copy where possible
    /// 
    /// # Safety
    /// Uses unaligned read since data from GPU buffer may not be aligned.
    /// This is safe because RawKeyData is #[repr(C, packed)].
    #[inline(always)]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        
        // SAFETY: RawKeyData is #[repr(C, packed)] so it can be read from any alignment.
        // The data pointer points to at least SIZE bytes (checked above).
        Some(unsafe {
            std::ptr::read_unaligned(data.as_ptr() as *const Self)
        })
    }
    
    /// Create from raw bytes with bounds check elided (caller guarantees size)
    /// 
    /// # Safety
    /// Caller must ensure `data.len() >= SIZE` (72 bytes).
    /// Violating this precondition is undefined behavior.
    /// 
    /// # Optimization
    /// The bounds check is elided in release builds via `unreachable_unchecked`,
    /// allowing the optimizer to remove redundant checks when the caller
    /// already validated the buffer size.
    #[inline(always)]
    pub unsafe fn from_bytes_unchecked(data: &[u8]) -> Self {
        debug_assert!(
            data.len() >= Self::SIZE,
            "from_bytes_unchecked: buffer too small ({} < {})",
            data.len(),
            Self::SIZE
        );
        
        // SAFETY: Caller guarantees data.len() >= SIZE.
        // This hint allows the optimizer to elide bounds checks in release builds
        // when the caller has already validated the buffer size.
        if data.len() < Self::SIZE {
            std::hint::unreachable_unchecked();
        }
        
        std::ptr::read_unaligned(data.as_ptr() as *const Self)
    }
    
    /// Check if this key data is valid (non-zero private key)
    /// Uses SIMD-friendly pattern for faster checking
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        // Check 8 bytes at a time for faster zero-detection
        let ptr = self.private_key.as_ptr() as *const u64;
        unsafe {
            // Read 4 u64s (32 bytes) and OR them together
            let v0 = std::ptr::read_unaligned(ptr);
            let v1 = std::ptr::read_unaligned(ptr.add(1));
            let v2 = std::ptr::read_unaligned(ptr.add(2));
            let v3 = std::ptr::read_unaligned(ptr.add(3));
            (v0 | v1 | v2 | v3) != 0
        }
    }
    
    /// Get private key as hex string
    pub fn private_key_hex(&self) -> String {
        hex::encode(&self.private_key)
    }
}

/// A batch of raw key data - zero-copy view into GPU buffer
pub struct KeyBatch<'a> {
    /// Raw byte slice from GPU buffer (Unified Memory)
    data: &'a [u8],
    /// Number of keys in this batch
    count: usize,
}

impl<'a> KeyBatch<'a> {
    /// Create a new key batch from raw bytes
    pub fn new(data: &'a [u8]) -> Self {
        let count = data.len() / RawKeyData::SIZE;
        Self { data, count }
    }
    
    /// ZERO-COPY: Create batch from raw pointer and length
    /// This is the core zero-copy primitive - no data is copied.
    /// 
    /// # Safety
    /// - `ptr` must be valid for reads of `len` bytes
    /// - `ptr` must be aligned to at least 1 byte
    /// - The memory must remain valid for lifetime `'a`
    /// - The memory must not be mutated for lifetime `'a`
    #[cfg(feature = "zero-copy")]
    #[inline]
    pub unsafe fn from_raw_parts(ptr: *const u8, len: usize) -> Self {
        let data = std::slice::from_raw_parts(ptr, len);
        Self::new(data)
    }
    
    /// Number of keys in this batch
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }
    
    /// Is the batch empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    
    /// Get key at index (copies the key data)
    #[inline]
    pub fn get(&self, index: usize) -> Option<RawKeyData> {
        if index >= self.count {
            return None;
        }
        let offset = index * RawKeyData::SIZE;
        RawKeyData::from_bytes(&self.data[offset..offset + RawKeyData::SIZE])
    }
    
    /// ZERO-COPY: Get raw slice reference at index (no copy)
    /// Returns the raw bytes for a single key entry
    #[cfg(feature = "zero-copy")]
    #[inline]
    pub fn get_raw(&self, index: usize) -> Option<&'a [u8]> {
        if index >= self.count {
            return None;
        }
        let offset = index * RawKeyData::SIZE;
        Some(&self.data[offset..offset + RawKeyData::SIZE])
    }
    
    /// ZERO-COPY: Get pubkey_hash slice directly (no copy)
    /// Returns bytes [32..52] of the entry
    #[cfg(feature = "zero-copy")]
    #[inline]
    pub fn get_pubkey_hash(&self, index: usize) -> Option<&'a [u8; 20]> {
        if index >= self.count {
            return None;
        }
        let offset = index * RawKeyData::SIZE + 32;
        self.data[offset..offset + 20].try_into().ok()
    }
    
    /// ZERO-COPY: Get p2sh_hash slice directly (no copy)
    /// Returns bytes [52..72] of the entry
    #[cfg(feature = "zero-copy")]
    #[inline]
    pub fn get_p2sh_hash(&self, index: usize) -> Option<&'a [u8; 20]> {
        if index >= self.count {
            return None;
        }
        let offset = index * RawKeyData::SIZE + 52;
        self.data[offset..offset + 20].try_into().ok()
    }
    
    /// Iterate over all keys
    pub fn iter(&self) -> KeyBatchIter<'a> {
        KeyBatchIter {
            data: self.data,
            index: 0,
            count: self.count,
        }
    }
    
    /// Get raw bytes for parallel processing
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
    
    /// Split into chunks for parallel processing
    pub fn chunks(&self, chunk_size: usize) -> impl Iterator<Item = KeyBatch<'a>> {
        self.data
            .chunks(chunk_size * RawKeyData::SIZE)
            .map(|chunk| KeyBatch::new(chunk))
    }
    
    /// ZERO-COPY: Get parallel iterator over raw key slices
    /// Each slice is exactly 72 bytes (one key entry)
    #[cfg(feature = "zero-copy")]
    pub fn par_raw_iter(&self) -> impl rayon::iter::ParallelIterator<Item = &'a [u8]> + 'a {
        use rayon::prelude::*;
        self.data.par_chunks_exact(RawKeyData::SIZE)
    }
}

/// Iterator over KeyBatch
pub struct KeyBatchIter<'a> {
    data: &'a [u8],
    index: usize,
    count: usize,
}

impl<'a> Iterator for KeyBatchIter<'a> {
    type Item = RawKeyData;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        let offset = self.index * RawKeyData::SIZE;
        self.index += 1;
        RawKeyData::from_bytes(&self.data[offset..offset + RawKeyData::SIZE])
    }
    
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.count - self.index;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for KeyBatchIter<'a> {}

/// GPU Error types based on Metal MTLCommandBufferError codes
/// These provide more reliable error classification than string matching
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum GpuErrorCode {
    /// No error
    None = 0,
    /// Internal error (MTLCommandBufferErrorInternal = 1)
    Internal = 1,
    /// Timeout (MTLCommandBufferErrorTimeout = 2)
    Timeout = 2,
    /// Page fault - GPU memory access error (MTLCommandBufferErrorPageFault = 3)
    PageFault = 3,
    /// Access revoked / blacklisted (MTLCommandBufferErrorAccessRevoked = 4)
    AccessRevoked = 4,
    /// Not permitted (MTLCommandBufferErrorNotPermitted = 7)
    NotPermitted = 7,
    /// Out of memory (MTLCommandBufferErrorOutOfMemory = 8)
    OutOfMemory = 8,
    /// Invalid resource (MTLCommandBufferErrorInvalidResource = 9)
    InvalidResource = 9,
    /// Memoryless texture error (MTLCommandBufferErrorMemoryless = 10)
    Memoryless = 10,
    /// Device reset (MTLCommandBufferErrorDeviceReset = 11)
    DeviceReset = 11,
    /// Stack overflow (MTLCommandBufferErrorStackOverflow = 12)
    StackOverflow = 12,
    /// Unknown error code
    Unknown = 999,
}

impl GpuErrorCode {
    /// Convert from Metal error code integer
    pub fn from_code(code: u64) -> Self {
        match code {
            0 => Self::None,
            1 => Self::Internal,
            2 => Self::Timeout,
            3 => Self::PageFault,
            4 => Self::AccessRevoked,
            7 => Self::NotPermitted,
            8 => Self::OutOfMemory,
            9 => Self::InvalidResource,
            10 => Self::Memoryless,
            11 => Self::DeviceReset,
            12 => Self::StackOverflow,
            _ => Self::Unknown,
        }
    }
    
    /// Check if this error is fatal (non-recoverable)
    /// Fatal errors indicate hardware/driver issues that won't resolve with retries
    #[inline]
    pub fn is_fatal(&self) -> bool {
        match self {
            // These are always fatal - hardware/driver level failures
            Self::Internal => true,
            Self::PageFault => true,
            Self::AccessRevoked => true,
            Self::NotPermitted => true,
            Self::OutOfMemory => true,
            Self::InvalidResource => true,
            Self::Memoryless => true,
            Self::DeviceReset => true,
            Self::StackOverflow => true,
            // These might be recoverable
            Self::None => false,
            Self::Timeout => false, // Could be transient load
            Self::Unknown => false, // Be conservative with unknown
        }
    }
    
    /// Check if this error might be recoverable with retry
    #[inline]
    pub fn is_retriable(&self) -> bool {
        match self {
            Self::None => true,
            Self::Timeout => true, // Might succeed on retry
            Self::Unknown => true, // Give it a chance
            _ => false,
        }
    }
}

impl std::fmt::Display for GpuErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Internal => write!(f, "Internal GPU Error"),
            Self::Timeout => write!(f, "GPU Timeout"),
            Self::PageFault => write!(f, "GPU Page Fault"),
            Self::AccessRevoked => write!(f, "GPU Access Revoked"),
            Self::NotPermitted => write!(f, "GPU Operation Not Permitted"),
            Self::OutOfMemory => write!(f, "GPU Out of Memory"),
            Self::InvalidResource => write!(f, "Invalid GPU Resource"),
            Self::Memoryless => write!(f, "Memoryless Texture Error"),
            Self::DeviceReset => write!(f, "GPU Device Reset"),
            Self::StackOverflow => write!(f, "GPU Stack Overflow"),
            Self::Unknown => write!(f, "Unknown GPU Error"),
        }
    }
}

/// GPU Error with both code and message
#[derive(Debug, Clone)]
pub struct GpuError {
    /// Error code from Metal API
    pub code: GpuErrorCode,
    /// Human-readable error message
    pub message: String,
}

impl GpuError {
    pub fn new(code: GpuErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    
    /// Create from error code only
    pub fn from_code(code: u64) -> Self {
        let gpu_code = GpuErrorCode::from_code(code);
        Self {
            code: gpu_code,
            message: gpu_code.to_string(),
        }
    }
    
    /// Check if this error is fatal
    #[inline]
    pub fn is_fatal(&self) -> bool {
        self.code.is_fatal()
    }
    
    /// Check if this error is retriable
    #[inline]
    pub fn is_retriable(&self) -> bool {
        self.code.is_retriable()
    }
}

impl std::fmt::Display for GpuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for GpuError {}

/// Type of address match
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchType {
    /// P2PKH (Legacy) - starts with 1
    P2PKH,
    /// P2SH (Nested SegWit) - starts with 3
    P2SH,
    /// P2WPKH (Native SegWit) - starts with bc1q
    P2WPKH,
}

impl std::fmt::Display for MatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchType::P2PKH => write!(f, "P2PKH"),
            MatchType::P2SH => write!(f, "P2SH"),
            MatchType::P2WPKH => write!(f, "P2WPKH"),
        }
    }
}

/// A match result - when a key matches a target
#[derive(Debug, Clone)]
pub struct Match {
    /// The matching key data
    pub key: RawKeyData,
    /// Which address type matched
    pub match_type: MatchType,
    /// The matched hash (20 bytes)
    pub matched_hash: [u8; 20],
}

impl Match {
    /// Create a new match
    #[inline(always)]
    pub fn new(key: RawKeyData, match_type: MatchType) -> Self {
        let matched_hash = match match_type {
            MatchType::P2PKH | MatchType::P2WPKH => key.pubkey_hash,
            MatchType::P2SH => key.p2sh_hash,
        };
        Self {
            key,
            match_type,
            matched_hash,
        }
    }
    
    /// Format as a readable string
    pub fn to_string_detailed(&self) -> String {
        format!(
            "🎯 FOUND! Key: {} | Type: {} | Hash: {}",
            self.key.private_key_hex(),
            self.match_type,
            hex::encode(&self.matched_hash)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_raw_key_data_size() {
        assert_eq!(RawKeyData::SIZE, 72);
    }
    
    #[test]
    fn test_key_batch_iteration() {
        let mut data = vec![0u8; RawKeyData::SIZE * 3];
        // Set first byte of each key to make them different
        data[0] = 1;
        data[RawKeyData::SIZE] = 2;
        data[RawKeyData::SIZE * 2] = 3;
        
        let batch = KeyBatch::new(&data);
        assert_eq!(batch.len(), 3);
        
        let keys: Vec<_> = batch.iter().collect();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].private_key[0], 1);
        assert_eq!(keys[1].private_key[0], 2);
        assert_eq!(keys[2].private_key[0], 3);
    }
}


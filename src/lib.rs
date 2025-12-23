// src/lib.rs
// Library interface for testing and external use

pub mod address;
pub mod crypto;
pub mod error;
pub mod gpu;
pub mod startup_tests;
pub mod targets;
pub mod types;

#[cfg(feature = "philox-rng")]
pub mod rng;

#[cfg(feature = "xor-filter")]
pub mod filter;

#[cfg(feature = "simd-math")]
pub mod math;

#[cfg(feature = "pid-thermal")]
pub mod thermal;

// scanner module removed - dead code, ZeroCopyMatchBuffer was never used externally
// gpu.rs handles all match buffer operations directly

// Re-export commonly used types
pub use error::{Result, ScannerError};
pub use types::{AddressType, Hash160};


// src/lib.rs
// Library interface for testing and external use

pub mod address;
pub mod crypto;
pub mod error;
pub mod gpu;
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

#[cfg(feature = "zero-copy")]
pub mod scanner;

// Re-export commonly used types
pub use error::{Result, ScannerError};
pub use types::{AddressType, Hash160};


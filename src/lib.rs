//! xyz-pro: High-Performance Bitcoin Key Generator & Scanner
//!
//! Independent modules:
//! - `generator`: GPU-accelerated key generation (btc_keygen binary)
//! - `reader`: Fast address matching against targets (btc_reader binary)

pub mod generator;
pub mod reader;


//! xyz-pro: High-Performance Bitcoin Key Generator & Scanner
//!
//! Clean Architecture:
//! - `generator`: GPU-accelerated key generation (independent)
//! - `reader`: Fast address matching against targets (independent)
//! - `bridge`: Clean interface connecting generator and reader
//!
//! The bridge module defines traits and types that allow generator
//! and reader to work together without direct dependencies.

pub mod generator;
pub mod reader;
pub mod bridge;
pub mod cli;


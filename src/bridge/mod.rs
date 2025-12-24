//! Bridge Module - Clean Interface Between Generator and Reader
//!
//! This module provides:
//! 1. Shared data types (RawKeyData, KeyBatch)
//! 2. Trait definitions (KeyGenerator, Matcher)
//! 3. Pipeline orchestrator (IntegratedPipeline)
//!
//! Architecture:
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         BRIDGE                                   │
//! │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
//! │  │   RawKeyData │    │  KeyBatch    │    │  Match       │       │
//! │  │  (32+20+20)  │    │  (slice)     │    │  (hit info)  │       │
//! │  └──────────────┘    └──────────────┘    └──────────────┘       │
//! └─────────────────────────────────────────────────────────────────┘
//!            ▲                   ▲                   │
//!            │                   │                   ▼
//! ┌──────────┴──────────┐ ┌──────┴──────────┐ ┌─────────────────────┐
//! │     GENERATOR       │ │     MATCHER     │ │      OUTPUT         │
//! │  ┌───────────────┐  │ │ ┌─────────────┐ │ │  ┌───────────────┐  │
//! │  │ impl KeyGen   │  │ │ │ impl Match  │ │ │  │ impl Output   │  │
//! │  │               │──┼─┼─│             │─┼─┼──│               │  │
//! │  │ - GPU/CPU     │  │ │ │ - HashSet   │ │ │  │ - File        │  │
//! │  └───────────────┘  │ │ └─────────────┘ │ │  └───────────────┘  │
//! └─────────────────────┘ └─────────────────┘ └─────────────────────┘
//! ```
//!
//! Usage:
//! ```no_run
//! use xyz_pro::bridge::{IntegratedPipeline, ConsoleOutput};
//! use xyz_pro::generator::{GpuKeyGenerator, GpuGeneratorAdapter, GeneratorConfig};
//! use xyz_pro::reader::ParallelMatcher;
//! 
//! fn main() -> Result<(), String> {
//!     let config = GeneratorConfig::default();
//!     let gpu = GpuKeyGenerator::new(config)?;
//!     let generator = GpuGeneratorAdapter::new(gpu);
//!     let matcher = ParallelMatcher::load("targets.json")?;
//!     let output = ConsoleOutput::new();
//!     
//!     let pipeline = IntegratedPipeline::new(generator, matcher, output);
//!     pipeline.run()?;
//!     Ok(())
//! }
//! ```

mod types;
mod traits;
mod pipeline;

pub use types::{RawKeyData, KeyBatch, Match, MatchType, GpuError, GpuErrorCode};
pub use traits::{KeyGenerator, Matcher, MatchOutput, MatcherStats, ConsoleOutput, FileOutput, CombinedOutput};
pub use pipeline::{IntegratedPipeline, PipelineConfig, PipelineStats};


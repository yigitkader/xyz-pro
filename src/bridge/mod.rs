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
//! ```ignore
//! let pipeline = IntegratedPipeline::new(generator, matcher, output);
//! pipeline.run()?;
//! ```

mod types;
mod traits;
mod pipeline;

pub use types::{RawKeyData, KeyBatch, Match, MatchType};
pub use traits::{KeyGenerator, Matcher, MatchOutput, MatcherStats, ConsoleOutput, FileOutput, CombinedOutput};
pub use pipeline::{IntegratedPipeline, PipelineConfig, PipelineStats};


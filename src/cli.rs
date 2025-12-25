//! Common CLI argument parsing for all binaries
//! 
//! Provides standardized argument parsing using clap to ensure consistency
//! across btc_keygen and btc_reader binaries.

use clap::{Parser, ValueEnum};

/// Common arguments shared by all binaries
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct CommonArgs {
    /// Number of threads (default: auto-detect)
    #[arg(short = 't', long = "threads", value_name = "N")]
    pub threads: Option<usize>,
    
    /// Print help information
    #[arg(short = 'h', long = "help")]
    pub help: bool,
}

/// Output format options
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliOutputFormat {
    Json,
    Binary,
    Both,
    Compact,
    Raw,
}

impl From<CliOutputFormat> for crate::generator::OutputFormat {
    fn from(fmt: CliOutputFormat) -> Self {
        match fmt {
            CliOutputFormat::Json => crate::generator::OutputFormat::Json,
            CliOutputFormat::Binary => crate::generator::OutputFormat::Binary,
            CliOutputFormat::Both => crate::generator::OutputFormat::Both,
            CliOutputFormat::Compact => crate::generator::OutputFormat::Compact,
            CliOutputFormat::Raw => crate::generator::OutputFormat::Raw,
        }
    }
}

/// GLV mode options
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliGlvMode {
    Off,
    #[value(name = "2x")]
    Glv2x,
    #[value(name = "3x")]
    Glv3x,
}

impl From<CliGlvMode> for crate::generator::GlvMode {
    fn from(mode: CliGlvMode) -> Self {
        match mode {
            CliGlvMode::Off => crate::generator::GlvMode::Disabled,
            CliGlvMode::Glv2x => crate::generator::GlvMode::Glv2x,
            CliGlvMode::Glv3x => crate::generator::GlvMode::Glv3x,
        }
    }
}

/// Parse u64 from string (supports hex with 0x prefix)
pub fn parse_u64(value: &str) -> Result<u64, String> {
    if value.starts_with("0x") || value.starts_with("0X") {
        u64::from_str_radix(&value[2..], 16)
            .map_err(|e| format!("Invalid hex value '{}': {}", value, e))
    } else {
        value.parse::<u64>()
            .map_err(|e| format!("Invalid decimal value '{}': {}", value, e))
    }
}

/// Format number with thousands separator
pub fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }
    
    result
}


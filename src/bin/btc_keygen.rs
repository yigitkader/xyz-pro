//! Standalone BTC Key Generator Binary
//! 
//! Usage: btc_keygen [OPTIONS]
//! 
//! Options:
//!   --output DIR       Output directory (default: ./btc_keys)
//!   --format FORMAT    Output format: json, binary, both (default: json)
//!   --batch SIZE       Batch size for parallel processing (default: 100000)
//!   --keys-per-file N  Keys per file (default: 1000000000)
//!   --target N         Stop after generating N keys (default: infinite)
//!   --threads N        Number of threads (default: auto)
//!   --seed N           Random seed for reproducibility

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use clap::{Parser, Subcommand};

// Generator module
use xyz_pro::generator::{BatchProcessor, GeneratorConfig, GlvMode, GpuKeyGenerator, GpuGeneratorAdapter, OutputFormat};

// Reader module  
use xyz_pro::reader::ParallelMatcher;

// Bridge module - clean interface between generator and reader
use xyz_pro::bridge::{IntegratedPipeline, PipelineConfig, CombinedOutput};

// CLI module
use xyz_pro::cli::{CliOutputFormat, CliGlvMode, parse_u64, format_number};

#[derive(Parser, Debug)]
#[command(name = "btc_keygen", about = "BTC Private Key Scanner & Generator", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
    
    // Common arguments (used in both modes)
    /// Number of threads (default: auto-detect)
    #[arg(short = 't', long = "threads")]
    threads: Option<usize>,
    
    /// Output directory (generator mode) or matches file (scan mode)
    #[arg(short = 'o', long = "output")]
    output: Option<String>,
    
    /// Output format: json, binary, compact, raw, both
    #[arg(short = 'f', long = "format", value_enum)]
    format: Option<CliOutputFormat>,
    
    /// Batch size for parallel processing
    #[arg(short = 'b', long = "batch")]
    batch: Option<usize>,
    
    /// Keys per file
    #[arg(short = 'k', long = "keys-per-file")]
    keys_per_file: Option<u64>,
    
    /// GLV mode: off, 2x, 3x
    #[arg(short = 'G', long = "glv", value_enum)]
    glv: Option<CliGlvMode>,
    
    /// Starting private key offset (hex: 0x... or decimal)
    #[arg(long = "start-offset")]
    start_offset: Option<String>,
    
    /// End offset for range limiting (hex: 0x... or decimal)
    #[arg(long = "end")]
    end: Option<String>,
    
    /// Random seed (CPU mode only)
    #[arg(short = 's', long = "seed")]
    seed: Option<u64>,
    
    /// Use GPU acceleration (Metal)
    #[arg(short = 'g', long = "gpu")]
    gpu: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generator mode: Generate keys and write to disk
    Generate {
        /// Stop after generating N keys
        #[arg(short = 'n', long = "target")]
        target: Option<u64>,
    },
    /// Scan mode: Generate & Match via Bridge (DEFAULT)
    Scan {
        /// Path to targets.json file
        #[arg(short = 'T', long = "targets", default_value = "targets.json")]
        targets: String,
        /// Start key (hex: 0x... or decimal)
        #[arg(long = "start")]
        start: Option<String>,
    },
}

fn main() {
    let args = Args::parse();
    
    // Determine mode
    match args.command {
        Some(Commands::Generate { target }) => {
            run_generator_mode(&args, target);
        }
        Some(Commands::Scan { targets, start }) => {
            run_scan_mode(&args, targets, start);
        }
        None => {
            // DEFAULT: Scan mode
            run_scan_mode(&args, "targets.json".to_string(), None);
        }
    }
}

fn run_generator_mode(args: &Args, target: Option<u64>) {
    let mut config = GeneratorConfig::default();
    
    // Apply arguments to config
    if let Some(threads) = args.threads {
        config.threads = threads;
    }
    if let Some(ref output) = args.output {
        config.output_dir = output.clone();
    }
    if let Some(ref format) = args.format {
        config.output_format = (*format).into();
    }
    if let Some(batch) = args.batch {
        config.batch_size = batch;
    }
    if let Some(keys_per_file) = args.keys_per_file {
        config.keys_per_file = keys_per_file;
    }
    if let Some(ref glv) = args.glv {
        config.glv_mode = (*glv).into();
    }
    if let Some(ref start_offset_str) = args.start_offset {
        match parse_u64(start_offset_str) {
            Ok(n) if n > 0 => config.start_offset = n,
            Ok(_) => {
                eprintln!("❌ --start-offset must be greater than 0");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("❌ Invalid start-offset: {}", e);
                std::process::exit(1);
            }
        }
    }
    if let Some(ref end_str) = args.end {
        match parse_u64(end_str) {
            Ok(n) => config.end_offset = Some(n),
            Err(e) => {
                eprintln!("❌ Invalid end offset: {}", e);
                std::process::exit(1);
            }
        }
    }
    
    if let Err(e) = config.validate() {
        eprintln!("❌ Invalid configuration: {}", e);
        std::process::exit(1);
    }
    
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║           🔑 BTC Key Generator (Disk Mode)                 ║");
    println!("║                                                            ║");
    println!("║   Generates keys → writes to disk                          ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    
    if args.gpu {
        run_gpu_mode(config, target);
    } else {
        run_cpu_mode(config, target, args.seed);
    }
}

/// NASA-grade: Integrated Pipeline Mode
/// 
/// Clean Architecture using Bridge Pattern:
/// - Generator: Produces keys (GPU-accelerated)
/// - Matcher: Checks against targets (HashSet O(1))
/// - Output: Handles matches (file + console)
/// - Pipeline: Orchestrates everything
fn run_scan_mode(args: &Args, targets_path: String, start: Option<String>) {
    let mut config = GeneratorConfig::default();
    
    // Apply common arguments
    if let Some(threads) = args.threads {
        config.threads = threads;
    }
    if let Some(batch) = args.batch {
        config.batch_size = batch;
    }
    if let Some(ref glv) = args.glv {
        config.glv_mode = (*glv).into();
    }
    
    // Scan-mode specific: start offset
    if let Some(ref start_str) = start {
        match parse_u64(start_str) {
            Ok(n) if n > 0 => config.start_offset = n,
            Ok(_) => {
                eprintln!("❌ --start must be greater than 0");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("❌ Invalid start offset: {}", e);
                std::process::exit(1);
            }
        }
    }
    if let Some(ref end_str) = args.end {
        match parse_u64(end_str) {
            Ok(n) => config.end_offset = Some(n),
            Err(e) => {
                eprintln!("❌ Invalid end offset: {}", e);
                std::process::exit(1);
            }
        }
    }
    
    // In scan mode, --output is the matches file, NOT output directory
    let output_file = args.output.as_deref().unwrap_or("matches.txt");
    config.output_dir = String::new(); // Not used in scan mode
    
    // Scan mode always uses Raw format (no disk I/O until match)
    config.output_format = OutputFormat::Raw;
    
    // Validate configuration
    if let Err(e) = config.validate() {
        eprintln!("❌ Invalid configuration: {}", e);
        std::process::exit(1);
    }
    
    // ========================================================================
    // 1. READER MODULE: Load targets
    // ========================================================================
    println!("📂 Loading targets from: {}", targets_path);
    
    let matcher = match ParallelMatcher::load(&targets_path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("❌ Failed to load targets: {}", e);
            std::process::exit(1);
        }
    };
    
    let gpu_gen = match GpuKeyGenerator::new(config) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("❌ Failed to initialize GPU: {}", e);
            std::process::exit(1);
        }
    };
    
    // Wrap in adapter for bridge compatibility
    let generator = GpuGeneratorAdapter::new(gpu_gen);
    
    // ========================================================================
    // 3. BRIDGE MODULE: Create pipeline
    // ========================================================================
    let output = match CombinedOutput::new(&output_file) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("❌ Failed to create output: {}", e);
            std::process::exit(1);
        }
    };
    
    let pipeline_config = PipelineConfig {
        report_interval_secs: 2,
        parallel_matching: true,
        parallel_chunk_size: 10_000,
        ..Default::default()  // Use defaults for retry settings
    };
    
    let pipeline = Arc::new(IntegratedPipeline::with_config(
        generator,
        matcher,
        output,
        pipeline_config,
    ));
    
    // Ctrl+C handler
    let pipeline_clone = pipeline.clone();
    ctrlc::set_handler(move || {
        println!("\n\n⚠️  Received Ctrl+C, stopping...");
        pipeline_clone.stop();
    }).expect("Error setting Ctrl+C handler");
    
    // ========================================================================
    // 4. RUN PIPELINE
    // ========================================================================
    match pipeline.run() {
        Ok(stats) => {
            println!();
            println!("╔════════════════════════════════════════════════════════════╗");
            println!("║                    📊 Scan Results                         ║");
            println!("╠════════════════════════════════════════════════════════════╣");
            println!("║  Keys scanned:         {:>35} ║", format_number(stats.keys_scanned));
            println!("║  Hits found:           {:>35} ║", stats.matches_found);
            println!("║  Time elapsed:         {:>32.2} sec ║", stats.elapsed_secs);
            println!("║  Keys per second:      {:>32.2} M ║", stats.keys_per_second() / 1_000_000.0);
            println!("║  Keys per minute:      {:>32.2} M ║", stats.keys_per_minute() / 1_000_000.0);
            println!("╚════════════════════════════════════════════════════════════╝");
            
            if stats.matches_found > 0 {
                println!();
                println!("🎯 Matches saved to: {}", output_file);
            }
        }
        Err(e) => {
            eprintln!("❌ Pipeline error: {}", e);
            std::process::exit(1);
        }
    }
}


fn run_gpu_mode(config: GeneratorConfig, target: Option<u64>) {
    println!("🎮 GPU Mode (Metal Accelerated)");
    println!();
    
    let generator = match GpuKeyGenerator::new(config) {
        Ok(g) => Arc::new(g),
        Err(e) => {
            eprintln!("❌ Failed to initialize GPU: {}", e);
            std::process::exit(1);
        }
    };
    
    let generator_clone = generator.clone();
    ctrlc::set_handler(move || {
        println!("\n\n⚠️  Received Ctrl+C, stopping gracefully...");
        generator_clone.stop();
    }).expect("Error setting Ctrl+C handler");
    
    match generator.run(target) {
        Ok(stats) => print_stats(stats),
        Err(e) => {
            eprintln!("❌ Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn run_cpu_mode(config: GeneratorConfig, target: Option<u64>, seed: Option<u64>) {
    println!("💻 CPU Mode (Parallel Processing)");
    println!();
    
    // config is moved into BatchProcessor - no clone needed
    let processor = if let Some(s) = seed {
        println!("🌱 Using seed: {}", s);
        Arc::new(BatchProcessor::with_seed(config, s))
    } else {
        Arc::new(BatchProcessor::new(config))
    };
    
    let processor_clone = processor.clone();
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();
    
    ctrlc::set_handler(move || {
        println!("\n\n⚠️  Received Ctrl+C, stopping gracefully...");
        processor_clone.stop();
        running_clone.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");
    
    match processor.run(target) {
        Ok(stats) => print_stats(stats),
        Err(e) => {
            eprintln!("❌ Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn print_stats(stats: xyz_pro::generator::GeneratorStats) {
    println!();
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║                    📊 Final Statistics                     ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!("║  Total keys generated: {:>35} ║", format_number(stats.total_generated));
    println!("║  Duplicates skipped:   {:>35} ║", format_number(stats.duplicates_skipped));
    println!("║  Files written:        {:>35} ║", stats.files_written);
    println!("║  Time elapsed:         {:>32.2} sec ║", stats.elapsed_secs);
    println!("║  Keys per second:      {:>32.2} M ║", stats.keys_per_second() / 1_000_000.0);
    println!("║  Keys per minute:      {:>32.2} M ║", stats.keys_per_minute() / 1_000_000.0);
    println!("╚════════════════════════════════════════════════════════════╝");
}




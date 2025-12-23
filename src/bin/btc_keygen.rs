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

// Generator module
use xyz_pro::generator::{BatchProcessor, GeneratorConfig, GpuKeyGenerator, GpuGeneratorAdapter, OutputFormat};

// Reader module  
use xyz_pro::reader::ParallelMatcher;

// Bridge module - clean interface between generator and reader
use xyz_pro::bridge::{IntegratedPipeline, PipelineConfig, CombinedOutput};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    // Check for scan mode first
    if args.iter().any(|a| a == "--scan") {
        run_scan_mode(&args);
        return;
    }
    
    let config = parse_args(&args);
    let target = parse_target(&args);
    let use_gpu = parse_gpu_flag(&args);
    
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║           🔑 BTC Private Key Generator v1.0                ║");
    println!("║                                                            ║");
    println!("║   Generates keys with P2PKH, P2SH, and P2WPKH addresses   ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    
    if use_gpu {
        run_gpu_mode(config, target);
    } else {
        run_cpu_mode(config, target, &args);
    }
}

/// NASA-grade: Integrated Pipeline Mode
/// 
/// Clean Architecture using Bridge Pattern:
/// - Generator: Produces keys (GPU-accelerated)
/// - Matcher: Checks against targets (HashSet O(1))
/// - Output: Handles matches (file + console)
/// - Pipeline: Orchestrates everything
fn run_scan_mode(args: &[String]) {
    // Parse arguments
    let targets_path = parse_string_arg(args, "--targets").unwrap_or("targets.json".to_string());
    let start_offset = parse_u64_arg(args, "--start").unwrap_or(1);
    let output_file = parse_string_arg(args, "--output").unwrap_or("matches.txt".to_string());
    
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
    
    // ========================================================================
    // 2. GENERATOR MODULE: Initialize GPU
    // ========================================================================
    let config = GeneratorConfig {
        start_offset,
        output_format: OutputFormat::Raw,
        ..Default::default()
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

fn parse_string_arg(args: &[String], name: &str) -> Option<String> {
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == name {
            return Some(args[i + 1].clone());
        }
    }
    None
}

fn parse_u64_arg(args: &[String], name: &str) -> Option<u64> {
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == name {
            // Support hex (0x...) and decimal
            let val = &args[i + 1];
            if val.starts_with("0x") || val.starts_with("0X") {
                return u64::from_str_radix(&val[2..], 16).ok();
            } else {
                return val.parse().ok();
            }
        }
    }
    None
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

fn run_cpu_mode(config: GeneratorConfig, target: Option<u64>, args: &[String]) {
    println!("💻 CPU Mode (Parallel Processing)");
    println!();
    
    let seed = parse_seed(args);
    let processor = if let Some(s) = seed {
        println!("🌱 Using seed: {}", s);
        Arc::new(BatchProcessor::with_seed(config.clone(), s))
    } else {
        Arc::new(BatchProcessor::new(config.clone()))
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

fn parse_args(args: &[String]) -> GeneratorConfig {
    let mut config = GeneratorConfig::default();
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    config.output_dir = args[i + 1].clone();
                    i += 1;
                }
            }
            "--format" | "-f" => {
                if i + 1 < args.len() {
                    config.output_format = match args[i + 1].to_lowercase().as_str() {
                        "binary" | "bin" => OutputFormat::Binary,
                        "both" => OutputFormat::Both,
                        "compact" | "cbin" => OutputFormat::Compact,
                        "raw" => OutputFormat::Raw,
                        _ => OutputFormat::Json,
                    };
                    i += 1;
                }
            }
            "--batch" | "-b" => {
                if i + 1 < args.len() {
                    if let Ok(n) = args[i + 1].parse() {
                        config.batch_size = n;
                    }
                    i += 1;
                }
            }
            "--keys-per-file" | "-k" => {
                if i + 1 < args.len() {
                    if let Ok(n) = args[i + 1].parse() {
                        config.keys_per_file = n;
                    }
                    i += 1;
                }
            }
            "--threads" | "-t" => {
                if i + 1 < args.len() {
                    if let Ok(n) = args[i + 1].parse() {
                        config.threads = n;
                    }
                    i += 1;
                }
            }
            "--start-offset" => {
                if i + 1 < args.len() {
                    if let Ok(n) = args[i + 1].parse() {
                        config.start_offset = n;
                    }
                    i += 1;
                }
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    
    config
}

fn parse_target(args: &[String]) -> Option<u64> {
    for i in 0..args.len() - 1 {
        if args[i] == "--target" || args[i] == "-n" {
            return args[i + 1].parse().ok();
        }
    }
    None
}

fn parse_seed(args: &[String]) -> Option<u64> {
    for i in 0..args.len() - 1 {
        if args[i] == "--seed" || args[i] == "-s" {
            return args[i + 1].parse().ok();
        }
    }
    None
}

fn parse_gpu_flag(args: &[String]) -> bool {
    args.iter().any(|a| a == "--gpu" || a == "-g")
}

fn print_help() {
    println!("BTC Private Key Generator & Scanner");
    println!();
    println!("USAGE:");
    println!("    btc_keygen [OPTIONS]");
    println!();
    println!("MODES:");
    println!("    Generator mode (default): Generate keys and write to disk");
    println!("    Scanner mode (--scan):    Generate & Match in GPU, zero I/O until hit");
    println!();
    println!("GENERATOR OPTIONS:");
    println!("    -g, --gpu                Use GPU acceleration (Metal)");
    println!("    -o, --output DIR         Output directory (default: ./output)");
    println!("    -f, --format FORMAT      Output format: json, binary, compact, raw, both");
    println!("    -b, --batch SIZE         Batch size (default: 100000)");
    println!("    -k, --keys-per-file N    Keys per file (default: 1000000000)");
    println!("    -n, --target N           Stop after N keys");
    println!("    --start-offset N         Starting private key offset");
    println!();
    println!("SCANNER OPTIONS (--scan):");
    println!("    --scan                   Enable Generate & Match mode");
    println!("    --targets FILE           Path to targets.json (default: targets.json)");
    println!("    --start N                Start key (hex: 0x... or decimal)");
    println!("    --end N                  End key (optional)");
    println!();
    println!("OTHER:");
    println!("    -t, --threads N          Number of threads (default: auto)");
    println!("    -s, --seed N             Random seed (CPU only)");
    println!("    -h, --help               Print this help");
    println!();
    println!("EXAMPLES:");
    println!("    # Generate mode");
    println!("    btc_keygen --gpu --format raw --target 100000000");
    println!();
    println!("    # Scanner mode - NASA-grade");
    println!("    btc_keygen --scan --targets targets.json --start 0x1");
}

fn format_number(n: u64) -> String {
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


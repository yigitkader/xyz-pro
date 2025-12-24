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
    
    // Check for help
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }
    
    // Check for generator-only mode (writes to disk)
    if args.iter().any(|a| a == "--generate" || a == "--gen") {
        run_generator_mode(&args);
        return;
    }
    
    // DEFAULT: Integrated Pipeline (Scan Mode)
    // Bridge connects Generator + Reader
    // Zero disk I/O until match found
    run_scan_mode(&args);
}

fn run_generator_mode(args: &[String]) {
    let config = parse_args(args);
    let target = parse_target(args);
    let use_gpu = parse_gpu_flag(args);
    
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║           🔑 BTC Key Generator (Disk Mode)                 ║");
    println!("║                                                            ║");
    println!("║   Generates keys → writes to disk                          ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    
    if use_gpu {
        run_gpu_mode(config, target);
    } else {
        run_cpu_mode(config, target, args);
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
    // Parse ALL arguments using centralized parser
    // This ensures --batch, --threads, --format etc. are not ignored
    let mut config = parse_args(args);
    
    // Scan-mode specific arguments:
    // --targets / -T : Path to targets JSON file (note: -T uppercase, -t is for --threads)
    // --output / -o  : Path to matches output file (overrides config.output_dir in scan mode)
    let targets_path = parse_string_arg(args, "--targets").unwrap_or_else(|| "targets.json".to_string());
    
    // In scan mode, --output is the matches file, NOT output directory
    // If user specified --output, use it; otherwise default to "matches.txt"
    let output_file = parse_string_arg(args, "--output").unwrap_or_else(|| "matches.txt".to_string());
    // Clear output_dir since it's not used in scan mode (prevents confusion)
    config.output_dir = String::new();
    
    // Scan-mode specific overrides from command line
    if let Some(start) = parse_u64_arg(args, "--start") {
        config.start_offset = start;
    }
    if let Some(end) = parse_u64_arg(args, "--end") {
        config.end_offset = Some(end);
    }
    
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

/// Parse string argument with support for short flags
/// Maps common short flags to their long equivalents:
/// - `-o` → `--output`
/// - `-t` → `--targets` (in scan mode)
fn parse_string_arg(args: &[String], name: &str) -> Option<String> {
    // Define short flag mappings
    // NOTE: -t is reserved for --threads, so --targets uses -T (uppercase)
    let short_flag = match name {
        "--output" => Some("-o"),
        "--targets" => Some("-T"),  // Uppercase T to avoid conflict with -t (threads)
        "--input" => Some("-i"),
        "--format" => Some("-f"),
        _ => None,
    };
    
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == name || short_flag.map(|s| args[i] == s).unwrap_or(false) {
            return Some(args[i + 1].clone());
        }
    }
    None
}

/// Parse u64 argument with explicit error handling
/// Returns None if flag not found, exits with error if value is invalid
fn parse_u64_arg(args: &[String], name: &str) -> Option<u64> {
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == name {
            let val = &args[i + 1];
            
            // Support hex (0x...) and decimal
            let result = if val.starts_with("0x") || val.starts_with("0X") {
                u64::from_str_radix(&val[2..], 16)
            } else {
                val.parse()
            };
            
            match result {
                Ok(n) => return Some(n),
                Err(e) => {
                    eprintln!("❌ Invalid value for {}: '{}' - {}", name, val, e);
                    eprintln!("   Expected: decimal (123456) or hex (0x1E240)");
                    std::process::exit(1);
                }
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

fn parse_args(args: &[String]) -> GeneratorConfig {
    let mut config = GeneratorConfig::default();
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    config.output_dir = args[i + 1].clone();
                    i += 1;
                } else {
                    eprintln!("❌ --output requires a directory path");
                    std::process::exit(1);
                }
            }
            "--format" | "-f" => {
                if i + 1 < args.len() {
                    let format_str = args[i + 1].to_lowercase();
                    config.output_format = match format_str.as_str() {
                        "binary" | "bin" => OutputFormat::Binary,
                        "both" => OutputFormat::Both,
                        "compact" | "cbin" => OutputFormat::Compact,
                        "raw" => OutputFormat::Raw,
                        "json" => OutputFormat::Json,
                        _ => {
                            eprintln!("❌ Invalid format '{}'. Valid options: json, binary, compact, raw, both", format_str);
                            std::process::exit(1);
                        }
                    };
                    i += 1;
                } else {
                    eprintln!("❌ --format requires a value (json, binary, compact, raw, both)");
                    std::process::exit(1);
                }
            }
            "--batch" | "-b" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse::<usize>() {
                        Ok(n) if n > 0 => config.batch_size = n,
                        Ok(_) => {
                            eprintln!("❌ --batch must be greater than 0");
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("❌ Invalid batch size '{}': {}", args[i + 1], e);
                            std::process::exit(1);
                        }
                    }
                    i += 1;
                } else {
                    eprintln!("❌ --batch requires a number");
                    std::process::exit(1);
                }
            }
            "--keys-per-file" | "-k" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse::<u64>() {
                        Ok(n) if n > 0 => config.keys_per_file = n,
                        Ok(_) => {
                            eprintln!("❌ --keys-per-file must be greater than 0");
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("❌ Invalid keys-per-file value '{}': {}", args[i + 1], e);
                            std::process::exit(1);
                        }
                    }
                    i += 1;
                } else {
                    eprintln!("❌ --keys-per-file requires a number");
                    std::process::exit(1);
                }
            }
            "--threads" | "-t" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse::<usize>() {
                        Ok(n) => config.threads = n,
                        Err(e) => {
                            eprintln!("❌ Invalid thread count '{}': {}", args[i + 1], e);
                            std::process::exit(1);
                        }
                    }
                    i += 1;
                } else {
                    eprintln!("❌ --threads requires a number");
                    std::process::exit(1);
                }
            }
            "--start-offset" => {
                if i + 1 < args.len() {
                    let val = &args[i + 1];
                    let result = if val.starts_with("0x") || val.starts_with("0X") {
                        u64::from_str_radix(&val[2..], 16)
                    } else {
                        val.parse()
                    };
                    match result {
                        Ok(n) if n > 0 => config.start_offset = n,
                        Ok(_) => {
                            eprintln!("❌ --start-offset must be greater than 0 (0 is invalid private key)");
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("❌ Invalid start-offset '{}': {}", val, e);
                            eprintln!("   Expected: decimal (123456) or hex (0x1E240)");
                            std::process::exit(1);
                        }
                    }
                    i += 1;
                } else {
                    eprintln!("❌ --start-offset requires a number");
                    std::process::exit(1);
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
    // Use saturating_sub to prevent panic when args is empty or has 1 element
    for i in 0..args.len().saturating_sub(1) {
        if args[i] == "--target" || args[i] == "-n" {
            return args[i + 1].parse().ok();
        }
    }
    None
}

fn parse_seed(args: &[String]) -> Option<u64> {
    // Use saturating_sub to prevent panic when args is empty or has 1 element
    for i in 0..args.len().saturating_sub(1) {
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
    println!("BTC Private Key Scanner & Generator");
    println!();
    println!("USAGE:");
    println!("    btc_keygen [OPTIONS]");
    println!();
    println!("MODES:");
    println!("    Scanner mode (DEFAULT):   Generate & Match via Bridge, zero I/O until hit");
    println!("    Generator mode (--gen):   Generate keys and write to disk");
    println!();
    println!("SCANNER OPTIONS (DEFAULT MODE):");
    println!("    --targets FILE           Path to targets.json (default: targets.json)");
    println!("    --start N                Start key (hex: 0x... or decimal, default: 1)");
    println!("    --output FILE            Output file for matches (default: matches.txt)");
    println!();
    println!("GENERATOR OPTIONS (--gen or --generate):");
    println!("    --gen, --generate        Switch to generator mode (disk I/O)");
    println!("    -g, --gpu                Use GPU acceleration (Metal)");
    println!("    -o, --output DIR         Output directory (default: ./output)");
    println!("    -f, --format FORMAT      Output format: json, binary, compact, raw, both");
    println!("    -b, --batch SIZE         Batch size (default: 100000)");
    println!("    -k, --keys-per-file N    Keys per file (default: 1000000000)");
    println!("    -n, --target N           Stop after N keys");
    println!("    --start-offset N         Starting private key offset");
    println!();
    println!("OTHER:");
    println!("    -t, --threads N          Number of threads (default: auto)");
    println!("    -s, --seed N             Random seed (CPU only)");
    println!("    -h, --help               Print this help");
    println!();
    println!("EXAMPLES:");
    println!("    # Scanner mode (default) - NASA-grade Bridge architecture");
    println!("    btc_keygen --targets targets.json --start 0x1");
    println!();
    println!("    # Generator mode - writes to disk");
    println!("    btc_keygen --gen --gpu --format raw --target 100000000");
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


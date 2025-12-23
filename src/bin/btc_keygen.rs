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

use xyz_pro::generator::{BatchProcessor, GeneratorConfig, GpuKeyGenerator, OutputFormat};

fn main() {
    let args: Vec<String> = std::env::args().collect();
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
    println!("BTC Private Key Generator");
    println!();
    println!("USAGE:");
    println!("    btc_keygen [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    -g, --gpu                Use GPU acceleration (Metal)");
    println!("    -o, --output DIR         Output directory (default: ./output)");
    println!("    -f, --format FORMAT      Output format: json, binary, compact, raw, both (default: json)");
    println!("                             raw = NASA-grade: direct GPU buffer dump, max throughput");
    println!("    -b, --batch SIZE         Batch size for parallel processing (default: 100000)");
    println!("    -k, --keys-per-file N    Keys per file (default: 1000000000)");
    println!("    -n, --target N           Stop after generating N keys (default: infinite)");
    println!("    -t, --threads N          Number of threads (default: auto)");
    println!("    -s, --seed N             Random seed for reproducibility (CPU only)");
    println!("    --start-offset N         Starting private key offset (GPU only)");
    println!("    -h, --help               Print this help message");
    println!();
    println!("EXAMPLES:");
    println!("    btc_keygen --gpu --target 1000000 --output ./my_keys");
    println!("    btc_keygen --format binary --batch 500000");
    println!("    btc_keygen --seed 12345 --target 100");
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


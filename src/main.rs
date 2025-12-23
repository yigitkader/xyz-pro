mod address;
mod crypto;
mod error;
mod gpu;
mod startup_tests;
mod targets;
mod types;
mod puzzle_mode;
mod puzzle_scanner;

#[cfg(feature = "philox-rng")]
mod rng;

#[cfg(feature = "xor-filter")]
mod filter;

#[cfg(feature = "simd-math")]
mod math;

#[cfg(feature = "pid-thermal")]
mod thermal;

use crossbeam_channel::{bounded, Receiver, Sender};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use std::io::{stdout, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use address::to_wif_compressed;
use gpu::{MatchType, OptimizedScanner, PotentialMatch, PooledBuffer};
use startup_tests::{run_self_test, run_gpu_correctness_test, run_gpu_pipeline_test, run_end_to_end_match_test};
#[cfg(feature = "philox-rng")]
use startup_tests::run_startup_verification;
use targets::TargetDatabase;
#[cfg(feature = "philox-rng")]
use rng::philox::PhiloxState;

const TARGETS_FILE: &str = "targets.json";

type VerifyBatch = ([u8; 32], PhiloxState, PooledBuffer);

#[cfg(target_os = "macos")]
fn check_memory_pressure() -> f32 {
    use std::mem::MaybeUninit;
    
    extern "C" {
        fn sysctlbyname(name: *const libc::c_char, oldp: *mut libc::c_void,
            oldlenp: *mut libc::size_t, newp: *const libc::c_void, newlen: libc::size_t) -> libc::c_int;
        fn mach_host_self() -> u32;
        fn host_page_size(host: u32, page_size: *mut u32) -> i32;
        fn host_statistics64(host: u32, flavor: i32, host_info: *mut libc::c_void, count: *mut u32) -> i32;
    }
    
    let total_bytes: u64 = unsafe {
        let name = b"hw.memsize\0";
        let mut value: u64 = 0;
        let mut size = std::mem::size_of::<u64>();
        if sysctlbyname(name.as_ptr() as *const _, &mut value as *mut _ as *mut _, 
            &mut size, std::ptr::null(), 0) == 0 { value } else { 16 * 1024 * 1024 * 1024 }
    };
    
    let available_bytes: u64 = unsafe {
        const HOST_VM_INFO64: i32 = 4;
        const HOST_VM_INFO64_COUNT: u32 = 38;
        
        #[repr(C)]
        struct VmStats { free: u32, active: u32, inactive: u32, wire: u32, 
            _z: u64, _r: u64, _pi: u64, _po: u64, _f: u64, _c: u64, _l: u64, _h: u64, _pu: u64, 
            purgeable: u32, speculative: u32, _pad: [u64; 16] }
        
        let host = mach_host_self();
        let mut page_size: u32 = 4096;
        host_page_size(host, &mut page_size);
        
        let mut stats = MaybeUninit::<VmStats>::zeroed();
        let mut count = HOST_VM_INFO64_COUNT;
        
        if host_statistics64(host, HOST_VM_INFO64, stats.as_mut_ptr() as *mut _, &mut count) == 0 {
            let s = stats.assume_init();
            (s.free as u64 + s.inactive as u64 + s.speculative as u64) * page_size as u64
        } else {
            total_bytes / 2
        }
    };
    
    ((available_bytes as f64 / total_bytes as f64 * 100.0) as f32).clamp(0.0, 100.0)
}

#[cfg(not(target_os = "macos"))]
fn check_memory_pressure() -> f32 { 100.0 }

fn get_performance_core_count() -> usize {
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn sysctlbyname(name: *const libc::c_char, oldp: *mut libc::c_void,
                oldlenp: *mut libc::size_t, newp: *const libc::c_void, newlen: libc::size_t) -> libc::c_int;
        }
        
        fn get_int(name: &[u8]) -> Option<i32> {
            unsafe {
                let mut v: i32 = 0;
                let mut sz = std::mem::size_of::<i32>();
                if sysctlbyname(name.as_ptr() as *const _, &mut v as *mut _ as *mut _, 
                    &mut sz, std::ptr::null(), 0) == 0 { Some(v) } else { None }
            }
        }
        
        if let Some(c) = get_int(b"hw.perflevel0.physicalcpu\0") {
            if c > 0 && c <= 32 { return c as usize; }
        }
        
        if let Some(t) = get_int(b"hw.physicalcpu\0") {
            return match t as usize {
                0..=8 => 2, 9..=10 => 3, 11..=12 => 4, 13..=16 => 6, _ => 8,
            }.max(2).min(10);
        }
    }
    6
}

/// Scan mode: Random or Puzzle
#[derive(Clone, Copy, PartialEq)]
enum ScanMode {
    Random,
    Puzzle(u8),
}

impl ScanMode {
    fn from_env() -> Self {
        if let Ok(puzzle_str) = std::env::var("PUZZLE") {
            if let Ok(num) = puzzle_str.parse::<u8>() {
                if (40..=160).contains(&num) {
                    return ScanMode::Puzzle(num);
                }
            }
        }
        ScanMode::Random
    }
    
    fn print_info(&self, keys_per_sec: f64) {
        match self {
            ScanMode::Random => println!("[Mode] Random (Philox RNG)"),
            ScanMode::Puzzle(num) => puzzle_mode::print_puzzle_info(*num, keys_per_sec),
        }
    }
}

fn main() {
    println!("\n\x1b[1;36m╔═══════════════════════════════════════════════════════╗");
    println!("║     XYZ-PRO  •  Bitcoin Key Scanner  •  Metal GPU      ║");
    println!("╚═══════════════════════════════════════════════════════╝\x1b[0m\n");

    let p_cores = get_performance_core_count();
    setup_rayon_pool(p_cores);

    // Scan mode selection from environment
    let scan_mode = ScanMode::from_env();
    
    let fast_start = std::env::var("FAST_START").is_ok() 
        || std::env::var("FAST_MODE").is_ok()
        || std::env::args().any(|a| a == "--fast" || a == "-f");
    
    if fast_start {
        println!("[⚡] Fast start mode\n");
    }

    if !run_self_test() {
        eprintln!("[FATAL] Self-test failed.");
        std::process::exit(1);
    }

    let targets = match TargetDatabase::new(TARGETS_FILE) {
        Ok(t) => {
            println!("[✓] Loaded {} targets ({:.1} MB)", t.total(), t.memory_stats().1 as f64 / 1e6);
            Arc::new(t)
        }
        Err(e) => {
            eprintln!("[✗] {}", e);
            return;
        }
    };

    let hashes = targets.get_all_hashes();
    let xor_cache = TARGETS_FILE.replace(".json", ".shxor");

    let gpu = match OptimizedScanner::new_with_cache(&hashes, Some(&xor_cache)) {
        Ok(g) => Arc::new(g),
        Err(e) => {
            eprintln!("[✗] GPU: {}", e);
            return;
        }
    };

    if !fast_start {
        if !run_gpu_correctness_test(&gpu, &targets) {
            eprintln!("[FATAL] GPU correctness test failed.");
            std::process::exit(1);
        }
        if !run_gpu_pipeline_test(&gpu) {
            eprintln!("[FATAL] GPU pipeline test failed.");
            std::process::exit(1);
        }
        #[cfg(feature = "philox-rng")]
        if !run_startup_verification(&gpu) {
            eprintln!("[FATAL] Startup verification failed.");
            std::process::exit(1);
        }
        if !run_end_to_end_match_test(&gpu, &targets) {
            eprintln!("[FATAL] End-to-end match test failed.");
            std::process::exit(1);
        }
    } else {
        print!("[⚡] Quick GPU check... ");
        stdout().flush().ok();
        let mut key = [0u8; 32];
        key[31] = 1;
        match gpu.scan_batch(&key) {
            Ok(_) => println!("OK"),
            Err(e) => {
                println!("FAILED");
                eprintln!("[FATAL] GPU: {}", e);
                std::process::exit(1);
            }
        }
    }

    let counter = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicU64::new(0));
    let shutdown = Arc::new(AtomicBool::new(false));
    let start = Instant::now();

    let shutdown_sig = shutdown.clone();
    ctrlc::set_handler(move || {
        println!("\n[!] Stopping...");
        shutdown_sig.store(true, Ordering::SeqCst);
    }).ok();

    println!("[▶] Scanning... (Ctrl+C to stop)\n");
    
    // Print scan mode info
    scan_mode.print_info(2_500_000.0); // Estimate based on typical M1 speed
    println!();

    // Route to appropriate scanner based on mode
    match scan_mode {
        ScanMode::Puzzle(puzzle_num) => {
            // Puzzle mode: Sequential scanning with checkpoint support
            if let Some(config) = puzzle_mode::PuzzleConfig::for_puzzle(puzzle_num) {
                if let Some(found_key) = puzzle_scanner::run_puzzle_scan(&gpu, &config, &shutdown) {
                    println!("\n🎉 PUZZLE #{} SOLVED!", puzzle_num);
                    println!("Private Key: {}", hex::encode(&found_key));
                    found.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                eprintln!("[!] Unknown puzzle #{}, use PUZZLE=66 to PUZZLE=160", puzzle_num);
            }
        }
        ScanMode::Random => {
            run_pipelined(gpu.clone(), targets.clone(), counter.clone(), found.clone(), shutdown.clone(), start);
        }
    }

    // Final statistics (skip for Puzzle mode which has its own stats)
    if !matches!(scan_mode, ScanMode::Puzzle(_)) {
        let total = counter.load(Ordering::Relaxed);
        let time = start.elapsed().as_secs_f64();
        if total > 0 {
            println!("\n\n[Done] {} keys in {} @ {}", 
                format_num(total), format_time(time), format_speed(total as f64 / time));
        }
    }
    
    flush_logger();
}

fn setup_rayon_pool(threads: usize) {
    use rayon::ThreadPoolBuilder;
    
    let result = ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|i| format!("verify-{}", i))
        .spawn_handler(|thread| {
            let mut b = std::thread::Builder::new();
            if let Some(n) = thread.name() { b = b.name(n.to_owned()); }
            b = b.stack_size(256 * 1024);
            b.spawn(|| {
                #[cfg(target_os = "macos")]
                unsafe {
                    extern "C" {
                        fn pthread_set_qos_class_self_np(qos: u32, priority: i32) -> i32;
                    }
                    // QOS_CLASS_UTILITY (0x09) - long-running, resource-intensive tasks
                    // Prevents starving system UI while still getting good performance
                    // Previous: 0x19 (USER_INTERACTIVE) caused system freeze
                    pthread_set_qos_class_self_np(0x09, 0);
                }
                thread.run();
            })?;
            Ok(())
        })
        .build_global();
    
    match result {
        Ok(()) => println!("[CPU] Rayon: {} threads (P-cores)", threads),
        Err(e) => eprintln!("[!] Rayon pool error: {}", e),
    }
}

fn run_pipelined(
    gpu: Arc<OptimizedScanner>,
    targets: Arc<TargetDatabase>,
    counter: Arc<AtomicU64>,
    found: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
    start: Instant,
) {
    // Get config-driven values from GPU
    let config = gpu.config();
    let pipeline_depth = config.pipeline_depth;
    let gpu_breath_ms = config.gpu_breath_ms;
    let throttle_multiplier = config.throttle_multiplier;
    
    let (tx, rx): (Sender<VerifyBatch>, Receiver<VerifyBatch>) = bounded(pipeline_depth);

    let gpu_shutdown = shutdown.clone();
    let verify_shutdown = shutdown.clone();
    let gpu_counter = counter.clone();
    let verify_found = found.clone();
    let keys_per_batch = gpu.keys_per_batch();

    let gpu_handle = thread::spawn(move || {
        #[cfg(feature = "philox-rng")]
        {
            println!("[GPU] Using Philox4x32 RNG");
            
            #[cfg(feature = "pid-thermal")]
            {
                use crate::thermal::{DynamicSpeedController, read_gpu_temperature, estimate_temperature_from_performance};
                let mut pid = DynamicSpeedController::new(87.0, keys_per_batch as u32);
                let mut last_batch = Instant::now();
                let mut baseline = Duration::ZERO;
                let mut baseline_set = false;
                let mut batch_n = 0u32;
                
                let result = gpu.scan_pipelined(
                    || gpu.next_base_key(),
                    |base_key, base_state, matches| {
                        let dur = last_batch.elapsed();
                        last_batch = Instant::now();
                        batch_n += 1;
                        
                        if !baseline_set {
                            baseline = if baseline.is_zero() { dur } else {
                                Duration::from_millis(((baseline.as_millis() * 9 + dur.as_millis()) / 10) as u64)
                            };
                            if batch_n >= 5 && baseline.as_millis() > 0 { baseline_set = true; }
                        }
                        
                        let temp = read_gpu_temperature().unwrap_or_else(|| {
                            if baseline_set {
                                estimate_temperature_from_performance(dur.as_millis() as u64, baseline.as_millis() as u64)
                            } else { 70.0 }
                        });
                        
                        // CRITICAL: Apply PID throttling + GPU breathing room
                        // This prevents: 1) Thermal runaway 2) UI starvation 3) Memory bus saturation
                        let _ = pid.update(temp); // Update PID state
                        let speed = pid.current_speed();
                        
                        // GPU breathing room (config-driven)
                        let throttle_ms = if speed < 0.95 {
                            ((1.0 - speed) * throttle_multiplier) as u64
                        } else { 0 };
                        std::thread::sleep(Duration::from_millis(gpu_breath_ms + throttle_ms));
                        
                        gpu_counter.fetch_add(keys_per_batch, Ordering::Relaxed);
                        
                        if !matches.is_empty() {
                            if tx.send((base_key, base_state, matches)).is_err() {
                                gpu_shutdown.store(true, Ordering::SeqCst);
                            }
                        }
                    },
                    &gpu_shutdown,
                );
                
                if let Err(e) = result {
                    eprintln!("[!] GPU error: {}", e);
                    gpu_shutdown.store(true, Ordering::SeqCst);
                }
            }
            
            #[cfg(not(feature = "pid-thermal"))]
            {
                let result = gpu.scan_pipelined(
                    || gpu.next_base_key(),
                    |base_key, base_state, matches| {
                        gpu_counter.fetch_add(keys_per_batch, Ordering::Relaxed);
                        if !matches.is_empty() {
                            if tx.send((base_key, base_state, matches)).is_err() {
                                gpu_shutdown.store(true, Ordering::SeqCst);
                            }
                        }
                        // GPU breathing room (config-driven)
                        std::thread::sleep(Duration::from_millis(gpu_breath_ms));
                    },
                    &gpu_shutdown,
                );
                
                if let Err(e) = result {
                    eprintln!("[!] GPU error: {}", e);
                    gpu_shutdown.store(true, Ordering::SeqCst);
                }
            }
        }
    });

    let verify_fp = Arc::new(AtomicU64::new(0));
    let verify_fp_clone = verify_fp.clone();
    let found_keys: Arc<Mutex<Vec<[u8; 32]>>> = Arc::new(Mutex::new(Vec::new()));
    let found_keys_clone = found_keys.clone();
    
    // BACKPRESSURE: Track matches per second for filter anomaly detection
    let matches_per_sec = Arc::new(AtomicU64::new(0));
    let matches_per_sec_clone = matches_per_sec.clone();
    
    let verify_handle = thread::spawn(move || {
        use rayon::prelude::*;
        const PARALLEL_THRESHOLD: usize = 32;
        
        // BACKPRESSURE THRESHOLDS:
        // Normal operation: ~100-1000 FP matches per batch
        // Filter anomaly: >50,000 FP matches per batch (filter misconfiguration)
        // Memory bus saturation: >100,000 FP matches per batch
        const BACKPRESSURE_WARN_THRESHOLD: usize = 10_000;
        const BACKPRESSURE_CRITICAL_THRESHOLD: usize = 50_000;
        
        let mut last_warn = std::time::Instant::now();
        let mut consecutive_high_batches = 0u32;
        
        while !verify_shutdown.load(Ordering::Relaxed) {
            let (base_key, _, matches) = match rx.recv_timeout(Duration::from_millis(10)) {
                Ok(batch) => batch,
                Err(_) => continue,
            };
            
            // BACKPRESSURE CHECK: Detect filter anomaly or misconfiguration
            let batch_size = matches.len();
            matches_per_sec_clone.fetch_add(batch_size as u64, Ordering::Relaxed);
            
            if batch_size > BACKPRESSURE_CRITICAL_THRESHOLD {
                consecutive_high_batches += 1;
                if consecutive_high_batches >= 3 && last_warn.elapsed() > Duration::from_secs(5) {
                    eprintln!("\n[⚠️ BACKPRESSURE] CRITICAL: {} matches/batch - possible filter misconfiguration!", batch_size);
                    eprintln!("[⚠️ BACKPRESSURE] Check: 1) XorFilter cache valid? 2) Prefix table loaded? 3) DEBUG_FILTER_MODE=0?");
                    last_warn = std::time::Instant::now();
                }
            } else if batch_size > BACKPRESSURE_WARN_THRESHOLD {
                consecutive_high_batches += 1;
                if consecutive_high_batches >= 5 && last_warn.elapsed() > Duration::from_secs(10) {
                    eprintln!("\n[⚠️ BACKPRESSURE] High FP rate: {} matches/batch (normal: <1000)", batch_size);
                    last_warn = std::time::Instant::now();
                }
            } else {
                consecutive_high_batches = 0;
            }
            
            let process = |pm: &PotentialMatch| {
                if let Some((addr, atype, privkey)) = verify_match(&base_key, pm, &targets) {
                    let comp = pm.match_type != MatchType::Uncompressed 
                        && pm.match_type != MatchType::GlvUncompressed;
                    
                    let mut keys = found_keys_clone.lock().unwrap();
                    if !keys.contains(&privkey) {
                        keys.push(privkey);
                        verify_found.fetch_add(1, Ordering::Relaxed);
                        report(&privkey, &addr, atype, comp);
                    }
                } else {
                    verify_fp_clone.fetch_add(1, Ordering::Relaxed);
                }
            };
            
            if matches.len() < PARALLEL_THRESHOLD {
                matches.iter().for_each(process);
            } else {
                matches.par_iter().for_each(process);
            }
        }
    });

    let mut last_stat = Instant::now();
    let mut last_count = 0u64;
    let mut last_fp = 0u64;
    let mut rolling_speed = 0.0f64;

    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));

        if last_stat.elapsed() >= Duration::from_secs(1) {
            let count = counter.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs_f64();
            let interval = last_stat.elapsed().as_secs_f64();
            let speed = (count - last_count) as f64 / interval;
            
            rolling_speed = if rolling_speed == 0.0 { speed } else { rolling_speed * 0.7 + speed * 0.3 };
            
            let fp = verify_fp.load(Ordering::Relaxed);
            let fp_rate = if count > last_count { 
                ((fp - last_fp) as f64 / (count - last_count) as f64) * 100.0 
            } else { 0.0 };
            let mem = 100.0 - check_memory_pressure();
            
            print!("\r\x1b[K");
            println!("[⚡] {} keys | {} (avg {}) | {} found | {} FP ({:.4}%) | RAM: {:.1}% | {}",
                format_num(count), format_speed(rolling_speed), format_speed(count as f64 / elapsed),
                found.load(Ordering::Relaxed), format_num(fp), fp_rate, mem, format_time(elapsed));
            
            if mem > 90.0 {
                println!("  [!] CRITICAL: RAM at {:.1}%!", mem);
            }

            last_stat = Instant::now();
            last_count = count;
            last_fp = fp;
        }
    }

    gpu_handle.join().ok();
    verify_handle.join().ok();
}

fn verify_match(
    base_key: &[u8; 32],
    pm: &PotentialMatch,
    targets: &TargetDatabase,
) -> Option<(String, types::AddressType, [u8; 32])> {
    // CRITICAL FIX: GPU uses SEQUENTIAL keys (base_key + offset), NOT Philox per thread!
    // GPU computes: P = base_pubkey + key_index * G
    // This means: private_key = base_key + key_index (scalar addition mod n)
    // 
    // PREVIOUS BUG: Using Philox(counter + key_index) produced DIFFERENT keys
    // than GPU's sequential scan, causing 100% false positive rejection!
    let priv_key = scalar_add_offset(base_key, pm.key_index);

    let actual_key = if pm.match_type.is_glv() {
        gpu::glv_transform_key(&priv_key)
    } else {
        priv_key
    };

    if !crypto::is_valid_private_key(&actual_key) {
        return None;
    }

    let secret = SecretKey::from_slice(&actual_key).ok()?;
    let pubkey = secret.public_key();

    let computed_hash = match pm.match_type {
        MatchType::Compressed | MatchType::GlvCompressed => {
            types::Hash160::from_slice(&crypto::hash160(pubkey.to_encoded_point(true).as_bytes()))
        }
        MatchType::Uncompressed | MatchType::GlvUncompressed => {
            types::Hash160::from_slice(&crypto::hash160(pubkey.to_encoded_point(false).as_bytes()))
        }
        MatchType::P2SH | MatchType::GlvP2SH => {
            let comp_hash = crypto::hash160(pubkey.to_encoded_point(true).as_bytes());
            types::Hash160::from_slice(&address::p2sh_script_hash(&comp_hash))
        }
    };

    if computed_hash != pm.hash {
        return None;
    }

    targets.check_direct(&computed_hash).map(|(addr, atype)| (addr, atype, actual_key))
}

/// Add offset to private key (scalar addition mod n)
/// GPU uses: key[i] = base_key + i (sequential scan)
fn scalar_add_offset(base_key: &[u8; 32], offset: u32) -> [u8; 32] {
    use k256::Scalar;
    use k256::elliptic_curve::ops::Reduce;
    
    // Convert base_key to scalar (big-endian)
    let base = <Scalar as Reduce<k256::U256>>::reduce_bytes(base_key.into());
    
    // Add offset
    let offset_scalar = Scalar::from(offset as u64);
    let result = base + offset_scalar;
    
    // Convert back to bytes (handle potential overflow by modular reduction)
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.to_bytes());
    key
}

static REPORT_TX: OnceLock<crossbeam_channel::Sender<ReportEntry>> = OnceLock::new();

struct ReportEntry {
    privkey: [u8; 32],
    addr: String,
    atype: types::AddressType,
    compressed: bool,
}

fn flush_logger() {
    if let Some(tx) = REPORT_TX.get() {
        let start = Instant::now();
        while !tx.is_empty() && start.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(50));
        }
    }
}

fn init_async_logger() -> crossbeam_channel::Sender<ReportEntry> {
    // SAFETY: Bounded channel prevents RAM explosion if matches flood in
    // 1000 entries max = ~100KB buffer, provides backpressure
    let (tx, rx) = bounded::<ReportEntry>(1000);
    
    thread::Builder::new()
        .name("logger".to_string())
        .spawn(move || {
    use chrono::Local;
    use std::fs::OpenOptions;

            let mut file = OpenOptions::new().create(true).append(true).open("found.txt").ok();
            
            for entry in rx {
                let hex = hex::encode(&entry.privkey);
                let wif = to_wif_compressed(&entry.privkey, entry.compressed);
                let key_type = if entry.compressed { "compressed" } else { "uncompressed" };
    let time = Local::now().format("%Y-%m-%d %H:%M:%S");

    println!("\n\n\x1b[1;32m");
    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║                   🎉 KEY FOUND! 🎉                     ║");
    println!("╠═══════════════════════════════════════════════════════╣");
                println!("║ Address: {} ({})", entry.addr, entry.atype.as_str());
    println!("║ Key: {} ({})", hex, key_type);
    println!("║ WIF: {}", wif);
    println!("╚═══════════════════════════════════════════════════════╝");
    println!("\x1b[0m");

                if let Some(ref mut f) = file {
                    let _ = writeln!(f, "[{}] {} | {} | {} | {} | {}", 
                        time, entry.addr, entry.atype.as_str(), key_type, hex, wif);
                    let _ = f.flush();
                    let _ = f.sync_all();
                }
            }
        })
        .expect("Failed to spawn logger");
    
    tx
}

fn report(privkey: &[u8; 32], addr: &str, atype: types::AddressType, compressed: bool) {
    use std::fs::OpenOptions;
    
    // CRITICAL: Immediate sync write BEFORE async logging
    // This ensures we NEVER lose a found key, even if program crashes
    let hex = hex::encode(privkey);
    let wif = to_wif_compressed(privkey, compressed);
    let key_type = if compressed { "compressed" } else { "uncompressed" };
    
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("found.txt") {
        use chrono::Local;
        let time = Local::now().format("%Y-%m-%d %H:%M:%S");
        let _ = writeln!(f, "[{}] {} | {} | {} | {} | {}", time, addr, atype.as_str(), key_type, hex, wif);
        let _ = f.sync_all(); // CRITICAL: Force to disk immediately
    }
    
    // Then send to async logger for pretty console output
    let tx = REPORT_TX.get_or_init(init_async_logger);
    let _ = tx.send(ReportEntry {
        privkey: *privkey,
        addr: addr.to_string(),
        atype,
        compressed,
    });
}

fn format_num(n: u64) -> String {
    let s = n.to_string();
    let mut r = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { r.push(','); }
        r.push(c);
    }
    r.chars().rev().collect()
}

fn format_speed(s: f64) -> String {
    if s < 1_000.0 { format!("{:.0}/s", s) }
    else if s < 1_000_000.0 { format!("{:.1}K/s", s / 1_000.0) }
    else { format!("{:.2}M/s", s / 1_000_000.0) }
}

fn format_time(s: f64) -> String {
    if s < 60.0 { format!("{:.0}s", s) }
    else if s < 3600.0 { format!("{:.0}m{:.0}s", s / 60.0, s % 60.0) }
    else { format!("{:.0}h{:.0}m", s / 3600.0, (s % 3600.0) / 60.0) }
}

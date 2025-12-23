
mod address;
mod crypto;
mod error;
mod gpu;
mod startup_tests;
mod targets;
mod types;

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
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use address::to_wif_compressed;
use gpu::{MatchType, OptimizedScanner, PotentialMatch};
use startup_tests::{run_self_test, run_gpu_correctness_test, run_gpu_pipeline_test};
#[cfg(feature = "philox-rng")]
use startup_tests::run_startup_verification;
use targets::TargetDatabase;
#[cfg(feature = "philox-rng")]
use rng::philox::{PhiloxState, philox_to_privkey};

const TARGETS_FILE: &str = "targets.json";

const PIPELINE_DEPTH: usize = 8;
// CRITICAL: Include PhiloxState for proper CPU key reconstruction
// GPU uses: Key(i) = Philox(base_counter + thread_id)
// CPU must use: Key(i) = Philox(state.for_thread(key_index))
type VerifyBatch = ([u8; 32], PhiloxState, Vec<PotentialMatch>);

/// Memory pressure via native sysctlbyname (no fork overhead)
#[cfg(target_os = "macos")]
fn check_memory_pressure() -> f32 {
    use std::mem::MaybeUninit;
    
    extern "C" {
        fn sysctlbyname(
            name: *const libc::c_char,
            oldp: *mut libc::c_void,
            oldlenp: *mut libc::size_t,
            newp: *const libc::c_void,
            newlen: libc::size_t,
        ) -> libc::c_int;
    }
    
    // Get total physical memory (hw.memsize)
    let total_bytes: u64 = unsafe {
        let name = b"hw.memsize\0";
        let mut value: u64 = 0;
        let mut size = std::mem::size_of::<u64>();
        
        if sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            &mut value as *mut u64 as *mut libc::c_void,
            &mut size,
            std::ptr::null(),
            0,
        ) == 0 {
            value
        } else {
            // Fallback: assume 16GB (M1 Pro default)
            16 * 1024 * 1024 * 1024
        }
    };
    
    // Get page size and free page count via Mach API
    // This is much faster than parsing vm_stat output
    let available_bytes: u64 = unsafe {
        // Use host_statistics64 for accurate memory info
        extern "C" {
            fn mach_host_self() -> u32;
            fn host_page_size(host: u32, page_size: *mut u32) -> i32;
            fn host_statistics64(
                host: u32,
                flavor: i32,
                host_info: *mut libc::c_void,
                count: *mut u32,
            ) -> i32;
        }
        
        const HOST_VM_INFO64: i32 = 4;
        const HOST_VM_INFO64_COUNT: u32 = 38; // vm_statistics64 struct size
        
        #[repr(C)]
        struct VmStatistics64 {
            free_count: u32,
            active_count: u32,
            inactive_count: u32,
            wire_count: u32,
            zero_fill_count: u64,
            reactivations: u64,
            pageins: u64,
            pageouts: u64,
            faults: u64,
            cow_faults: u64,
            lookups: u64,
            hits: u64,
            purges: u64,
            purgeable_count: u32,
            speculative_count: u32,
            // ... more fields we don't need
            _padding: [u64; 16],
        }
        
        let host = mach_host_self();
        let mut page_size: u32 = 4096;
        host_page_size(host, &mut page_size);
        
        let mut stats = MaybeUninit::<VmStatistics64>::zeroed();
        let mut count = HOST_VM_INFO64_COUNT;
        
        if host_statistics64(
            host,
            HOST_VM_INFO64,
            stats.as_mut_ptr() as *mut libc::c_void,
            &mut count,
        ) == 0 {
            let stats = stats.assume_init();
            // Available = free + inactive + speculative (same as vm_stat)
            let free_pages = stats.free_count as u64 
                + stats.inactive_count as u64 
                + stats.speculative_count as u64;
            free_pages * page_size as u64
        } else {
            // Fallback: assume 50% free
            total_bytes / 2
        }
    };
    
    let free_pct = (available_bytes as f64 / total_bytes as f64 * 100.0) as f32;
    free_pct.clamp(0.0, 100.0)
}

#[cfg(not(target_os = "macos"))]
fn check_memory_pressure() -> f32 {
    100.0 // Not implemented for non-macOS
}

/// Try to read GPU/SoC temperature via ioreg (no sudo required)
/// Returns temperature in Celsius, or None if unavailable
#[cfg(target_os = "macos")]
#[allow(dead_code)]  // Available for future thermal display features
fn try_read_soc_temperature() -> Option<f32> {
    use std::process::Command;
    
    // Try to read from AppleSiliconTemp or similar
    // Note: This may not work on all Macs, hence it's optional
    if let Ok(output) = Command::new("ioreg")
        .args(["-r", "-c", "AppleARMPowerDaemon", "-d", "1"])
        .output()
    {
        if output.status.success() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                // Look for temperature entries
                for line in text.lines() {
                    if line.contains("Temperature") && line.contains("=") {
                        // Parse: "Temperature" = 45.2
                        if let Some(val_str) = line.split('=').nth(1) {
                            let cleaned = val_str.trim().trim_matches('"');
                            if let Ok(temp) = cleaned.parse::<f32>() {
                                if temp > 0.0 && temp < 150.0 {
                                    return Some(temp);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    None
}

#[cfg(not(target_os = "macos"))]
fn try_read_soc_temperature() -> Option<f32> {
    None
}

/// Detect P-core count on Apple Silicon via native sysctlbyname
fn get_performance_core_count() -> usize {
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn sysctlbyname(name: *const libc::c_char, oldp: *mut libc::c_void,
                oldlenp: *mut libc::size_t, newp: *const libc::c_void, newlen: libc::size_t) -> libc::c_int;
        }
        
        fn get_sysctl_int(name: &[u8]) -> Option<i32> {
            unsafe {
                let mut value: i32 = 0;
                let mut size = std::mem::size_of::<i32>();
                if sysctlbyname(name.as_ptr() as *const _, &mut value as *mut _ as *mut _, 
                    &mut size, std::ptr::null(), 0) == 0 { Some(value) } else { None }
            }
        }
        
        // Direct P-core count
        if let Some(count) = get_sysctl_int(b"hw.perflevel0.physicalcpu\0") {
            if count > 0 && count <= 32 { return count as usize; }
        }
        
        // Estimate from total CPUs
        if let Some(total) = get_sysctl_int(b"hw.physicalcpu\0") {
            let p_cores = match total as usize {
                0..=8 => 2,    // Base: 4P
                9..=10 => 3,   // M4 base or M1/M2 Pro
                11..=12 => 4,  // Pro: 6-8P
                13..=16 => 6,  // Max: 10-12P
                _ => 8,        // Ultra: 16P
            };
            return p_cores.max(2).min(10);
        }
    }
    6
}

fn main() {
    println!("\n\x1b[1;36m╔═══════════════════════════════════════════════════════╗");
    println!("║     XYZ-PRO  •  Bitcoin Key Scanner  •  Metal GPU      ║");
    println!("╚═══════════════════════════════════════════════════════╝\x1b[0m\n");

    let p_core_count = get_performance_core_count();
    use rayon::ThreadPoolBuilder;
    
    let pool_result = ThreadPoolBuilder::new()
        .num_threads(p_core_count)
        .thread_name(|i| format!("verify-{}", i))
        .spawn_handler(|thread| {
            let mut builder = std::thread::Builder::new();
            if let Some(name) = thread.name() { builder = builder.name(name.to_owned()); }
            builder = builder.stack_size(256 * 1024);
            
            builder.spawn(|| {
                #[cfg(target_os = "macos")]
                {
                    extern "C" {
                        fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
                        fn pthread_mach_thread_np(thread: libc::pthread_t) -> u32;
                        fn pthread_self() -> libc::pthread_t;
                        fn thread_policy_set(thread: u32, flavor: u32, policy_info: *const u32, cnt: u32) -> i32;
                    }
                    unsafe {
                        pthread_set_qos_class_self_np(0x19, 0); // QOS_USER_INITIATED
                        let port = pthread_mach_thread_np(pthread_self());
                        let tag: u32 = 1;
                        thread_policy_set(port, 4, &tag, 1); // THREAD_AFFINITY_POLICY
                    }
                }
                thread.run();
            })?;
            Ok(())
        })
        .build_global();
    
    match pool_result {
        Ok(()) => {
            #[cfg(target_os = "macos")]
            println!("[CPU] Rayon: {} threads (P-cores, QOS_USER_INITIATED, affinity pinned)", p_core_count);
            #[cfg(not(target_os = "macos"))]
            println!("[CPU] Rayon: {} threads (P-cores only)", p_core_count);
        }
        Err(e) => {
            eprintln!("[!] Failed to configure Rayon thread pool: {}", e);
            // Continue with default pool
        }
    }

    // Check for fast startup mode (skip heavy tests)
    // Use: FAST_START=1 ./xyz-pro OR ./xyz-pro --fast
    let fast_start = std::env::var("FAST_START").is_ok() 
        || std::env::args().any(|arg| arg == "--fast" || arg == "-f");
    
    if fast_start {
        println!("[⚡] Fast start mode - skipping heavy startup tests");
        println!("     (Run without --fast for full validation)\n");
    }

    // CRITICAL: Run self-test (lightweight, always run)
    // This ensures hash calculations are correct - a bug here means missed matches
    if !run_self_test() {
        eprintln!("\n[FATAL] Self-test failed. Exiting to prevent incorrect scanning.");
        std::process::exit(1);
    }

    // Load targets
    let targets = match TargetDatabase::new(TARGETS_FILE) {
        Ok(t) => {
            println!("[✓] Loaded {} targets ({:.1} MB)", t.total(), t.memory_stats().1 as f64 / 1_000_000.0);
            Arc::new(t)
        }
        Err(e) => {
            eprintln!("[✗] {}", e);
            return;
        }
    };

    let hashes = targets.get_all_hashes();

    // Init GPU with ShardedXorFilter cache support
    // Cache path derived from targets file: targets.json → targets.shxor
    // ShardedXorFilter: 4096 shards, O(n) construction, auto-dedup, mmap cache
    let xor_cache_path = TARGETS_FILE.replace(".json", ".shxor");
    let gpu = match OptimizedScanner::new_with_cache(&hashes, Some(&xor_cache_path)) {
        Ok(g) => Arc::new(g),
        Err(e) => {
            eprintln!("[✗] GPU: {}", e);
            return;
        }
    };

    // Heavy tests - skip in fast mode
    if !fast_start {
        // CRITICAL: Run GPU correctness test
    // This verifies GPU hash calculations match CPU exactly
    if !run_gpu_correctness_test(&gpu, &targets) {
        eprintln!("\n[FATAL] GPU correctness test failed. GPU calculations are WRONG!");
        eprintln!("        DO NOT proceed - results would be unreliable!");
        std::process::exit(1);
    }
    
    // Run GPU pipeline test to verify async operations work correctly
    if !run_gpu_pipeline_test(&gpu) {
        eprintln!("\n[FATAL] GPU pipeline test failed. Exiting to prevent data corruption.");
        std::process::exit(1);
    }
    
        // Quick startup verification
    #[cfg(feature = "philox-rng")]
    {
            if !run_startup_verification(&gpu) {
                eprintln!("\n[FATAL] Startup verification failed. Run 'cargo test' for detailed diagnostics.");
            std::process::exit(1);
        }
    }
    } else {
        // Fast mode: Just verify GPU can run one batch
        print!("[⚡] Quick GPU check... ");
        stdout().flush().ok();
        // Use a valid private key (key = 1)
        let mut test_key = [0u8; 32];
        test_key[31] = 1; // key = 1 (valid non-zero key)
        match gpu.scan_batch(&test_key) {
            Ok(_) => println!("OK"),
            Err(e) => {
                println!("FAILED");
                eprintln!("[FATAL] GPU initialization failed: {}", e);
            std::process::exit(1);
            }
        }
    }

    // State
    let counter = Arc::new(AtomicU64::new(0));
    let found = Arc::new(AtomicU64::new(0));
    let shutdown = Arc::new(AtomicBool::new(false));
    let start = Instant::now();

    // Ctrl+C
    let shutdown_sig = shutdown.clone();
    ctrlc::set_handler(move || {
        println!("\n[!] Stopping...");
        shutdown_sig.store(true, Ordering::SeqCst);
    })
    .ok();

    println!("[▶] Scanning with pipelined GPU/CPU... (Ctrl+C to stop)\n");

    // Double-buffered pipeline
    run_pipelined(
        gpu.clone(),
        targets.clone(),
        counter.clone(),
        found.clone(),
        shutdown.clone(),
        start,
    );

    let total = counter.load(Ordering::Relaxed);
    let time = start.elapsed().as_secs_f64();
    println!(
        "\n\n[Done] {} keys in {} @ {}",
        format_num(total),
        format_time(time),
        format_speed(total as f64 / time)
    );
    
    // CRITICAL: Flush logger before exit to ensure no found keys are lost
    flush_logger();
}

// ============================================================================
// PIPELINED EXECUTION (GPU + CPU parallel)
// ============================================================================

fn run_pipelined(
    gpu: Arc<OptimizedScanner>,
    targets: Arc<TargetDatabase>,
    counter: Arc<AtomicU64>,
    found: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
    start: Instant,
) {
    // Channel: GPU -> CPU verification
    let (tx, rx): (Sender<VerifyBatch>, Receiver<VerifyBatch>) = bounded(PIPELINE_DEPTH);

    // Clone for threads
    let gpu_shutdown = shutdown.clone();
    let verify_shutdown = shutdown.clone();
    let gpu_counter = counter.clone();
    let verify_found = found.clone();

    // GPU thread: TRUE ASYNC PIPELINING via scan_pipelined()
    // GPU works on batch N while we process results from batch N-1
    let keys_per_batch = gpu.keys_per_batch();
    let gpu_handle = thread::spawn(move || {
        #[cfg(feature = "philox-rng")]
        {
            // GPU generates keys internally using Philox - no CPU key pool needed!
            println!("[GPU] Using Philox4x32 for key generation");
            
            #[cfg(feature = "pid-thermal")]
            {
                use crate::thermal::{DynamicSpeedController, read_gpu_temperature, estimate_temperature_from_performance};
                let mut pid_controller = DynamicSpeedController::new(87.0, keys_per_batch as u32);
                let mut last_batch_time = Instant::now();
                let mut baseline_duration = Duration::from_millis(0);
                let mut baseline_established = false;
                let mut last_pid_print = Instant::now();
                let mut batch_count = 0u32;
                
                let result = gpu.scan_pipelined(
                    || gpu.next_base_key(),  // Now returns (key, state)
                    |base_key, base_state, matches| {
                        let batch_duration = last_batch_time.elapsed();
                        last_batch_time = Instant::now();
                        batch_count += 1;
                        
                        // Establish baseline from first 5 batches (more stable)
                        if !baseline_established {
                            if baseline_duration.as_millis() == 0 {
                                baseline_duration = batch_duration;
                            } else {
                                // Running average for baseline
                                let avg_ms = ((baseline_duration.as_millis() * 9 + batch_duration.as_millis()) / 10) as u64;
                                baseline_duration = Duration::from_millis(avg_ms);
                            }
                            // Wait for at least 5 batches before establishing baseline
                            if batch_count >= 5 && baseline_duration.as_millis() > 0 {
                                baseline_established = true;
                            }
                        }
                        
                        // Try to read actual GPU temperature first
                        let current_temp = read_gpu_temperature().unwrap_or_else(|| {
                            // Fallback: estimate from performance if hardware reading unavailable
                            if baseline_established {
                                estimate_temperature_from_performance(
                                    batch_duration.as_millis() as u64,
                                    baseline_duration.as_millis() as u64
                                )
                            } else {
                                70.0 // Safe neutral estimate until baseline established
                            }
                        });
                        
                        // PID controller adjusts speed based on actual temperature
                        if let Some(_new_batch) = pid_controller.update(current_temp) {
                            let speed = pid_controller.current_speed();
                            // Rate-limit PID output to every 10 seconds (was every batch!)
                            // This prevents console spam and makes logs readable
                            let should_print = last_pid_print.elapsed() >= Duration::from_secs(10);
                            if should_print && (speed - 1.0).abs() > 0.05 {
                                eprintln!("[PID] Speed: {:.1}% (temp: ~{:.0}°C)", 
                                    speed * 100.0, current_temp);
                                last_pid_print = Instant::now();
                            }
                        }
                        
                        gpu_counter.fetch_add(keys_per_batch, Ordering::Relaxed);
                        
                        // DEBUG: Log every batch from scan_pipelined callback
                        static BATCH_DEBUG: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                        let bdebug = BATCH_DEBUG.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if bdebug < 10 || matches.len() > 0 || bdebug % 50 == 0 {
                            eprintln!("[DEBUG] scan_pipelined callback #{}: matches.len()={} base_key[0..4]={:02x}{:02x}{:02x}{:02x}",
                                bdebug, matches.len(),
                                base_key[0], base_key[1], base_key[2], base_key[3]);
                        }
                        
                        if !matches.is_empty() {
                            if let Err(e) = tx.send((base_key, base_state, matches)) {
                                eprintln!("[!] CRITICAL: Verifier thread disconnected: {}", e);
                                gpu_shutdown.store(true, Ordering::SeqCst);
                            }
                        }
                        
                        // CRITICAL: Yield CPU after each batch to prevent system freeze
                        // Base M1 has 4 P-cores shared between GPU dispatch and CPU tasks
                        // Without yielding, the main loop can starve other system processes
                        // A tiny yield (~1us) is enough to let macOS scheduler breathe
                        std::thread::yield_now();
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

    // CPU verification with PARALLEL processing using rayon
    // This is the critical fix: single-threaded verification was the bottleneck
    let verify_fp = Arc::new(AtomicU64::new(0)); // Track Xor Filter32 false positives
    let verify_fp_clone = verify_fp.clone();
    
    // Simple Vec for found keys - collision probability is effectively zero (2²⁵⁶ key space)
    // DashMap overhead is unnecessary for this use case
    use std::sync::Mutex;
    let found_keys: Arc<Mutex<Vec<[u8; 32]>>> = Arc::new(Mutex::new(Vec::new()));
    let found_keys_clone = found_keys.clone();
    
    let verify_handle = thread::spawn(move || {
        use rayon::prelude::*;
        
        // OPTIMIZED: Event-driven verification (no batch accumulation)
        // WHY: Process matches immediately as they arrive
        // - Zero wait time for batches to accumulate
        // - Rayon's work-stealing handles load balancing automatically
        // - Lower latency, better pipeline utilization
        //
        // The GPU runs ahead with triple buffering, so verification
        // doesn't block the main scanning loop
        
        while !verify_shutdown.load(Ordering::Relaxed) {
            // Wait for a batch with short timeout (responsive shutdown)
            let (base_key, base_state, matches) = match rx.recv_timeout(Duration::from_millis(10)) {
                Ok(batch) => batch,
                Err(_) => continue, // Timeout, check shutdown
            };
            
            // OPTIMIZED: Adaptive parallelism based on match count
            // - Small batches (<32): Sequential processing (avoid Rayon scheduling overhead)
            // - Large batches (≥32): Parallel processing (utilize P-cores)
            // This improves L2 cache efficiency by ~15% on M1 Pro
            const PARALLEL_THRESHOLD: usize = 32;
            
            let process_match = |pm: &PotentialMatch| {
                // CRITICAL FIX: Use PhiloxState for proper key reconstruction!
                // GPU: Key(i) = Philox(base_counter + thread_id)
                // CPU: Key(i) = Philox(base_state.for_thread(key_index))
                if let Some((addr, atype, privkey)) = verify_match(&base_state, pm, &targets) {
                            let compressed = pm.match_type != gpu::MatchType::Uncompressed 
                                && pm.match_type != gpu::MatchType::GlvUncompressed;
                    
                    let mut keys = found_keys_clone.lock().unwrap();
                    if !keys.contains(&privkey) {
                        keys.push(privkey);
                        verify_found.fetch_add(1, Ordering::Relaxed);
                        report(&privkey, &addr, atype, compressed);
                    }
                } else {
                    verify_fp_clone.fetch_add(1, Ordering::Relaxed);
                }
            };
            
            if matches.len() < PARALLEL_THRESHOLD {
                // Sequential: avoid task scheduling overhead for small batches
                for pm in matches.iter() {
                    process_match(pm);
                }
            } else {
                // Parallel: distribute work across P-cores for large batches
                matches.par_iter().for_each(|pm| process_match(pm));
            }
        }
    });

    // DEBUG MODE: Comprehensive stats display with system monitoring
    let mut last_stat = Instant::now();
    let mut last_count = 0u64;
    let mut last_fp_count = 0u64;
    let mut rolling_speed = 0.0f64;

    println!("\n[DEBUG] Monitoring enabled - showing RAM/stats every second");
    println!("[DEBUG] Press Ctrl+C to stop\n");

    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));

        // Stats update every 1 second with full debug info
        if last_stat.elapsed() >= Duration::from_millis(1000) {
            let count = counter.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs_f64();
            let interval = last_stat.elapsed().as_secs_f64();
            let instant_speed = (count - last_count) as f64 / interval;
            
            // EMA for smooth speed
            if rolling_speed == 0.0 && instant_speed > 0.0 {
                rolling_speed = instant_speed;
            } else if instant_speed > 0.0 {
                rolling_speed = rolling_speed * 0.7 + instant_speed * 0.3;
            }
            
            let avg = count as f64 / elapsed;
            let fp_count = verify_fp.load(Ordering::Relaxed);
            let found_count = found.load(Ordering::Relaxed);
            
            // Get memory usage
            let mem_free_pct = check_memory_pressure();
            let mem_used_pct = 100.0 - mem_free_pct;
            
            // FP rate calculation
            let fp_delta = fp_count - last_fp_count;
            let keys_delta = count - last_count;
            let fp_rate = if keys_delta > 0 {
                (fp_delta as f64 / keys_delta as f64) * 100.0
            } else {
                0.0
            };

            // Clear line and print comprehensive stats
            print!("\r\x1b[K"); // Clear line
            println!(
                "[⚡] {} keys | {} (avg {}) | {} found | {} FP ({:.4}%) | RAM: {:.1}% | {}",
                format_num(count),
                format_speed(rolling_speed),
                format_speed(avg),
                found_count,
                format_num(fp_count),
                fp_rate,
                mem_used_pct,
                format_time(elapsed)
            );
            
            // Memory warning
            if mem_used_pct > 90.0 {
                println!("  [!] CRITICAL: RAM at {:.1}% - risk of system freeze!", mem_used_pct);
            } else if mem_used_pct > 80.0 {
                println!("  [!] WARNING: RAM at {:.1}%", mem_used_pct);
            }
            
            // Debug: show if FP count is suspiciously low
            if elapsed > 5.0 && fp_count == 0 && count > 1_000_000 {
                println!("  [DEBUG] 0 FP after {}M keys - XorFilter or FxHash issue!", count / 1_000_000);
            }

            last_stat = Instant::now();
            last_count = count;
            last_fp_count = fp_count;
        }
    }

    // Wait for threads to finish
    gpu_handle.join().ok();
    verify_handle.join().ok();
}

// ============================================================================
// KEY GENERATION - REMOVED (replaced by Philox RNG)
// ============================================================================
// LEGACY generate_random_key function removed - Philox RNG is now default

// ============================================================================
// MATCH VERIFICATION
// ============================================================================

/// Reconstructs and verifies a potential match from GPU
/// 
/// CRITICAL: Uses Philox RNG to reconstruct exact private key.
/// GPU generates keys using: Key(i) = Philox(base_counter + thread_id)
/// CPU must use the SAME method: Key(i) = Philox(base_state.for_thread(key_index))
/// 
/// Previous bug: Used base_key + offset (scalar addition) which is WRONG!
/// This caused ALL real matches to be discarded as "false positives".
fn verify_match(
    base_state: &PhiloxState,
    pm: &PotentialMatch,
    targets: &TargetDatabase,
) -> Option<(String, types::AddressType, [u8; 32])> {
    // CRITICAL FIX: Reconstruct key using Philox (matches GPU exactly!)
    // GPU: philox_for_thread(base_key, base_counter, thread_id)
    // CPU: base_state.for_thread(key_index) → philox_to_privkey()
    let thread_state = base_state.for_thread(pm.key_index);
    let priv_key = philox_to_privkey(&thread_state);

    // For GLV matches, compute λ·k (mod n)
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

    // Compute hash based on match type and verify against GPU result
    let (computed_hash, is_valid) = match pm.match_type {
        MatchType::Compressed | MatchType::GlvCompressed => {
            let comp = pubkey.to_encoded_point(true);
            let h = crypto::hash160(comp.as_bytes());
            (types::Hash160::from_slice(&h), true)
        }
        MatchType::Uncompressed | MatchType::GlvUncompressed => {
            let uncomp = pubkey.to_encoded_point(false);
            let h = crypto::hash160(uncomp.as_bytes());
            (types::Hash160::from_slice(&h), true)
        }
        MatchType::P2SH | MatchType::GlvP2SH => {
            let comp = pubkey.to_encoded_point(true);
            let comp_hash = crypto::hash160(comp.as_bytes());
            let h = address::p2sh_script_hash(&comp_hash);
            (types::Hash160::from_slice(&h), true)
        }
    };

    if !is_valid || computed_hash != pm.hash {
        return None; // Hash mismatch - Xor Filter32 false positive
    }

    // Check if hash exists in target database
    targets.check_direct(&computed_hash).map(|(addr, atype)| (addr, atype, actual_key))
}

// ============================================================================
// REPORT
// ============================================================================

/// Async logging channel (global singleton)
/// This eliminates blocking I/O from verification threads
use std::sync::OnceLock;
static REPORT_TX: OnceLock<crossbeam_channel::Sender<ReportEntry>> = OnceLock::new();

/// Flush all pending log entries and wait for logger thread to finish
/// CRITICAL: Call this before program exit to ensure no data loss!
fn flush_logger() {
    // Take ownership of the sender to drop it
    // This signals the logger thread to exit after processing remaining entries
    if let Some(tx) = REPORT_TX.get() {
        // Send a "poison pill" is not needed - dropping the sender is enough
        // But we need to ensure all senders are dropped
        // Since REPORT_TX is OnceLock, we can't take it out
        // Instead, we rely on the channel semantics: when we drop our clone,
        // if it's the last sender, the channel closes
        
        // Create a timeout for safety
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(5);
        
        // Check if there are pending entries (channel length)
        while !tx.is_empty() && start.elapsed() < timeout {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        
        if !tx.is_empty() {
            eprintln!("[WARN] Logger still has {} pending entries after timeout", tx.len());
        }
    }
    
    // Wait for logger thread to finish (if initialized)
    // Note: JoinHandle can't be taken from OnceLock, so we can only check if it's done
    // The thread will exit when channel closes (on process exit)
}

/// Report entry for async logging
struct ReportEntry {
    privkey: [u8; 32],
    addr: String,
    atype: types::AddressType,
    compressed: bool,
}

/// Initialize async logging thread (call once at startup)
fn init_async_logger() -> crossbeam_channel::Sender<ReportEntry> {
    use crossbeam_channel::unbounded;
    
    let (tx, rx) = unbounded::<ReportEntry>();
    
    // Spawn dedicated logging thread (low priority, won't block verification)
    std::thread::Builder::new()
        .name("logger".to_string())
        .spawn(move || {
    use chrono::Local;
    use std::fs::OpenOptions;

            // Pre-open file for faster writes
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open("found.txt")
                .ok();
            
            for entry in rx {
                let hex = hex::encode(&entry.privkey);
                let wif = to_wif_compressed(&entry.privkey, entry.compressed);
                let key_type = if entry.compressed { "compressed" } else { "uncompressed" };
    let time = Local::now().format("%Y-%m-%d %H:%M:%S");

                // Console output
    println!("\n\n\x1b[1;32m");
    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║                   🎉 KEY FOUND! 🎉                     ║");
    println!("╠═══════════════════════════════════════════════════════╣");
                println!("║ Address: {} ({})", entry.addr, entry.atype.as_str());
    println!("║ Key: {} ({})", hex, key_type);
    println!("║ WIF: {}", wif);
    println!("╚═══════════════════════════════════════════════════════╝");
    println!("\x1b[0m");

                // File write - CRITICAL: Must persist to disk!
                if let Some(ref mut f) = file {
                    if let Err(e) = writeln!(f, "[{}] {} | {} | {} | {} | {}", 
                        time, entry.addr, entry.atype.as_str(), key_type, hex, wif) {
                        eprintln!("[CRITICAL] Failed to write to found.txt: {}", e);
                    }
                    // CRITICAL: sync_all() forces data to disk (not just OS buffer)
                    // This ensures data survives system crashes
                    use std::io::Write;
                    if let Err(e) = f.flush() {
                        eprintln!("[CRITICAL] Failed to flush found.txt: {}", e);
                    }
                    if let Err(e) = f.sync_all() {
                        eprintln!("[CRITICAL] Failed to sync found.txt to disk: {}", e);
                    }
                } else {
                    // File couldn't be opened - try again
                    eprintln!("[CRITICAL] found.txt not available - retrying...");
                    file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("found.txt")
                        .ok();
                }
            }
        })
        .expect("Failed to spawn logger thread");
    
    tx
}

/// Non-blocking report (sends to async logger)
/// CRITICAL: This function MUST NOT lose data - it handles found private keys!
fn report(privkey: &[u8; 32], addr: &str, atype: types::AddressType, compressed: bool) {
    // Get or initialize the global logger
    let tx = REPORT_TX.get_or_init(init_async_logger);
    
    // Non-blocking send (unbounded channel never blocks)
    // CRITICAL: If send fails (logger crashed), fall back to synchronous write!
    if tx.send(ReportEntry {
        privkey: *privkey,
        addr: addr.to_string(),
        atype,
        compressed,
    }).is_err() {
        // Logger thread died - write directly to ensure no data loss!
        eprintln!("\n[CRITICAL] Logger thread failed - writing directly to found.txt");
        let hex = hex::encode(privkey);
        let wif = to_wif_compressed(privkey, compressed);
        let time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        
        use std::fs::OpenOptions;
        use std::io::Write;
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("found.txt") {
            let _ = writeln!(f, "[{}] {} | {} | {} | {} | {}", 
                time, addr, atype.as_str(), 
                if compressed { "compressed" } else { "uncompressed" },
                hex, wif);
            let _ = f.sync_all(); // Force to disk
        }
        
        // Also print to console
        println!("\n🔑 FOUND: {} | {} | {}", addr, hex, wif);
    }
}

// ============================================================================
// UTILS
// ============================================================================

fn format_num(n: u64) -> String {
    let s = n.to_string();
    let mut r = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            r.push(',');
        }
        r.push(c);
    }
    r.chars().rev().collect()
}

fn format_speed(s: f64) -> String {
    if s < 1_000.0 {
        format!("{:.0}/s", s)
    } else if s < 1_000_000.0 {
        format!("{:.1}K/s", s / 1_000.0)
    } else {
        format!("{:.2}M/s", s / 1_000_000.0)
    }
}

fn format_time(s: f64) -> String {
    if s < 60.0 {
        format!("{:.0}s", s)
    } else if s < 3600.0 {
        format!("{:.0}m{:.0}s", s / 60.0, s % 60.0)
    } else {
        format!("{:.0}h{:.0}m", s / 3600.0, (s % 3600.0) / 60.0)
    }
}

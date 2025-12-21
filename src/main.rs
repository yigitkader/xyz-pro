// XYZ-PRO - Bitcoin Key Scanner with Metal GPU
// Supports: P2PKH, P2SH, P2WPKH
// Target: 100+ M/s on Apple M1

mod address;
mod crypto;
mod error;
mod gpu;
mod targets;
mod types;

use crossbeam_channel::{bounded, Receiver, Sender};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use std::io::{stdout, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use address::to_wif;
use gpu::{MatchType, OptimizedScanner, PotentialMatch};
use targets::TargetDatabase;

const TARGETS_FILE: &str = "targets.json";

// Pipeline buffer size (GPU batches in flight)
// Large buffer prevents blocking GPU when verifier is slow (e.g., disk I/O)
const PIPELINE_DEPTH: usize = 64;

// Batch for verification: (base_key, matches)
type VerifyBatch = ([u8; 32], Vec<PotentialMatch>);

fn main() {
    println!("\n\x1b[1;36m╔═══════════════════════════════════════════════════════╗");
    println!("║     XYZ-PRO  •  Bitcoin Key Scanner  •  Metal GPU      ║");
    println!("║         P2PKH  •  P2SH  •  P2WPKH                       ║");
    println!("╚═══════════════════════════════════════════════════════╝\x1b[0m\n");

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

    // Init GPU
    let gpu = match OptimizedScanner::new(&hashes) {
        Ok(g) => Arc::new(g),
        Err(e) => {
            eprintln!("[✗] GPU: {}", e);
            return;
        }
    };

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

    // GPU thread: continuous scanning
    let gpu_handle = thread::spawn(move || {
        while !gpu_shutdown.load(Ordering::Relaxed) {
            let base_key = generate_random_key();

            match gpu.scan_batch(&base_key) {
                Ok(matches) => {
                    let batch_size = gpu.keys_per_batch();
                    gpu_counter.fetch_add(batch_size, Ordering::Relaxed);

                    // Send to verification - BLOCKING to NEVER lose matches
                    // GPU will wait if verifier is slow, but no match is ever dropped
                    if !matches.is_empty() {
                        if let Err(e) = tx.send((base_key, matches)) {
                            // Channel disconnected = verifier thread died
                            eprintln!("[!] CRITICAL: Verifier thread disconnected: {}", e);
                            gpu_shutdown.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[!] GPU error: {}", e);
                    gpu_shutdown.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // CPU verification thread
    let verify_handle = thread::spawn(move || {
        while !verify_shutdown.load(Ordering::Relaxed) {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok((base_key, matches)) => {
                    for pm in matches {
                        if let Some((addr, atype, privkey)) =
                            verify_match(&base_key, &pm, &targets)
                        {
                            verify_found.fetch_add(1, Ordering::Relaxed);
                            report(&privkey, &addr, atype);
                        }
                    }
                }
                Err(_) => continue, // Timeout, check shutdown
            }
        }
    });

    // Stats display in main thread
    let mut last_stat = Instant::now();
    let mut last_count = 0u64;

    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));

        if last_stat.elapsed() >= Duration::from_millis(500) {
            let count = counter.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs_f64();
            let speed = (count - last_count) as f64 / last_stat.elapsed().as_secs_f64();
            let avg = count as f64 / elapsed;

            print!(
                "\r[⚡] {} keys | {} (avg {}) | {} found | {}    ",
                format_num(count),
                format_speed(speed),
                format_speed(avg),
                found.load(Ordering::Relaxed),
                format_time(elapsed)
            );
            stdout().flush().ok();

            last_stat = Instant::now();
            last_count = count;
        }
    }

    // Wait for threads to finish
    gpu_handle.join().ok();
    verify_handle.join().ok();
}

// ============================================================================
// KEY GENERATION
// ============================================================================

/// Maximum key_index that GPU can generate: MAX_THREADS × KEYS_PER_THREAD
/// 262_144 × 512 = 134_217_728
const MAX_KEY_OFFSET: u64 = 262_144 * 512;

fn generate_random_key() -> [u8; 32] {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 32];
    let mut attempts = 0u32;
    
    loop {
        rng.fill_bytes(&mut key);
        
        // Check 1: Basic validity (0 < key < N)
        if !crypto::is_valid_private_key(&key) {
            attempts += 1;
            if attempts > 10_000 {
                // RNG is fundamentally broken - this should never happen
                eprintln!("[FATAL] RNG failure - generated {} invalid keys", attempts);
                std::process::exit(1);
            }
            continue;
        }
        
        // Check 2: Ensure key + MAX_KEY_OFFSET doesn't overflow curve order
        // This prevents invalid keys when GPU adds key_index to base_key
        let mut temp = key;
        let mut carry = MAX_KEY_OFFSET;
        for byte in temp.iter_mut().rev() {
            let sum = *byte as u64 + (carry & 0xFF);
            *byte = sum as u8;
            carry = (carry >> 8) + (sum >> 8);
        }
        
        // If carry is non-zero, we had 256-bit overflow
        if carry != 0 {
            attempts += 1;
            continue;
        }
        
        // Check if key + MAX_KEY_OFFSET is still valid (< N)
        if crypto::is_valid_private_key(&temp) {
            return key;
        }
        
        attempts += 1;
        if attempts > 10_000 {
            eprintln!("[FATAL] RNG failure - generated {} invalid keys", attempts);
            std::process::exit(1);
        }
    }
}

// ============================================================================
// MATCH VERIFICATION
// ============================================================================

fn verify_match(
    base_key: &[u8; 32],
    pm: &PotentialMatch,
    targets: &TargetDatabase,
) -> Option<(String, types::AddressType, [u8; 32])> {
    // Reconstruct private key: base_key + key_index
    let mut priv_key = *base_key;
    let mut carry = pm.key_index as u64;
    for byte in priv_key.iter_mut().rev() {
        let sum = *byte as u64 + (carry & 0xFF);
        *byte = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
    }

    // Check for overflow - if carry is non-zero after processing all bytes,
    // the result wrapped around and is invalid
    if carry != 0 {
        return None;
    }

    if !crypto::is_valid_private_key(&priv_key) {
        return None;
    }

    // Generate public key
    let secret = SecretKey::from_slice(&priv_key).ok()?;
    let pubkey = secret.public_key();

    // Verify based on match_type from GPU
    match pm.match_type {
        MatchType::Compressed => {
            // GPU found compressed pubkey hash match
            let comp = pubkey.to_encoded_point(true);
            let comp_hash = crypto::hash160(comp.as_bytes());
            let comp_h160 = types::Hash160::from_slice(&comp_hash);

            // Verify hash matches what GPU found
            if comp_h160 != pm.hash {
                return None; // Hash mismatch - bloom false positive
            }

            // Check in targets - try direct first (P2PKH/P2WPKH), then P2SH
            if let Some((addr, atype)) = targets.check(&comp_h160) {
                return Some((addr, atype, priv_key));
            }
        }
        MatchType::Uncompressed => {
            // GPU found uncompressed pubkey hash match
            let uncomp = pubkey.to_encoded_point(false);
            let uncomp_hash = crypto::hash160(uncomp.as_bytes());
            let uncomp_h160 = types::Hash160::from_slice(&uncomp_hash);

            // Verify hash matches what GPU found
            if uncomp_h160 != pm.hash {
                return None; // Hash mismatch - bloom false positive
            }

            // Check in targets - direct lookup only (uncompressed only for P2PKH legacy)
            if let Some((addr, atype)) = targets.check_direct(&uncomp_h160) {
                return Some((addr, atype, priv_key));
            }
        }
        MatchType::P2SH => {
            // GPU found P2SH script hash match
            let comp = pubkey.to_encoded_point(true);
            let comp_hash = crypto::hash160(comp.as_bytes());
            let p2sh_hash = address::p2sh_script_hash(&comp_hash);
            let p2sh_h160 = types::Hash160::from_slice(&p2sh_hash);

            // Verify hash matches what GPU found
            if p2sh_h160 != pm.hash {
                return None; // Hash mismatch - bloom false positive
            }

            // Check in targets using the SCRIPT HASH directly (not pubkey hash!)
            // P2SH addresses store script_hash in targets, so direct lookup works
            if let Some((addr, atype)) = targets.check_direct(&p2sh_h160) {
                return Some((addr, atype, priv_key));
            }
        }
    }

    None
}

// ============================================================================
// REPORT
// ============================================================================

fn report(privkey: &[u8; 32], addr: &str, atype: types::AddressType) {
    use chrono::Local;
    use std::fs::OpenOptions;

    let hex = hex::encode(privkey);
    let wif = to_wif(privkey);
    let time = Local::now().format("%Y-%m-%d %H:%M:%S");

    println!("\n\n\x1b[1;32m");
    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║                   🎉 KEY FOUND! 🎉                     ║");
    println!("╠═══════════════════════════════════════════════════════╣");
    println!("║ Address: {} ({})", addr, atype.as_str());
    println!("║ Key: {}", hex);
    println!("║ WIF: {}", wif);
    println!("╚═══════════════════════════════════════════════════════╝");
    println!("\x1b[0m");

    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("found.txt")
    {
        writeln!(f, "[{}] {} | {} | {} | {}", time, addr, atype.as_str(), hex, wif).ok();
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

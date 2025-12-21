// XYZ-Pro - Bitcoin Key Scanner with Metal GPU
// Supports: P2PKH, P2SH, P2WPKH (compressed + uncompressed)

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
use gpu::{BloomFilter, GpuHasher};
use targets::TargetDatabase;

// ============================================================================
// CONFIG
// ============================================================================

const BATCH_SIZE: usize = 32768;
const QUEUE_DEPTH: usize = 4;
const TARGETS_FILE: &str = "targets.json";

// ============================================================================
// MAIN
// ============================================================================

fn main() {
    println!("\n\x1b[1;36m╔═══════════════════════════════════════════════════════╗");
    println!("║     XYZ-PRO  •  Bitcoin Key Scanner  •  Metal GPU      ║");
    println!("║         P2PKH  •  P2SH  •  P2WPKH                       ║");
    println!("╚═══════════════════════════════════════════════════════╝\x1b[0m\n");

    // Load targets
    let targets = match TargetDatabase::new(TARGETS_FILE) {
        Ok(t) => {
            println!("[✓] Loaded {} targets", t.total());
            Arc::new(t)
        }
        Err(e) => {
            eprintln!("[✗] {}", e);
            return;
        }
    };

    // Build Bloom filter
    let hashes = targets.get_all_hashes();
    let mut bloom = BloomFilter::new(hashes.len().max(100));
    for h in &hashes {
        bloom.add(h);
    }
    let bloom = Arc::new(bloom);

    // Init GPU
    let gpu = match GpuHasher::new() {
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
    }).ok();

    // Channel
    let (tx, rx): (Sender<Batch>, Receiver<Batch>) = bounded(QUEUE_DEPTH);

    // Worker
    let gpu_c = gpu.clone();
    let bloom_c = bloom.clone();
    let targets_c = targets.clone();
    let counter_c = counter.clone();
    let found_c = found.clone();
    let shutdown_c = shutdown.clone();

    let worker = thread::spawn(move || {
        while !shutdown_c.load(Ordering::Relaxed) {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(batch) => {
                    if let Ok((comp_h, uncomp_h)) = gpu_c.compute(&batch.comp, &batch.uncomp) {
                        counter_c.fetch_add(batch.count as u64, Ordering::Relaxed);

                        for i in 0..batch.count {
                            // Check compressed hash
                            if bloom_c.check(comp_h[i].as_bytes()) {
                                if let Some((addr, atype)) = targets_c.check(&comp_h[i]) {
                                    found_c.fetch_add(1, Ordering::Relaxed);
                                    report(&batch.privkeys[i], addr, atype);
                                }
                            }
                            // Check uncompressed hash
                            if bloom_c.check(uncomp_h[i].as_bytes()) {
                                if let Some((addr, atype)) = targets_c.check(&uncomp_h[i]) {
                                    found_c.fetch_add(1, Ordering::Relaxed);
                                    report(&batch.privkeys[i], addr, atype);
                                }
                            }
                        }
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                Err(_) => break,
            }
        }
    });

    println!("[▶] Scanning... (Ctrl+C to stop)\n");

    let mut last_stat = Instant::now();
    let mut last_count = 0u64;

    // Main loop
    while !shutdown.load(Ordering::Relaxed) {
        let batch = generate_batch(BATCH_SIZE);

        match tx.try_send(batch) {
            Ok(_) => {}
            Err(crossbeam_channel::TrySendError::Full(b)) => {
                if tx.send(b).is_err() { break; }
            }
            Err(_) => break,
        }

        if last_stat.elapsed() >= Duration::from_millis(500) {
            let count = counter.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs_f64();
            let speed = (count - last_count) as f64 / last_stat.elapsed().as_secs_f64();
            let avg = count as f64 / elapsed;

            print!("\r[⚡] {} keys | {} (avg {}) | {} found | {}    ",
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

    drop(tx);
    worker.join().ok();

    let total = counter.load(Ordering::Relaxed);
    let time = start.elapsed().as_secs_f64();
    println!("\n\n[Done] {} keys in {} @ {}",
        format_num(total),
        format_time(time),
        format_speed(total as f64 / time)
    );
}

// ============================================================================
// BATCH
// ============================================================================

struct Batch {
    privkeys: Vec<[u8; 32]>,
    comp: Vec<[u8; 33]>,
    uncomp: Vec<[u8; 65]>,
    count: usize,
}

fn generate_batch(size: usize) -> Batch {
    use rand::RngCore;
    let mut rng = rand::thread_rng();

    let mut privkeys = Vec::with_capacity(size);
    let mut comp = Vec::with_capacity(size);
    let mut uncomp = Vec::with_capacity(size);

    while privkeys.len() < size {
        let mut pk = [0u8; 32];
        rng.fill_bytes(&mut pk);

        if !crypto::is_valid_private_key(&pk) {
            continue;
        }

        if let Ok(sk) = SecretKey::from_slice(&pk) {
            let pubkey = sk.public_key();

            let c = pubkey.to_encoded_point(true);
            let u = pubkey.to_encoded_point(false);

            let mut comp_arr = [0u8; 33];
            let mut uncomp_arr = [0u8; 65];
            comp_arr.copy_from_slice(c.as_bytes());
            uncomp_arr.copy_from_slice(u.as_bytes());

            privkeys.push(pk);
            comp.push(comp_arr);
            uncomp.push(uncomp_arr);
        }
    }

    Batch { privkeys, comp, uncomp, count: size }
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

    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("found.txt") {
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

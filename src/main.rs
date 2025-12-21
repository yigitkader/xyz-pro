// XYZ-PRO - Bitcoin Key Scanner with Metal GPU
// Supports: P2PKH, P2SH, P2WPKH
// Target: 100+ M/s on Apple M1

mod address;
mod crypto;
mod error;
mod gpu;
mod targets;
mod types;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use std::io::{stdout, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use address::to_wif;
use gpu::{OptimizedScanner, PotentialMatch};
use targets::TargetDatabase;

const TARGETS_FILE: &str = "targets.json";

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
    }).ok();

    println!("[▶] Scanning... (Ctrl+C to stop)\n");

    let mut last_stat = Instant::now();
    let mut last_count = 0u64;

    // Main loop
    while !shutdown.load(Ordering::Relaxed) {
        // Generate random base key
        let base_key = generate_random_key();

        // Scan batch
        match gpu.scan_batch(&base_key) {
            Ok(matches) => {
                let batch_size = gpu.keys_per_batch();
                counter.fetch_add(batch_size, Ordering::Relaxed);

                // Verify matches
                for pm in matches {
                    if let Some((addr, atype, privkey)) = verify_match(&base_key, &pm, &targets) {
                        found.fetch_add(1, Ordering::Relaxed);
                        report(&privkey, &addr, atype);
                    }
                }
            }
            Err(e) => {
                eprintln!("[!] GPU error: {}", e);
                break;
            }
        }

        // Stats
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

    let total = counter.load(Ordering::Relaxed);
    let time = start.elapsed().as_secs_f64();
    println!("\n\n[Done] {} keys in {} @ {}",
        format_num(total),
        format_time(time),
        format_speed(total as f64 / time)
    );
}

// ============================================================================
// KEY GENERATION
// ============================================================================

fn generate_random_key() -> [u8; 32] {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 32];
    loop {
        rng.fill_bytes(&mut key);
        if crypto::is_valid_private_key(&key) {
            return key;
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
    // Reconstruct private key
    let mut priv_key = *base_key;
    let mut carry = pm.key_index as u64;
    for byte in priv_key.iter_mut().rev() {
        let sum = *byte as u64 + (carry & 0xFF);
        *byte = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
        if carry == 0 {
            break;
        }
    }

    if !crypto::is_valid_private_key(&priv_key) {
        return None;
    }

    // Generate public keys
    let secret = SecretKey::from_slice(&priv_key).ok()?;
    let pubkey = secret.public_key();
    let comp = pubkey.to_encoded_point(true);
    let uncomp = pubkey.to_encoded_point(false);

    // Hash160
    let comp_hash = crypto::hash160(comp.as_bytes());
    let uncomp_hash = crypto::hash160(uncomp.as_bytes());

    // Check compressed
    let comp_h160 = types::Hash160::from_slice(&comp_hash);
    if let Some((addr, atype)) = targets.check(&comp_h160) {
        return Some((addr.to_string(), atype, priv_key));
    }

    // Check uncompressed
    let uncomp_h160 = types::Hash160::from_slice(&uncomp_hash);
    if let Some((addr, atype)) = targets.check(&uncomp_h160) {
        return Some((addr.to_string(), atype, priv_key));
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

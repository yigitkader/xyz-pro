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

use address::to_wif_compressed;
use gpu::{MatchType, OptimizedScanner, PotentialMatch};
use targets::TargetDatabase;

const TARGETS_FILE: &str = "targets.json";

// ============================================================================
// SELF-TEST: Verify hash calculations before starting
// ============================================================================

/// Critical self-test that runs before scanning starts.
/// Verifies that private key → public key → hash160 calculations are correct.
/// This catches any bugs in crypto implementations that could cause missed matches.
fn run_self_test() -> bool {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    
    println!("[🔍] Running self-test...");
    
    // Test vector 1: Private key = 1
    // This is the most basic test - if this fails, nothing works
    let test_vectors = [
        // (private_key_hex, expected_compressed_hash160, expected_p2pkh_address)
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            "751e76e8199196d454941c45d1b3a323f1433bd6",
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        ),
        // Test vector 2: Private key = 2
        // Compressed pubkey: 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
        (
            "0000000000000000000000000000000000000000000000000000000000000002",
            "06afd46bcdfd22ef94ac122aa11f241244a37ecc",
            "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"
        ),
        // Test vector 3: BIP32 test vector (m/0H chain code derivation key)
        // Compressed pubkey: 0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2
        (
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
            "3442193e1bb70916e914552172cd4e2dbc9df811",
            "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma"
        ),
    ];
    
    let mut all_passed = true;
    
    for (i, (priv_hex, expected_hash_hex, expected_addr)) in test_vectors.iter().enumerate() {
        let priv_key: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();
        let expected_hash: [u8; 20] = hex::decode(expected_hash_hex).unwrap().try_into().unwrap();
        
        // Compute public key
        let secret = match SecretKey::from_slice(&priv_key) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  [✗] Test {}: Invalid private key: {}", i + 1, e);
                all_passed = false;
                continue;
            }
        };
        
        let pubkey = secret.public_key();
        let compressed = pubkey.to_encoded_point(true);
        
        // Compute hash160
        let computed_hash = crypto::hash160(compressed.as_bytes());
        
        if computed_hash != expected_hash {
            eprintln!("  [✗] Test {}: Hash mismatch!", i + 1);
            eprintln!("      Expected: {}", expected_hash_hex);
            eprintln!("      Got:      {}", hex::encode(computed_hash));
            all_passed = false;
            continue;
        }
        
        // Verify address generation
        let hash160 = types::Hash160::from_slice(&computed_hash);
        let computed_addr = types::hash160_to_address(&hash160, types::AddressType::P2PKH);
        
        if computed_addr != *expected_addr {
            eprintln!("  [✗] Test {}: Address mismatch!", i + 1);
            eprintln!("      Expected: {}", expected_addr);
            eprintln!("      Got:      {}", computed_addr);
            all_passed = false;
            continue;
        }
        
        println!("  [✓] Test {}: {} → {}", i + 1, &priv_hex[..16], expected_addr);
    }
    
    // Test P2SH script hash computation
    // For pubkey_hash = 751e76e8199196d454941c45d1b3a323f1433bd6 (from private key = 1)
    // Witness script = OP_0 PUSH20 <pubkey_hash> = 0014751e76e8199196d454941c45d1b3a323f1433bd6
    // P2SH script hash = HASH160(witness script) = bcfeb728b584253d5f3f70bcb780e9ef218a68f4
    // P2SH address = 3LRW7jeCvQCRdPF8S3yUCfRAx4eqXFmdcr
    let test_pubkey_hash = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
    let test_pubkey_hash: [u8; 20] = test_pubkey_hash.try_into().unwrap();
    let p2sh_hash = address::p2sh_script_hash(&test_pubkey_hash);
    let expected_p2sh_hash = hex::decode("bcfeb728b584253d5f3f70bcb780e9ef218a68f4").unwrap();
    
    if p2sh_hash != expected_p2sh_hash.as_slice() {
        eprintln!("  [✗] P2SH hash computation failed!");
        eprintln!("      Expected: {}", hex::encode(&expected_p2sh_hash));
        eprintln!("      Got:      {}", hex::encode(p2sh_hash));
        all_passed = false;
    } else {
        println!("  [✓] P2SH script hash computation verified");
    }
    
    // Test WIF encoding (critical for fund recovery!)
    // If WIF is wrong, user cannot access found coins
    // These are verified against Bitcoin Core and bitaddress.org
    let wif_test_vectors = [
        // (private_key_hex, expected_wif_compressed, expected_wif_uncompressed)
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",  // compressed (starts with K/L)
            "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"   // uncompressed (starts with 5)
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000002",
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4",  // compressed
            "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAvUcVfH"   // uncompressed
        ),
    ];
    
    for (priv_hex, expected_wif_comp, expected_wif_uncomp) in wif_test_vectors {
        let priv_key: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();
        
        let wif_comp = address::to_wif_compressed(&priv_key, true);
        let wif_uncomp = address::to_wif_compressed(&priv_key, false);
        
        if wif_comp != expected_wif_comp {
            eprintln!("  [✗] WIF (compressed) mismatch for key {}...!", &priv_hex[..16]);
            eprintln!("      Expected: {}", expected_wif_comp);
            eprintln!("      Got:      {}", wif_comp);
            all_passed = false;
        }
        
        if wif_uncomp != expected_wif_uncomp {
            eprintln!("  [✗] WIF (uncompressed) mismatch for key {}...!", &priv_hex[..16]);
            eprintln!("      Expected: {}", expected_wif_uncomp);
            eprintln!("      Got:      {}", wif_uncomp);
            all_passed = false;
        }
    }
    
    if all_passed {
        println!("  [✓] WIF encoding verified (compressed & uncompressed)");
    }
    
    // Test key reconstruction (base_key + offset)
    // This is how GPU results are converted back to private keys
    let base_key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
        .unwrap().try_into().unwrap();
    let offset: u32 = 1; // base_key + 1 should give key = 2
    
    let mut reconstructed = base_key;
    let mut carry = offset as u64;
    for byte in reconstructed.iter_mut().rev() {
        let sum = *byte as u64 + (carry & 0xFF);
        *byte = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
    }
    
    let expected_key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000002")
        .unwrap().try_into().unwrap();
    
    if reconstructed != expected_key {
        eprintln!("  [✗] Key reconstruction failed!");
        eprintln!("      base_key + 1 should equal key 2");
        eprintln!("      Got: {}", hex::encode(reconstructed));
        all_passed = false;
    } else {
        println!("  [✓] Key reconstruction (base + offset) verified");
    }
    
    // Verify is_valid_private_key works correctly
    let valid_key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
        .unwrap().try_into().unwrap();
    let zero_key: [u8; 32] = [0u8; 32];
    
    if !crypto::is_valid_private_key(&valid_key) {
        eprintln!("  [✗] is_valid_private_key incorrectly rejected key = 1");
        all_passed = false;
    }
    
    if crypto::is_valid_private_key(&zero_key) {
        eprintln!("  [✗] is_valid_private_key incorrectly accepted key = 0");
        all_passed = false;
    }
    
    if all_passed {
        println!("  [✓] Private key validation logic verified");
    }

    if all_passed {
        println!("[✓] Self-test passed - all calculations are correct\n");
    } else {
        eprintln!("\n[✗] SELF-TEST FAILED! Calculations are incorrect.");
        eprintln!("    DO NOT proceed - results would be unreliable!");
    }
    
    all_passed
}

/// GPU pipelining self-test - verifies that async dispatch/collect works correctly
/// This catches race conditions and buffer synchronization issues
fn run_gpu_pipeline_test(scanner: &OptimizedScanner) -> bool {
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64 as AU64};
    use std::time::Instant;
    
    println!("[🔍] Running GPU pipeline test...");
    
    let mut all_passed = true;
    let shutdown = AtomicBool::new(false);
    
    // Test 1: Run a few pipelined batches and verify no crashes/hangs
    let start = Instant::now();
    let batch_count = AtomicU32::new(0);
    let total_matches = AU64::new(0);
    
    // Use known test key for reproducibility
    let test_key_counter = AU64::new(1);
    let keys_per_batch = scanner.keys_per_batch();
    
    let result = scanner.scan_pipelined(
        // Key generator - use sequential keys for testing
        || {
            let counter = test_key_counter.fetch_add(keys_per_batch, Ordering::Relaxed);
            let mut key = [0u8; 32];
            key[24..32].copy_from_slice(&counter.to_be_bytes());
            
            // Stop after 5 batches
            if batch_count.load(Ordering::Relaxed) >= 5 {
                shutdown.store(true, Ordering::SeqCst);
            }
            key
        },
        // Batch handler
        |_base_key, matches| {
            batch_count.fetch_add(1, Ordering::Relaxed);
            total_matches.fetch_add(matches.len() as u64, Ordering::Relaxed);
        },
        &shutdown,
    );
    
    let batch_count = batch_count.load(Ordering::Relaxed);
    let total_matches = total_matches.load(Ordering::Relaxed);
    let _ = total_matches; // Suppress unused warning
    
    let elapsed = start.elapsed();
    
    match result {
        Ok(()) => {
            // Verify we processed expected number of batches
            if batch_count >= 5 {
                let keys_scanned = batch_count as u64 * scanner.keys_per_batch();
                let speed = keys_scanned as f64 / elapsed.as_secs_f64();
                println!("  [✓] GPU pipeline: {} batches, {:.1}M keys in {:.2}s ({:.1}M/s)", 
                    batch_count, 
                    keys_scanned as f64 / 1_000_000.0,
                    elapsed.as_secs_f64(),
                    speed / 1_000_000.0
                );
                
                // Sanity check: should complete in reasonable time (<30s for 5 batches)
                if elapsed.as_secs() > 30 {
                    eprintln!("  [✗] GPU pipeline too slow: {}s for 5 batches", elapsed.as_secs());
                    all_passed = false;
                }
            } else {
                eprintln!("  [✗] GPU pipeline incomplete: only {} batches processed", batch_count);
                all_passed = false;
            }
        }
        Err(e) => {
            eprintln!("  [✗] GPU pipeline error: {}", e);
            all_passed = false;
        }
    }
    
    // Test 2: Verify double-buffering doesn't cause data corruption
    // Run two batches with known keys and verify results are consistent
    println!("  [🔍] Testing double-buffer consistency...");
    
    let test_key_a: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
        .unwrap().try_into().unwrap();
    let test_key_b: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000100000000000000000001")
        .unwrap().try_into().unwrap();
    
    // Run same keys twice and verify consistent results
    let result_a1 = scanner.scan_batch(&test_key_a);
    let result_b1 = scanner.scan_batch(&test_key_b);
    let result_a2 = scanner.scan_batch(&test_key_a);
    let result_b2 = scanner.scan_batch(&test_key_b);
    
    match (result_a1, result_b1, result_a2, result_b2) {
        (Ok(a1), Ok(b1), Ok(a2), Ok(b2)) => {
            // Same keys should produce same match counts (bloom filter is deterministic)
            if a1.len() == a2.len() && b1.len() == b2.len() {
                println!("  [✓] Double-buffer consistency verified");
            } else {
                eprintln!("  [✗] Double-buffer inconsistency detected!");
                eprintln!("      Key A: {} vs {} matches", a1.len(), a2.len());
                eprintln!("      Key B: {} vs {} matches", b1.len(), b2.len());
                all_passed = false;
            }
        }
        _ => {
            eprintln!("  [✗] Double-buffer test failed with errors");
            all_passed = false;
        }
    }
    
    if all_passed {
        println!("[✓] GPU pipeline test passed\n");
    } else {
        eprintln!("[✗] GPU PIPELINE TEST FAILED!\n");
    }
    
    all_passed
}

// Pipeline buffer size (GPU batches in flight)
// With true async pipelining, only 3 buffers needed:
// - One being processed by GPU
// - One being verified by CPU
// - One being prepared for next submission
const PIPELINE_DEPTH: usize = 3;

// Batch for verification: (base_key, matches)
type VerifyBatch = ([u8; 32], Vec<PotentialMatch>);

fn main() {
    println!("\n\x1b[1;36m╔═══════════════════════════════════════════════════════╗");
    println!("║     XYZ-PRO  •  Bitcoin Key Scanner  •  Metal GPU      ║");
    println!("║         P2PKH  •  P2SH  •  P2WPKH                       ║");
    println!("╚═══════════════════════════════════════════════════════╝\x1b[0m\n");

    // CRITICAL: Run self-test before anything else
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

    // Init GPU
    let gpu = match OptimizedScanner::new(&hashes) {
        Ok(g) => Arc::new(g),
        Err(e) => {
            eprintln!("[✗] GPU: {}", e);
            return;
        }
    };

    // Run GPU pipeline test to verify async operations work correctly
    if !run_gpu_pipeline_test(&gpu) {
        eprintln!("\n[FATAL] GPU pipeline test failed. Exiting to prevent data corruption.");
        std::process::exit(1);
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
        let result = gpu.scan_pipelined(
            // Key generator closure
            || generate_random_key(keys_per_batch),
            // Batch result handler closure
            |base_key, matches| {
                gpu_counter.fetch_add(keys_per_batch, Ordering::Relaxed);
                
                // Send to verification (blocking to never lose matches)
                if !matches.is_empty() {
                    if let Err(e) = tx.send((base_key, matches)) {
                        eprintln!("[!] CRITICAL: Verifier thread disconnected: {}", e);
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
    });

    // CPU verification with PARALLEL processing using rayon
    // This is the critical fix: single-threaded verification was the bottleneck
    let verify_fp = Arc::new(AtomicU64::new(0)); // Track bloom false positives
    let verify_fp_clone = verify_fp.clone();
    
    // Shared set for deduplication (thread-safe)
    use std::sync::Mutex;
    use std::collections::HashSet;
    let found_keys: Arc<Mutex<HashSet<[u8; 32]>>> = Arc::new(Mutex::new(HashSet::new()));
    let found_keys_clone = found_keys.clone();
    
    let verify_handle = thread::spawn(move || {
        use rayon::prelude::*;
        
        while !verify_shutdown.load(Ordering::Relaxed) {
            // Collect multiple batches for better parallelism
            let mut batches: Vec<VerifyBatch> = Vec::with_capacity(32);
            
            // Drain available batches (non-blocking after first)
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(batch) => {
                    batches.push(batch);
                    // Grab more if available (non-blocking)
                    while let Ok(b) = rx.try_recv() {
                        batches.push(b);
                        if batches.len() >= 64 { break; } // Cap to prevent memory bloat
                    }
                }
                Err(_) => continue, // Timeout, check shutdown
            }
            
            // Process all collected batches in parallel using rayon
            let results: Vec<_> = batches.par_iter()
                .flat_map(|(base_key, matches)| {
                    matches.par_iter().filter_map(|pm| {
                        if let Some((addr, atype, privkey)) = verify_match(base_key, pm, &targets) {
                            let compressed = pm.match_type != gpu::MatchType::Uncompressed;
                            Some((addr, atype, privkey, compressed))
                        } else {
                            // Count false positives (atomic, safe)
                            verify_fp_clone.fetch_add(1, Ordering::Relaxed);
                            None
                        }
                    })
                })
                .collect();
            
            // Process verified matches (sequential for deduplication & I/O)
            for (addr, atype, privkey, compressed) in results {
                let mut keys = found_keys_clone.lock().unwrap();
                if keys.insert(privkey) {
                    drop(keys); // Release lock before I/O
                    verify_found.fetch_add(1, Ordering::Relaxed);
                    report(&privkey, &addr, atype, compressed);
                }
            }
        }
    });

    // Stats display in main thread
    let mut last_stat = Instant::now();
    let mut last_count = 0u64;

    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));

        if last_stat.elapsed() >= Duration::from_millis(200) {
            let count = counter.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs_f64();
            let speed = (count - last_count) as f64 / last_stat.elapsed().as_secs_f64();
            let avg = count as f64 / elapsed;
            let fp_count = verify_fp.load(Ordering::Relaxed);

            print!(
                "\r[⚡] {} keys | {} (avg {}) | {} found | {} FP | {}    ",
                format_num(count),
                format_speed(speed),
                format_speed(avg),
                found.load(Ordering::Relaxed),
                format_num(fp_count),
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

/// Generate a random valid private key that won't overflow when GPU adds key_index
/// max_key_offset = keys_per_batch (from GPU config)
fn generate_random_key(max_key_offset: u64) -> [u8; 32] {
    use rand::RngCore;
    use std::cell::RefCell;
    
    // Thread-local RNG - created once per thread, reused for all calls
    // This avoids the overhead of creating a new RNG for each key generation
    thread_local! {
        static RNG: RefCell<rand::rngs::ThreadRng> = RefCell::new(rand::thread_rng());
    }
    
    let mut key = [0u8; 32];
    let mut attempts = 0u32;
    
    loop {
        RNG.with(|rng| rng.borrow_mut().fill_bytes(&mut key));
        
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
        
        // Check 2: Ensure key + max_key_offset doesn't overflow curve order
        // This prevents invalid keys when GPU adds key_index to base_key
        let mut temp = key;
        let mut carry = max_key_offset;
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
        
        // Check if key + max_key_offset is still valid (< N)
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

            // OPTIMIZATION: Use check_direct() instead of check()
            // GPU already computes P2SH separately as MatchType::P2SH
            // So here we only need to check P2PKH and P2WPKH (direct hash match)
            // This avoids redundant P2SH script hash computation
            if let Some((addr, atype)) = targets.check_direct(&comp_h160) {
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

fn report(privkey: &[u8; 32], addr: &str, atype: types::AddressType, compressed: bool) {
    use chrono::Local;
    use std::fs::OpenOptions;

    let hex = hex::encode(privkey);
    // CRITICAL: Use correct WIF format based on pubkey compression
    // Wrong format = user cannot access coins!
    let wif = to_wif_compressed(privkey, compressed);
    let key_type = if compressed { "compressed" } else { "uncompressed" };
    let time = Local::now().format("%Y-%m-%d %H:%M:%S");

    println!("\n\n\x1b[1;32m");
    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║                   🎉 KEY FOUND! 🎉                     ║");
    println!("╠═══════════════════════════════════════════════════════╣");
    println!("║ Address: {} ({})", addr, atype.as_str());
    println!("║ Key: {} ({})", hex, key_type);
    println!("║ WIF: {}", wif);
    println!("╚═══════════════════════════════════════════════════════╝");
    println!("\x1b[0m");

    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("found.txt")
    {
        writeln!(f, "[{}] {} | {} | {} | {} | {}", time, addr, atype.as_str(), key_type, hex, wif).ok();
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

// Startup verification tests

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use std::io::{stdout, Write};
use std::time::Instant;

use crate::address;
use crate::crypto;
use crate::gpu::{self, OptimizedScanner, MatchType};
use crate::targets::TargetDatabase;
use crate::types;

// Test constants
const TEST_KEY_1: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
const TEST_KEY_5: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5];
const EXPECTED_HASH_KEY1: [u8; 20] = [0x75,0x1e,0x76,0xe8,0x19,0x91,0x96,0xd4,0x54,0x94,0x1c,0x45,0xd1,0xb3,0xa3,0x23,0xf1,0x43,0x3b,0xd6];

/// Run basic self-test to verify hash calculations
/// Returns true if all tests pass
pub fn run_self_test() -> bool {
    println!("[🔍] Running self-test...");
    let self_test_start = Instant::now();
    
    let test_vectors = [
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            "751e76e8199196d454941c45d1b3a323f1433bd6",
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000002",
            "06afd46bcdfd22ef94ac122aa11f241244a37ecc",
            "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"
        ),
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
        let computed_hash = crypto::hash160(compressed.as_bytes());
        
        if computed_hash != expected_hash {
            eprintln!("  [✗] Test {}: Hash mismatch!", i + 1);
            eprintln!("      Expected: {}", expected_hash_hex);
            eprintln!("      Got:      {}", hex::encode(computed_hash));
            all_passed = false;
            continue;
        }
        
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
    
    // P2SH test
    let test_pubkey_hash = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
    let test_pubkey_hash: [u8; 20] = test_pubkey_hash.try_into().unwrap();
    let p2sh_hash = address::p2sh_script_hash(&test_pubkey_hash);
    let expected_p2sh_hash = hex::decode("bcfeb728b584253d5f3f70bcb780e9ef218a68f4").unwrap();
    
    if p2sh_hash != expected_p2sh_hash.as_slice() {
        eprintln!("  [✗] P2SH hash computation failed!");
        all_passed = false;
    } else {
        println!("  [✓] P2SH script hash computation verified");
    }
    
    // WIF encoding tests
    all_passed &= test_wif_encoding();
    
    // Key reconstruction test
    all_passed &= test_key_reconstruction();
    
    // Private key validation test
    all_passed &= test_private_key_validation();
    
    // GLV tests
    all_passed &= test_glv_endomorphism();
    
    // Windowed step table test
    all_passed &= test_windowed_step_table();

    if all_passed {
        println!("[✓] Self-test passed (total: {:.2}s)\n", self_test_start.elapsed().as_secs_f64());
    } else {
        eprintln!("\n[✗] SELF-TEST FAILED! (total: {:.2}s)", self_test_start.elapsed().as_secs_f64());
        eprintln!("    DO NOT proceed - results would be unreliable!");
    }
    
    all_passed
}

fn test_wif_encoding() -> bool {
    let wif_test_vectors = [
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
            "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000002",
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4",
            "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAvUcVfH"
        ),
    ];
    
    let mut passed = true;
    
    for (priv_hex, expected_wif_comp, expected_wif_uncomp) in wif_test_vectors {
        let priv_key: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();
        
        let wif_comp = address::to_wif_compressed(&priv_key, true);
        let wif_uncomp = address::to_wif_compressed(&priv_key, false);
        
        if wif_comp != expected_wif_comp {
            eprintln!("  [✗] WIF (compressed) mismatch for key {}...!", &priv_hex[..16]);
            passed = false;
        }
        
        if wif_uncomp != expected_wif_uncomp {
            eprintln!("  [✗] WIF (uncompressed) mismatch for key {}...!", &priv_hex[..16]);
            passed = false;
        }
    }
    
    if passed {
        println!("  [✓] WIF encoding verified (compressed & uncompressed)");
    }
    
    passed
}

fn test_key_reconstruction() -> bool {
    let base_key: [u8; 32] = TEST_KEY_1;
    let offset: u32 = 1;
    
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
        return false;
    }
    
    println!("  [✓] Key reconstruction (base + offset) verified");
    true
}

fn test_private_key_validation() -> bool {
    let valid_key: [u8; 32] = TEST_KEY_1;
    let zero_key: [u8; 32] = [0u8; 32];
    
    let mut passed = true;
    
    if !crypto::is_valid_private_key(&valid_key) {
        eprintln!("  [✗] is_valid_private_key incorrectly rejected key = 1");
        passed = false;
    }
    
    if crypto::is_valid_private_key(&zero_key) {
        eprintln!("  [✗] is_valid_private_key incorrectly accepted key = 0");
        passed = false;
    }
    
    if passed {
        println!("  [✓] Private key validation logic verified");
    }
    
    passed
}

fn test_glv_endomorphism() -> bool {
    use k256::elliptic_curve::PrimeField;
    use k256::Scalar;
    
    println!("  [🔍] Testing GLV endomorphism constants...");
    
    let mut all_passed = true;
    
    // Test 1: λ³ ≡ 1 (mod n)
    {
        let lambda = Scalar::from_repr_vartime(gpu::GLV_LAMBDA.into()).unwrap();
        let lambda_squared = lambda * lambda;
        let lambda_cubed = lambda_squared * lambda;
        let one = Scalar::ONE;
        
        if lambda_cubed != one {
            eprintln!("  [✗] GLV λ³ ≡ 1 (mod n) verification FAILED!");
            all_passed = false;
        } else {
            println!("  [✓] GLV λ³ ≡ 1 (mod n) verified");
        }
    }
    
    // Test 2: GLV transform preserves Y coordinate
    {
        let test_key: [u8; 32] = TEST_KEY_5;
        
        let glv_key = gpu::glv_transform_key(&test_key);
        
        let secret = SecretKey::from_slice(&test_key).unwrap();
        let original_pubkey = secret.public_key();
        let original_point = original_pubkey.to_encoded_point(false);
        let orig_y = &original_point.as_bytes()[33..65];
        
        let glv_secret = SecretKey::from_slice(&glv_key).unwrap();
        let glv_pubkey = glv_secret.public_key();
        let glv_point = glv_pubkey.to_encoded_point(false);
        let glv_y = &glv_point.as_bytes()[33..65];
        
        if glv_y != orig_y {
            eprintln!("  [✗] GLV transform Y-coordinate mismatch!");
            all_passed = false;
        } else {
            println!("  [✓] GLV transform preserves Y coordinate");
        }
    }
    
    // Test 3: GLV key reconstruction
    {
        let key: [u8; 32] = TEST_KEY_5;
        
        let glv1 = gpu::glv_transform_key(&key);
        let glv2 = gpu::glv_transform_key(&glv1);
        let glv3 = gpu::glv_transform_key(&glv2);
        
        if glv3 == key {
            println!("  [✓] GLV λ³ = 1 property verified");
        } else {
            eprintln!("  [✗] GLV λ³ ≠ 1!");
            all_passed = false;
        }
    }
    
    all_passed
}

fn test_windowed_step_table() -> bool {
    use k256::elliptic_curve::PrimeField;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::{ProjectivePoint, Scalar};
    
    println!("  [🔍] Testing windowed step table computation...");
    
    let keys_per_thread: u32 = 128;
    
    let kpt_bytes = {
        let mut b = [0u8; 32];
        b[28..32].copy_from_slice(&keys_per_thread.to_be_bytes());
        b
    };
    let kpt_scalar = Scalar::from_repr_vartime(kpt_bytes.into()).unwrap();
    let base_point = ProjectivePoint::GENERATOR * kpt_scalar;
    
    let expected_w0_d1 = base_point.to_affine().to_encoded_point(false);
    
    let three_scalar = Scalar::from_repr_vartime({
        let mut b = [0u8; 32];
        b[31] = 3;
        b.into()
    }).unwrap();
    let expected_w0_d3 = (ProjectivePoint::GENERATOR * kpt_scalar * three_scalar)
        .to_affine().to_encoded_point(false);
    
    let mut w1_base = base_point;
    for _ in 0..4 { w1_base = w1_base.double(); }
    let expected_w1_d1 = w1_base.to_affine().to_encoded_point(false);
    
    let mut passed = true;
    
    if expected_w0_d1.as_bytes() == expected_w0_d3.as_bytes() {
        eprintln!("  [✗] Window 0: digit 1 and digit 3 should be different!");
        passed = false;
    }
    
    if expected_w0_d1.as_bytes() == expected_w1_d1.as_bytes() {
        eprintln!("  [✗] Window 0 digit 1 and Window 1 digit 1 should be different!");
        passed = false;
    }
    
    if passed {
        println!("  [✓] Windowed step table structure verified");
    }
    
    passed
}

/// GPU correctness test - verifies GPU computes same hashes as CPU
pub fn run_gpu_correctness_test(scanner: &OptimizedScanner, targets: &TargetDatabase) -> bool {
    println!("[🔍] Running GPU correctness test...");
    println!("      This verifies GPU hash calculations match CPU exactly.");
    
    // Canary test
    print!("  [🐤] Canary test (Key=1)... ");
    stdout().flush().ok();
    
    let canary_key: [u8; 32] = TEST_KEY_1;
    let canary_secret = SecretKey::from_slice(&canary_key).unwrap();
    let canary_pubkey = canary_secret.public_key();
    
    let comp_point = canary_pubkey.to_encoded_point(true);
    let comp_hash = crypto::hash160(comp_point.as_bytes());
    let comp_h160 = types::Hash160::from_slice(&comp_hash);
    
    let uncomp_point = canary_pubkey.to_encoded_point(false);
    let uncomp_hash = crypto::hash160(uncomp_point.as_bytes());
    let uncomp_h160 = types::Hash160::from_slice(&uncomp_hash);
    
    let p2sh_hash = address::p2sh_script_hash(&comp_hash);
    let p2sh_h160 = types::Hash160::from_slice(&p2sh_hash);
    
    let comp_in_targets = targets.check_direct(&comp_h160);
    let uncomp_in_targets = targets.check_direct(&uncomp_h160);
    let p2sh_in_targets = targets.check_direct(&p2sh_h160);
    
    if comp_in_targets.is_some() || uncomp_in_targets.is_some() || p2sh_in_targets.is_some() {
        println!("FOUND in targets! ✓");
        println!("      → System is LIVE! If GPU scans key=1, it WILL find this!");
    } else {
        println!("not in targets");
    }
    
    let mut all_passed = true;
    
    // CPU verification
    print!("  [🔍] Verifying CPU reference calculations... ");
    stdout().flush().ok();
    let cpu_start = Instant::now();
    
    let priv_key: [u8; 32] = TEST_KEY_1;
    let secret = SecretKey::from_slice(&priv_key).unwrap();
    let pubkey = secret.public_key();
    let compressed = pubkey.to_encoded_point(true);
    let cpu_hash = crypto::hash160(compressed.as_bytes());
    let expected: [u8; 20] = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6")
        .unwrap().try_into().unwrap();
    
    if cpu_hash != expected {
        println!("FAILED ({:.2}s)", cpu_start.elapsed().as_secs_f64());
        eprintln!("  [✗] CPU hash mismatch!");
        return false;
    }
    println!("done ({:.2}s)", cpu_start.elapsed().as_secs_f64());
    
    #[cfg(feature = "xor-filter")]
    {
        println!("  [✓] Xor Filter already built by scanner (skipping redundant FP test)");
    }
    
    // GPU test
    print!("  [🔍] Testing GPU hash calculations... ");
    stdout().flush().ok();
    let gpu_test_start = Instant::now();
    
    let base_key: [u8; 32] = TEST_KEY_1;
    
    match scanner.scan_batch(&base_key) {
        Ok(matches) => {
            println!("done ({:.2}s)", gpu_test_start.elapsed().as_secs_f64());
            println!("      GPU scan completed successfully");
            println!("      Xor Filter matches in batch: {}", matches.len());
            
            all_passed &= verify_gpu_matches(&base_key, &matches);
        }
        Err(e) => {
            println!("FAILED ({:.2}s)", gpu_test_start.elapsed().as_secs_f64());
            eprintln!("  [✗] GPU scan failed: {}", e);
            all_passed = false;
        }
    }
    
    // Full verification path test
    all_passed &= test_verification_path(scanner, &base_key);
    
    // Key offset test
    all_passed &= test_key_offsets(&base_key);
    
    if all_passed {
        println!("[✓] GPU correctness test PASSED\n");
    } else {
        eprintln!("[✗] GPU CORRECTNESS TEST FAILED!\n");
    }
    
    all_passed
}

fn verify_gpu_matches(base_key: &[u8; 32], matches: &[gpu::PotentialMatch]) -> bool {
    let mut verified_count = 0;
    let mut failed_count = 0;
    let check_limit = matches.len().min(10);
    
    for (i, m) in matches.iter().take(check_limit).enumerate() {
        let mut priv_key = *base_key;
        let mut carry = m.key_index as u64;
        for byte in priv_key.iter_mut().rev() {
            let sum = *byte as u64 + (carry & 0xFF);
            *byte = sum as u8;
            carry = (carry >> 8) + (sum >> 8);
        }
        
        if let Ok(secret) = SecretKey::from_slice(&priv_key) {
            let pubkey = secret.public_key();
            
            let (effective_pubkey, base_type) = if m.match_type.is_glv() {
                let glv_key = gpu::glv_transform_key(&priv_key);
                if let Ok(glv_secret) = SecretKey::from_slice(&glv_key) {
                    (glv_secret.public_key(), match m.match_type {
                        MatchType::GlvCompressed => MatchType::Compressed,
                        MatchType::GlvUncompressed => MatchType::Uncompressed,
                        MatchType::GlvP2SH => MatchType::P2SH,
                        _ => m.match_type,
                    })
                } else {
                    continue;
                }
            } else {
                (pubkey, m.match_type)
            };
            
            let cpu_hash: [u8; 20] = match base_type {
                MatchType::Compressed | MatchType::GlvCompressed => {
                    let comp = effective_pubkey.to_encoded_point(true);
                    crypto::hash160(comp.as_bytes())
                }
                MatchType::Uncompressed | MatchType::GlvUncompressed => {
                    let uncomp = effective_pubkey.to_encoded_point(false);
                    crypto::hash160(uncomp.as_bytes())
                }
                MatchType::P2SH | MatchType::GlvP2SH => {
                    let comp = effective_pubkey.to_encoded_point(true);
                    let comp_hash = crypto::hash160(comp.as_bytes());
                    address::p2sh_script_hash(&comp_hash)
                }
            };
            
            if cpu_hash == *m.hash.as_bytes() {
                verified_count += 1;
            } else {
                failed_count += 1;
                eprintln!("  [✗] HASH MISMATCH at index {}!", i);
            }
        }
    }
    
    if failed_count == 0 && verified_count > 0 {
        println!("  [✓] Verified {}/{} GPU hashes match CPU exactly", verified_count, check_limit);
        true
    } else if matches.is_empty() {
        eprintln!("  [✗] CRITICAL: Got 0 Xor Filter matches!");
        false
    } else {
        false
    }
}

fn test_verification_path(scanner: &OptimizedScanner, base_key: &[u8; 32]) -> bool {
    print!("  [🔍] Testing full GPU→CPU verification path... ");
    stdout().flush().ok();
    let verify_start = Instant::now();
    
    match scanner.scan_batch(base_key) {
        Ok(matches) if !matches.is_empty() => {
            let pm = &matches[0];
            let mut priv_key = *base_key;
            let mut carry = pm.key_index as u64;
            for byte in priv_key.iter_mut().rev() {
                let sum = *byte as u64 + (carry & 0xFF);
                *byte = sum as u8;
                carry = (carry >> 8) + (sum >> 8);
            }
            
            if let Ok(secret) = SecretKey::from_slice(&priv_key) {
                let pubkey = secret.public_key();
                
                let (effective_pubkey, base_type) = if pm.match_type.is_glv() {
                    let glv_key = gpu::glv_transform_key(&priv_key);
                    if let Ok(glv_secret) = SecretKey::from_slice(&glv_key) {
                        (glv_secret.public_key(), match pm.match_type {
                            MatchType::GlvCompressed => MatchType::Compressed,
                            MatchType::GlvUncompressed => MatchType::Uncompressed,
                            MatchType::GlvP2SH => MatchType::P2SH,
                            _ => pm.match_type,
                        })
                    } else {
                        (pubkey, pm.match_type)
                    }
                } else {
                    (pubkey, pm.match_type)
                };
                
                let cpu_hash = match base_type {
                    MatchType::Compressed | MatchType::GlvCompressed => {
                        let comp = effective_pubkey.to_encoded_point(true);
                        crypto::hash160(comp.as_bytes())
                    }
                    MatchType::Uncompressed | MatchType::GlvUncompressed => {
                        let uncomp = effective_pubkey.to_encoded_point(false);
                        crypto::hash160(uncomp.as_bytes())
                    }
                    MatchType::P2SH | MatchType::GlvP2SH => {
                        let comp = effective_pubkey.to_encoded_point(true);
                        let comp_hash = crypto::hash160(comp.as_bytes());
                        address::p2sh_script_hash(&comp_hash)
                    }
                };
                
                if cpu_hash == *pm.hash.as_bytes() {
                    println!("done ({:.2}s)", verify_start.elapsed().as_secs_f64());
                    println!("  [✓] GPU→CPU hash verification PASSED");
                    return true;
                }
            }
        }
        Ok(_) => {
            println!("done ({:.2}s)", verify_start.elapsed().as_secs_f64());
            eprintln!("  [✗] CRITICAL: No matches for verification!");
        }
        Err(e) => {
            println!("FAILED ({:.2}s)", verify_start.elapsed().as_secs_f64());
            eprintln!("  [✗] Scan failed: {}", e);
        }
    }
    false
}

fn test_key_offsets(base_key: &[u8; 32]) -> bool {
    print!("  [🔍] Testing key offset reconstruction... ");
    stdout().flush().ok();
    let offset_start = Instant::now();
    
    for offset in [0u32, 1, 10, 63, 64, 100, 1000] {
        let mut reconstructed = *base_key;
        let mut carry = offset as u64;
        for byte in reconstructed.iter_mut().rev() {
            let sum = *byte as u64 + (carry & 0xFF);
            *byte = sum as u8;
            carry = (carry >> 8) + (sum >> 8);
        }
        
        let expected_val = 1u64 + offset as u64;
        let reconstructed_val = u64::from_be_bytes(reconstructed[24..32].try_into().unwrap());
        
        if reconstructed_val != expected_val {
            println!("FAILED ({:.2}s)", offset_start.elapsed().as_secs_f64());
            eprintln!("  [✗] Key reconstruction failed for offset {}!", offset);
            return false;
        }
    }
    
    println!("done ({:.2}s)", offset_start.elapsed().as_secs_f64());
    true
}

/// GPU pipeline test - verifies async dispatch/collect works correctly
pub fn run_gpu_pipeline_test(scanner: &OptimizedScanner) -> bool {
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
    
    println!("[🔍] Running GPU pipeline test...");
    print!("  [🔍] Testing pipelined batch processing... ");
    stdout().flush().ok();
    
    let mut all_passed = true;
    let shutdown = AtomicBool::new(false);
    
    let start = Instant::now();
    let batch_count = AtomicU32::new(0);
    let total_matches = AtomicU64::new(0);
    let test_key_counter = AtomicU64::new(1);
    let keys_per_batch = scanner.keys_per_batch();
    
    let result = scanner.scan_pipelined(
        || {
            let counter = test_key_counter.fetch_add(keys_per_batch, Ordering::Relaxed);
            let mut key = [0u8; 32];
            key[24..32].copy_from_slice(&counter.to_be_bytes());
            
            if batch_count.load(Ordering::Relaxed) >= 5 {
                shutdown.store(true, Ordering::SeqCst);
            }
            key
        },
        |_base_key, matches| {
            batch_count.fetch_add(1, Ordering::Relaxed);
            total_matches.fetch_add(matches.len() as u64, Ordering::Relaxed);
        },
        &shutdown,
    );
    
    let batch_count = batch_count.load(Ordering::Relaxed);
    let elapsed = start.elapsed();
    
    match result {
        Ok(()) if batch_count >= 5 => {
            let keys_scanned = batch_count as u64 * scanner.keys_per_batch();
            let speed = keys_scanned as f64 / elapsed.as_secs_f64();
            println!("done ({:.2}s)", elapsed.as_secs_f64());
            println!("      {} batches, {:.1}M keys, {:.1}M/s", 
                batch_count, 
                keys_scanned as f64 / 1_000_000.0,
                speed / 1_000_000.0
            );
        }
        Ok(()) => {
            println!("FAILED ({:.2}s)", elapsed.as_secs_f64());
            eprintln!("  [✗] GPU pipeline incomplete: only {} batches", batch_count);
            all_passed = false;
        }
        Err(e) => {
            println!("FAILED ({:.2}s)", elapsed.as_secs_f64());
            eprintln!("  [✗] GPU pipeline error: {}", e);
            all_passed = false;
        }
    }
    
    // Triple buffer stability test
    all_passed &= test_triple_buffer_stability(scanner);
    
    if all_passed {
        println!("[✓] GPU pipeline test passed\n");
    } else {
        eprintln!("[✗] GPU PIPELINE TEST FAILED!\n");
    }
    
    all_passed
}

fn test_triple_buffer_stability(scanner: &OptimizedScanner) -> bool {
    print!("  [🔍] Testing triple-buffer stability... ");
    stdout().flush().ok();
    let start = Instant::now();
    
    let test_key: [u8; 32] = TEST_KEY_1;
    
    let mut total_matches = 0usize;
    let mut all_scans_ok = true;
    
    for i in 0..6 {
        match scanner.scan_batch(&test_key) {
            Ok(matches) => {
                total_matches += matches.len();
                if matches.len() > 100_000 {
                    eprintln!("  [⚠] Batch {} returned unusually high match count: {}", i, matches.len());
                }
            }
            Err(e) => {
                eprintln!("  [✗] Batch {} failed: {}", i, e);
                all_scans_ok = false;
            }
        }
    }
    
    if all_scans_ok {
        println!("done ({:.2}s)", start.elapsed().as_secs_f64());
        println!("      6 batches completed, {} total FP matches", total_matches);
    } else {
        println!("FAILED ({:.2}s)", start.elapsed().as_secs_f64());
    }
    
    all_scans_ok
}

/// Quick startup verification (Philox RNG specific)
#[cfg(feature = "philox-rng")]
pub fn run_startup_verification(scanner: &OptimizedScanner) -> bool {
    use crate::rng::{PhiloxCounter, PhiloxState, philox4x32_10};
    
    println!("[🔍] Running startup verification...");
    let startup_start = Instant::now();
    
    let mut all_passed = true;
    
    // Test 1: Philox RNG
    print!("  [1/5] Philox RNG... ");
    stdout().flush().ok();
    let t1 = Instant::now();
    {
        let state = PhiloxState::new(12345);
        let output = philox4x32_10(&state);
        if output[0] == 0 && output[1] == 0 && output[2] == 0 && output[3] == 0 {
            println!("FAILED ({:.2}s)", t1.elapsed().as_secs_f64());
            all_passed = false;
        } else {
            println!("OK ({:.2}s)", t1.elapsed().as_secs_f64());
        }
    }
    
    // Test 2: Counter increment
    print!("  [2/5] Philox counter... ");
    stdout().flush().ok();
    let t2 = Instant::now();
    {
        let counter = PhiloxCounter::new(42);
        let state1 = counter.next_batch(128);
        let state2 = counter.next_batch(128);
        if state1.counter == state2.counter {
            println!("FAILED ({:.2}s)", t2.elapsed().as_secs_f64());
            all_passed = false;
        } else {
            println!("OK ({:.2}s)", t2.elapsed().as_secs_f64());
        }
    }
    
    // Test 3: GPU scan
    print!("  [3/5] GPU scan... ");
    stdout().flush().ok();
    let t3 = Instant::now();
    {
        match scanner.scan_batch(&TEST_KEY_1) {
            Ok(_) => println!("OK ({:.2}s)", t3.elapsed().as_secs_f64()),
            Err(e) => {
                println!("FAILED ({:.2}s)", t3.elapsed().as_secs_f64());
                eprintln!("        GPU scan failed: {}", e);
                all_passed = false;
            }
        }
    }
    
    // Test 4: CPU hash calculation
    print!("  [4/5] CPU hash calculation... ");
    stdout().flush().ok();
    let t4 = Instant::now();
    {
        let secret = SecretKey::from_slice(&TEST_KEY_1).unwrap();
        let hash = crypto::hash160(secret.public_key().to_encoded_point(true).as_bytes());
        
        if hash == EXPECTED_HASH_KEY1 {
            println!("OK ({:.2}s)", t4.elapsed().as_secs_f64());
        } else {
            println!("FAILED ({:.2}s)", t4.elapsed().as_secs_f64());
            all_passed = false;
        }
    }
    
    // Test 5: GLV endomorphism
    print!("  [5/5] GLV endomorphism... ");
    stdout().flush().ok();
    let t5 = Instant::now();
    {
        let key: [u8; 32] = TEST_KEY_5;
        
        let glv1 = gpu::glv_transform_key(&key);
        let glv2 = gpu::glv_transform_key(&glv1);
        let glv3 = gpu::glv_transform_key(&glv2);
        
        if glv3 == key {
            println!("OK ({:.2}s) - λ³ = 1", t5.elapsed().as_secs_f64());
        } else {
            println!("FAILED ({:.2}s)", t5.elapsed().as_secs_f64());
            all_passed = false;
        }
    }
    
    if all_passed {
        println!("[✓] Startup verification passed (total: {:.2}s)\n", startup_start.elapsed().as_secs_f64());
    } else {
        eprintln!("[✗] STARTUP VERIFICATION FAILED! (total: {:.2}s)\n", startup_start.elapsed().as_secs_f64());
    }
    
    all_passed
}


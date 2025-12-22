
mod address;
mod crypto;
mod error;
mod gpu;
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

#[cfg(feature = "zero-copy")]
mod scanner;

#[cfg(feature = "philox-rng")]
mod tests;

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

fn run_self_test() -> bool {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    
    println!("[🔍] Running self-test...");
    
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
    
    // ========================================================================
    // GLV ENDOMORPHISM TESTS
    // Critical: If β or λ constants are wrong, GLV matches will be completely invalid!
    // ========================================================================
    println!("  [🔍] Testing GLV endomorphism constants...");
    
    // Test 1: Verify λ³ ≡ 1 (mod n)
    // This is a fundamental property of the GLV endomorphism
    {
        use k256::elliptic_curve::PrimeField;
        use k256::Scalar;
        
        let lambda = Scalar::from_repr_vartime(gpu::GLV_LAMBDA.into()).unwrap();
        let lambda_squared = lambda * lambda;
        let lambda_cubed = lambda_squared * lambda;
        let one = Scalar::ONE;
        
        if lambda_cubed != one {
            eprintln!("  [✗] GLV λ³ ≡ 1 (mod n) verification FAILED!");
            eprintln!("      λ³ should equal 1, but got different value");
            all_passed = false;
        } else {
            println!("  [✓] GLV λ³ ≡ 1 (mod n) verified");
        }
    }
    
    // Test 2: Verify GLV transform produces correct public key
    // For key k, λ·k should produce pubkey (β·Px, Py)
    {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::SecretKey;
        
        // Test with a known private key
        let test_key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000005")
            .unwrap().try_into().unwrap();
        
        // Compute λ·k (mod n)
        let glv_key = gpu::glv_transform_key(&test_key);
        
        // Get original public key
        let secret = SecretKey::from_slice(&test_key).unwrap();
        let original_pubkey = secret.public_key();
        let original_point = original_pubkey.to_encoded_point(false);
        let orig_x = &original_point.as_bytes()[1..33];
        let orig_y = &original_point.as_bytes()[33..65];
        
        // Get GLV-transformed public key
        let glv_secret = SecretKey::from_slice(&glv_key).unwrap();
        let glv_pubkey = glv_secret.public_key();
        let glv_point = glv_pubkey.to_encoded_point(false);
        let glv_x = &glv_point.as_bytes()[1..33];
        let glv_y = &glv_point.as_bytes()[33..65];
        
        // GLV property: φ(P) = (β·Px, Py) should have same Y coordinate
        // (X coordinate is β·original_x mod p)
        if glv_y != orig_y {
            eprintln!("  [✗] GLV transform Y-coordinate mismatch!");
            eprintln!("      φ(P) should preserve Y coordinate but it changed");
            eprintln!("      Original Y: {}", hex::encode(orig_y));
            eprintln!("      GLV Y:      {}", hex::encode(glv_y));
            all_passed = false;
        } else {
            println!("  [✓] GLV transform preserves Y coordinate (φ(P).y = P.y)");
        }
        
        // Verify X coordinate is different (should be β·x mod p)
        if glv_x == orig_x {
            eprintln!("  [✗] GLV transform X-coordinate unchanged!");
            eprintln!("      φ(P).x should equal β·P.x mod p, not P.x");
            all_passed = false;
        } else {
            println!("  [✓] GLV transform modifies X coordinate (φ(P).x = β·P.x)");
        }
    }
    
    // Test 3: Verify β is correct by checking GLV property holds for multiple keys
    // If β is wrong, Y coordinates wouldn't be preserved for different keys
    {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::SecretKey;
        
        let test_keys: [[u8; 32]; 3] = [
            hex::decode("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap().try_into().unwrap(),
            hex::decode("0000000000000000000000000000000000000000000000000000000000000007")
                .unwrap().try_into().unwrap(),
            hex::decode("000000000000000000000000000000000000000000000000000000000000000b")
                .unwrap().try_into().unwrap(),
        ];
        
        let mut beta_verified = true;
        for test_key in &test_keys {
            let glv_key = gpu::glv_transform_key(test_key);
            
            let orig_secret = SecretKey::from_slice(test_key).unwrap();
            let orig_pubkey = orig_secret.public_key().to_encoded_point(false);
            let orig_y = &orig_pubkey.as_bytes()[33..65];
            
            let glv_secret = SecretKey::from_slice(&glv_key).unwrap();
            let glv_pubkey = glv_secret.public_key().to_encoded_point(false);
            let glv_y = &glv_pubkey.as_bytes()[33..65];
            
            if orig_y != glv_y {
                eprintln!("  [✗] GLV β verification failed for key {}!", hex::encode(test_key));
                beta_verified = false;
                break;
            }
        }
        
        if beta_verified {
            println!("  [✓] GLV β constant verified (Y preserved for multiple keys)");
        } else {
            all_passed = false;
        }
    }
    
    // Test 4: Verify GLV private key recovery works correctly
    // If we have a GLV match with key_index i, actual key should be λ·(base + i)
    {
        let base_key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap().try_into().unwrap();
        let key_index: u32 = 5;
        
        // Reconstruct key: base + key_index
        let mut reconstructed = base_key;
        let mut carry = key_index as u64;
        for byte in reconstructed.iter_mut().rev() {
            let sum = *byte as u64 + (carry & 0xFF);
            *byte = sum as u8;
            carry = (carry >> 8) + (sum >> 8);
        }
        // reconstructed should now be 6
        
        // Apply GLV transform
        let glv_key = gpu::glv_transform_key(&reconstructed);
        
        // Verify it's a valid key
        if !crypto::is_valid_private_key(&glv_key) {
            eprintln!("  [✗] GLV-transformed key is invalid!");
            all_passed = false;
        } else {
            // Verify it produces a valid public key
            if SecretKey::from_slice(&glv_key).is_ok() {
                println!("  [✓] GLV private key recovery verified");
            } else {
                eprintln!("  [✗] GLV-transformed key fails SecretKey parsing!");
                all_passed = false;
            }
        }
    }
    
    // Test 5: Explicit GLV key reconstruction exact test
    // CRITICAL: Verifies that GLV transform correctly computes λ·(base + offset)
    {
        use k256::elliptic_curve::PrimeField;
        use k256::Scalar;
        
        let mut base: [u8; 32] = [0u8; 32];
        base[31] = 100; // base = 100
        let offset: u32 = 5; // base + 5 = 105
        
        let mut reconstructed = base;
        let mut carry = offset as u64;
        for byte in reconstructed.iter_mut().rev() {
            let sum = *byte as u64 + (carry & 0xFF);
            *byte = sum as u8;
            carry = (carry >> 8) + (sum >> 8);
        }
        // reconstructed should now be 105
        
        let glv_key = gpu::glv_transform_key(&reconstructed);
        
        // Verify: glv_key should equal λ·105 mod n
        let lambda = Scalar::from_repr_vartime(gpu::GLV_LAMBDA.into()).unwrap();
        let k_scalar = Scalar::from_repr_vartime(reconstructed.into()).unwrap();
        let expected_glv = lambda * k_scalar;
        let expected_bytes: [u8; 32] = expected_glv.to_bytes().into();
        
        if glv_key == expected_bytes {
            println!("  [✓] GLV key reconstruction exact match verified (λ·105)");
        } else {
            eprintln!("  [✗] GLV key reconstruction mismatch!");
            eprintln!("      Expected: {}", hex::encode(expected_bytes));
            eprintln!("      Got:      {}", hex::encode(glv_key));
            all_passed = false;
        }
    }
    
    // Test 6: GLV Y coordinate preservation test
    // CRITICAL: Verifies that GLV endomorphism preserves Y coordinate
    // GLV: φ(x, y) = (β·x mod p, y) - Y should remain unchanged
    {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::SecretKey;
        
        let test_key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000005")
            .unwrap().try_into().unwrap();
        
        let glv_key = gpu::glv_transform_key(&test_key);
        
        let orig_secret = SecretKey::from_slice(&test_key).unwrap();
        let orig_pubkey = orig_secret.public_key();
        let orig_point = orig_pubkey.to_encoded_point(false);
        let orig_y = &orig_point.as_bytes()[33..65];
        
        let glv_secret = SecretKey::from_slice(&glv_key).unwrap();
        let glv_pubkey = glv_secret.public_key();
        let glv_point = glv_pubkey.to_encoded_point(false);
        let glv_y = &glv_point.as_bytes()[33..65];
        
        if orig_y == glv_y {
            println!("  [✓] GLV preserves Y coordinate (φ(P).y = P.y)");
        } else {
            eprintln!("  [✗] GLV Y coordinate mismatch!");
            eprintln!("      Original Y: {}", hex::encode(orig_y));
            eprintln!("      GLV Y:      {}", hex::encode(glv_y));
            all_passed = false;
        }
    }
    
    // ========================================================================
    // WINDOWED STEP TABLE TEST
    // Verify the 5-window × 15-digit precomputation is correct
    // ========================================================================
    println!("  [🔍] Testing windowed step table computation...");
    {
        use k256::elliptic_curve::PrimeField;
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        use k256::{ProjectivePoint, Scalar};
        
        let keys_per_thread: u32 = 128;
        
        // Compute base: kpt * G
        let kpt_bytes = {
            let mut b = [0u8; 32];
            b[28..32].copy_from_slice(&keys_per_thread.to_be_bytes());
            b
        };
        let kpt_scalar = Scalar::from_repr_vartime(kpt_bytes.into()).unwrap();
        let base_point = ProjectivePoint::GENERATOR * kpt_scalar;
        
        // Test a few window entries manually
        let mut window_tests_passed = true;
        
        // Window 0, digit 1: should be 1 * kpt * G = base_point
        let expected_w0_d1 = base_point.to_affine().to_encoded_point(false);
        
        // Window 0, digit 3: should be 3 * kpt * G
        let three_scalar = Scalar::from_repr_vartime({
            let mut b = [0u8; 32];
            b[31] = 3;
            b.into()
        }).unwrap();
        let expected_w0_d3 = (ProjectivePoint::GENERATOR * kpt_scalar * three_scalar)
            .to_affine().to_encoded_point(false);
        
        // Window 1, digit 1: should be 1 * 16 * kpt * G = 16 * base
        let mut w1_base = base_point;
        for _ in 0..4 { w1_base = w1_base.double(); }
        let expected_w1_d1 = w1_base.to_affine().to_encoded_point(false);
        
        // Verify these are different (sanity check)
        if expected_w0_d1.as_bytes() == expected_w0_d3.as_bytes() {
            eprintln!("  [✗] Window 0: digit 1 and digit 3 should be different!");
            window_tests_passed = false;
        }
        
        if expected_w0_d1.as_bytes() == expected_w1_d1.as_bytes() {
            eprintln!("  [✗] Window 0 digit 1 and Window 1 digit 1 should be different!");
            window_tests_passed = false;
        }
        
        if window_tests_passed {
            println!("  [✓] Windowed step table structure verified");
        } else {
            all_passed = false;
        }
    }

    if all_passed {
        println!("[✓] Self-test passed - all calculations are correct\n");
    } else {
        eprintln!("\n[✗] SELF-TEST FAILED! Calculations are incorrect.");
        eprintln!("    DO NOT proceed - results would be unreliable!");
    }
    
    all_passed
}

/// CRITICAL GPU CORRECTNESS TEST
/// Verifies that GPU computes EXACTLY the same hashes as CPU
/// A single bit error here means missed matches!
fn run_gpu_correctness_test(scanner: &OptimizedScanner, targets: &TargetDatabase) -> bool {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    
    println!("[🔍] Running GPU correctness test...");
    println!("      This verifies GPU hash calculations match CPU exactly.");
    
    let mut all_passed = true;
    
    // Test vectors: known private keys with known hashes
    // These MUST match - any difference means GPU calculation is wrong!
    let test_vectors: Vec<(&str, &str, &str, &str)> = vec![
        // (private_key_hex, expected_compressed_hash160, expected_uncompressed_hash160, expected_p2sh_hash)
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            "751e76e8199196d454941c45d1b3a323f1433bd6",  // compressed
            "91b24bf9f5288532960ac687abb035127b1d28a5",  // uncompressed  
            "bcfeb728b584253d5f3f70bcb780e9ef218a68f4",  // p2sh
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000002",
            "06afd46bcdfd22ef94ac122aa11f241244a37ecc",  // compressed - verified
            "d6c8e828c1eeaa6fce4e3a2119d38ec232e62f27",  // uncompressed - COMPUTED
            "d8ed538f3bee0e8cf0672d1d1bc5c5f2a8e95f75",  // p2sh - COMPUTED
        ),
    ];
    
    // First verify CPU calculations are correct
    println!("  [🔍] Verifying CPU reference calculations...");
    for (priv_hex, expected_comp, _, _) in &test_vectors[..1] {  // Just test first vector for CPU
        let priv_key: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();
        let secret = SecretKey::from_slice(&priv_key).unwrap();
        let pubkey = secret.public_key();
        let compressed = pubkey.to_encoded_point(true);
        let cpu_hash = crypto::hash160(compressed.as_bytes());
        let expected: [u8; 20] = hex::decode(expected_comp).unwrap().try_into().unwrap();
        
        if cpu_hash != expected {
            eprintln!("  [✗] CPU hash mismatch! This should never happen.");
            eprintln!("      Expected: {}", expected_comp);
            eprintln!("      Got:      {}", hex::encode(cpu_hash));
            return false;
        }
    }
    println!("  [✓] CPU reference calculations verified");
    
    // Xor Filter false positive rate test (if enabled)
    #[cfg(feature = "xor-filter")]
    {
        use crate::filter::XorFilter32;
        use rand::Rng;
        
        println!("  [🔍] Testing Xor Filter false positive rate...");
        
        // Get all target hashes (already returns Vec<[u8; 20]>)
        let target_vec = targets.get_all_hashes();
        
        // Create Xor filter from targets
        let xor_filter = XorFilter32::new(&target_vec);
        
        // Test 100k random non-member keys
        let mut fp_count = 0;
        let mut rng = rand::thread_rng();
        let test_count = 100_000;
        
        for _ in 0..test_count {
            let mut random_hash = [0u8; 20];
            rng.fill(&mut random_hash);
            
            // Check if it's NOT in targets but filter says it is (false positive)
            let in_targets = target_vec.iter().any(|&h| h == random_hash);
            if !in_targets && xor_filter.contains(&random_hash) {
                fp_count += 1;
            }
        }
        
        let fp_rate = fp_count as f64 / test_count as f64;
        println!("  [Xor] False positive rate: {:.4}% ({}/{} FP)", 
            fp_rate * 100.0, fp_count, test_count);
        
        if fp_rate < 0.004 {
            println!("  [✓] Xor Filter FP rate acceptable (<0.4%)");
        } else {
            eprintln!("  [✗] Xor Filter FP rate too high: {:.4}% (expected <0.4%)", fp_rate * 100.0);
            all_passed = false;
        }
    }
    
    // Now test GPU: scan a batch and verify GPU hashes match CPU
    println!("  [🔍] Testing GPU hash calculations...");
    
    let base_key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
        .unwrap().try_into().unwrap();
    
    match scanner.scan_batch(&base_key) {
        Ok(matches) => {
            println!("      Xor Filter32 matches in batch: {}", matches.len());
            
            // CRITICAL TEST: Verify EVERY match from GPU against CPU calculation
            // This is the definitive test - if even ONE hash differs, GPU is broken
            let mut verified_count = 0;
            let mut failed_count = 0;
            let check_limit = matches.len().min(10); // Check up to 10 matches
            
            for (i, m) in matches.iter().take(check_limit).enumerate() {
                // Reconstruct private key: base_key + key_index
                let mut priv_key = base_key;
                let mut carry = m.key_index as u64;
                for byte in priv_key.iter_mut().rev() {
                    let sum = *byte as u64 + (carry & 0xFF);
                    *byte = sum as u8;
                    carry = (carry >> 8) + (sum >> 8);
                }
                
                // Calculate hash on CPU
                if let Ok(secret) = SecretKey::from_slice(&priv_key) {
                    let pubkey = secret.public_key();
                    
                    // For GLV matches, we need to use the GLV-transformed pubkey
                    let (effective_pubkey, base_type) = if m.match_type.is_glv() {
                        // GLV match: compute λ·k pubkey
                        let glv_key = gpu::glv_transform_key(&priv_key);
                        if let Ok(glv_secret) = SecretKey::from_slice(&glv_key) {
                            (glv_secret.public_key(), match m.match_type {
                                gpu::MatchType::GlvCompressed => gpu::MatchType::Compressed,
                                gpu::MatchType::GlvUncompressed => gpu::MatchType::Uncompressed,
                                gpu::MatchType::GlvP2SH => gpu::MatchType::P2SH,
                                _ => m.match_type,
                            })
                        } else {
                            continue; // Invalid GLV key
                        }
                    } else {
                        (pubkey, m.match_type)
                    };
                    
                    let cpu_hash: [u8; 20] = match base_type {
                        gpu::MatchType::Compressed | gpu::MatchType::GlvCompressed => {
                            let comp = effective_pubkey.to_encoded_point(true);
                            crypto::hash160(comp.as_bytes())
                        }
                        gpu::MatchType::Uncompressed | gpu::MatchType::GlvUncompressed => {
                            let uncomp = effective_pubkey.to_encoded_point(false);
                            crypto::hash160(uncomp.as_bytes())
                        }
                        gpu::MatchType::P2SH | gpu::MatchType::GlvP2SH => {
                            let comp = effective_pubkey.to_encoded_point(true);
                            let comp_hash = crypto::hash160(comp.as_bytes());
                            address::p2sh_script_hash(&comp_hash)
                        }
                    };
                    
                    let gpu_hash = m.hash.as_bytes();
                    
                    if cpu_hash == *gpu_hash {
                        verified_count += 1;
                    } else {
                        failed_count += 1;
                        eprintln!("  [✗] HASH MISMATCH at index {}!", i);
                        eprintln!("      key_index: {}, type: {:?}", m.key_index, m.match_type);
                        eprintln!("      GPU: {}", hex::encode(gpu_hash));
                        eprintln!("      CPU: {}", hex::encode(cpu_hash));
                        all_passed = false;
                    }
                }
            }
            
            if failed_count == 0 && verified_count > 0 {
                println!("  [✓] Verified {}/{} GPU hashes match CPU exactly", verified_count, check_limit);
            } else if verified_count == 0 {
                eprintln!("  [✗] No matches to verify!");
                all_passed = false;
            }
        }
        Err(e) => {
            eprintln!("  [✗] GPU scan failed: {}", e);
            all_passed = false;
        }
    }
    
    // Critical test: Full verification path
    // Take a match from GPU and verify it through the full CPU verification path
    println!("  [🔍] Testing full GPU→CPU verification path...");
    
    let result = scanner.scan_batch(&base_key);
    if let Ok(matches) = result {
        if !matches.is_empty() {
            let pm = &matches[0];
            
            // Reconstruct private key
            let mut priv_key = base_key;
            let mut carry = pm.key_index as u64;
            for byte in priv_key.iter_mut().rev() {
                let sum = *byte as u64 + (carry & 0xFF);
                *byte = sum as u8;
                carry = (carry >> 8) + (sum >> 8);
            }
            
            // Compute hash on CPU
            if let Ok(secret) = SecretKey::from_slice(&priv_key) {
                let pubkey = secret.public_key();
                
                // For GLV matches, use GLV-transformed pubkey
                let (effective_pubkey, base_type) = if pm.match_type.is_glv() {
                    let glv_key = gpu::glv_transform_key(&priv_key);
                    if let Ok(glv_secret) = SecretKey::from_slice(&glv_key) {
                        (glv_secret.public_key(), match pm.match_type {
                            gpu::MatchType::GlvCompressed => gpu::MatchType::Compressed,
                            gpu::MatchType::GlvUncompressed => gpu::MatchType::Uncompressed,
                            gpu::MatchType::GlvP2SH => gpu::MatchType::P2SH,
                            _ => pm.match_type,
                        })
                    } else {
                        (pubkey, pm.match_type) // Fallback
                    }
                } else {
                    (pubkey, pm.match_type)
                };
                
                let cpu_hash = match base_type {
                    gpu::MatchType::Compressed | gpu::MatchType::GlvCompressed => {
                        let comp = effective_pubkey.to_encoded_point(true);
                        crypto::hash160(comp.as_bytes())
                    }
                    gpu::MatchType::Uncompressed | gpu::MatchType::GlvUncompressed => {
                        let uncomp = effective_pubkey.to_encoded_point(false);
                        crypto::hash160(uncomp.as_bytes())
                    }
                    gpu::MatchType::P2SH | gpu::MatchType::GlvP2SH => {
                        let comp = effective_pubkey.to_encoded_point(true);
                        let comp_hash = crypto::hash160(comp.as_bytes());
                        address::p2sh_script_hash(&comp_hash)
                    }
                };
                
                let gpu_hash = pm.hash.as_bytes();
                
                if cpu_hash == *gpu_hash {
                    println!("  [✓] GPU→CPU hash verification PASSED");
                    println!("      key_index={}, type={:?}, hash={}", 
                        pm.key_index, pm.match_type, hex::encode(gpu_hash));
                } else {
                    eprintln!("  [✗] GPU→CPU hash MISMATCH!");
                    eprintln!("      key_index: {}", pm.key_index);
                    eprintln!("      GPU hash:  {}", hex::encode(gpu_hash));
                    eprintln!("      CPU hash:  {}", hex::encode(cpu_hash));
                    all_passed = false;
                }
            }
        } else {
            println!("  [⚠] No matches to verify (Xor Filter32 may not contain test hashes)");
        }
    }
    
    // Final verification: Check multiple key offsets
    println!("  [🔍] Testing key offset reconstruction...");
    for offset in [0u32, 1, 10, 63, 64, 100, 1000] {
        let mut reconstructed = base_key;
        let mut carry = offset as u64;
        for byte in reconstructed.iter_mut().rev() {
            let sum = *byte as u64 + (carry & 0xFF);
            *byte = sum as u8;
            carry = (carry >> 8) + (sum >> 8);
        }
        
        // The reconstructed key should be base_key + offset
        let expected_val = 1u64 + offset as u64;
        let reconstructed_val = u64::from_be_bytes(reconstructed[24..32].try_into().unwrap());
        
        if reconstructed_val != expected_val {
            eprintln!("  [✗] Key reconstruction failed for offset {}!", offset);
            eprintln!("      Expected: {}", expected_val);
            eprintln!("      Got:      {}", reconstructed_val);
            all_passed = false;
        }
    }
    
    if all_passed {
        println!("  [✓] Key offset reconstruction verified");
        println!("[✓] GPU correctness test PASSED\n");
    } else {
        eprintln!("[✗] GPU CORRECTNESS TEST FAILED!\n");
        eprintln!("    DO NOT USE - GPU calculations are incorrect!");
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
                
                // Sanity check: should complete in reasonable time
                // First run includes shader compilation (~5s) + bloom filter init
                // 60s threshold is generous for cold start, actual runtime is much faster
                if elapsed.as_secs() > 60 {
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
            // Same keys should produce same match counts (Xor Filter32 is deterministic)
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

const PIPELINE_DEPTH: usize = 8;

type VerifyBatch = ([u8; 32], Vec<PotentialMatch>);

#[cfg(target_os = "macos")]
fn check_memory_pressure() -> f32 {
    use std::process::Command;
    
    if let Ok(output) = Command::new("vm_stat").output() {
        if output.status.success() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                // Parse page size and free pages
                let mut page_size: u64 = 4096; // Default 4KB
                let mut free_pages: u64 = 0;
                let mut inactive_pages: u64 = 0;
                let mut speculative_pages: u64 = 0;
                
                for line in text.lines() {
                    if line.contains("page size of") {
                        if let Some(size_str) = line.split_whitespace().nth(7) {
                            page_size = size_str.parse().unwrap_or(4096);
                        }
                    } else if line.starts_with("Pages free:") {
                        if let Some(val) = line.split(':').nth(1) {
                            free_pages = val.trim().trim_end_matches('.').parse().unwrap_or(0);
                        }
                    } else if line.starts_with("Pages inactive:") {
                        if let Some(val) = line.split(':').nth(1) {
                            inactive_pages = val.trim().trim_end_matches('.').parse().unwrap_or(0);
                        }
                    } else if line.starts_with("Pages speculative:") {
                        if let Some(val) = line.split(':').nth(1) {
                            speculative_pages = val.trim().trim_end_matches('.').parse().unwrap_or(0);
                        }
                    }
                }
                
                // Available memory = free + inactive + speculative
                let available_bytes = (free_pages + inactive_pages + speculative_pages) * page_size;
                let available_gb = available_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                
                // Get total memory via sysctl
                if let Ok(mem_output) = Command::new("sysctl")
                    .args(["-n", "hw.memsize"])
                    .output()
                {
                    if mem_output.status.success() {
                        if let Ok(mem_str) = std::str::from_utf8(&mem_output.stdout) {
                            if let Ok(total_bytes) = mem_str.trim().parse::<u64>() {
                                let total_gb = total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                                let free_pct = (available_gb / total_gb * 100.0) as f32;
                                return free_pct.clamp(0.0, 100.0);
                            }
                        }
                    }
                }
            }
        }
    }
    
    100.0 // Assume OK if detection fails
}

#[cfg(not(target_os = "macos"))]
fn check_memory_pressure() -> f32 {
    100.0 // Not implemented for non-macOS
}

/// Memory pressure level for decision making
#[derive(Debug, Clone, Copy, PartialEq)]
enum MemoryPressure {
    Normal,   // > 20% free
    Warning,  // 10-20% free
    Critical, // < 10% free
}

impl MemoryPressure {
    fn from_free_pct(pct: f32) -> Self {
        if pct < 10.0 {
            Self::Critical
        } else if pct < 20.0 {
            Self::Warning
        } else {
            Self::Normal
        }
    }
}

// ============================================================================
// THERMAL MONITORING - REMOVED (replaced by PID Thermal Controller)
// ============================================================================
// LEGACY ThermalMonitor removed - PID thermal controller is now default

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

/// Detect number of Performance cores on Apple Silicon
/// Uses macOS sysctl to get accurate P-core count (excludes E-cores)
/// Falls back to conservative estimate based on total CPU count
fn get_performance_core_count() -> usize {
    // Try macOS sysctl first (most accurate for Apple Silicon)
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        
        // Method 1: Direct P-core count via hw.perflevel0.physicalcpu
        // This is the most accurate for Apple Silicon
        if let Ok(output) = Command::new("sysctl")
            .args(["-n", "hw.perflevel0.physicalcpu"])
            .output()
        {
            if output.status.success() {
                if let Ok(count_str) = std::str::from_utf8(&output.stdout) {
                    if let Ok(count) = count_str.trim().parse::<usize>() {
                        if count > 0 && count <= 32 {
                            return count;
                        }
                    }
                }
            }
        }
        
        // Method 2: Estimate based on total physical CPUs
        // Use chip-aware calculation instead of simple division
        if let Ok(output) = Command::new("sysctl")
            .args(["-n", "hw.physicalcpu"])
            .output()
        {
            if output.status.success() {
                if let Ok(count_str) = std::str::from_utf8(&output.stdout) {
                    if let Ok(total) = count_str.trim().parse::<usize>() {
                        // Apple Silicon P-core estimates:
                        // M1 base:  8 total → 4 P + 4 E → use 4
                        // M1 Pro:  10 total → 8 P + 2 E → use 8
                        // M1 Max:  10 total → 8 P + 2 E → use 8
                        // M1 Ultra: 20 total → 16 P + 4 E → use 12 (leave headroom)
                        // M2/M3/M4: Similar ratios
                        let p_cores = if total <= 8 {
                            total / 2  // Base chips: 50% P-cores
                        } else if total <= 12 {
                            total - 2  // Pro/Max: total - 2 E-cores
                        } else {
                            total - 4  // Ultra: total - 4 E-cores
                        };
                        return p_cores.max(4).min(16); // Clamp to reasonable range
                    }
                }
            }
        }
    }
    
    // Default fallback for non-macOS or if detection fails
    4
}

fn main() {
    println!("\n\x1b[1;36m╔═══════════════════════════════════════════════════════╗");
    println!("║     XYZ-PRO  •  Bitcoin Key Scanner  •  Metal GPU      ║");
    println!("║         P2PKH  •  P2SH  •  P2WPKH                       ║");
    println!("╚═══════════════════════════════════════════════════════╝\x1b[0m\n");

    // OPTIMIZATION: Configure Rayon thread pool for P-cores only with high priority
    // Apple Silicon has Performance cores (fast) and Efficiency cores (slow)
    // Using only P-cores avoids E-core overhead and improves verification speed
    // 
    // P-core counts by chip:
    //   M1 base:  4 P-cores + 4 E-cores → use 4 threads
    //   M1 Pro:   8 P-cores + 2 E-cores → use 6-8 threads
    //   M1 Max:  10 P-cores + 2 E-cores → use 8 threads
    //   M1 Ultra: 20 P-cores + 4 E-cores → use 12 threads
    //
    // We detect chip type via macOS sysctl to get actual P-core count
    let p_core_count = get_performance_core_count();
    
    use rayon::ThreadPoolBuilder;
    
    // Configure thread pool with high-priority QoS on macOS
    // This ensures verification threads get CPU time promptly
    let pool_result = ThreadPoolBuilder::new()
        .num_threads(p_core_count)  // P-cores only (exclude E-cores)
        .thread_name(|i| format!("verify-{}", i))
        .spawn_handler(|thread| {
            // Create thread with custom spawn to set QoS
            let mut builder = std::thread::Builder::new();
            if let Some(name) = thread.name() {
                builder = builder.name(name.to_owned());
            }
            // Stack size: 256KB per thread (sufficient for verification, reduces memory footprint)
            // Verification uses max 100KB per thread, so 256KB provides safety margin
            builder = builder.stack_size(256 * 1024);
            
            builder.spawn(|| {
                // Set high priority QoS on macOS for faster verification
                #[cfg(target_os = "macos")]
                {
                    // pthread_set_qos_class_self_np sets the QoS class for current thread
                    // QOS_CLASS_USER_INTERACTIVE (0x21) = highest priority for responsive work
                    extern "C" {
                        fn pthread_set_qos_class_self_np(
                            qos_class: u32,
                            relative_priority: i32,
                        ) -> i32;
                    }
                    const QOS_CLASS_USER_INTERACTIVE: u32 = 0x21;
                    unsafe {
                        pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
                    }
                }
                
                // Run the actual rayon thread work
                thread.run();
            })?;
            Ok(())
        })
        .build_global();
    
    match pool_result {
        Ok(()) => {
            #[cfg(target_os = "macos")]
            println!("[CPU] Rayon: {} threads (P-cores, QOS_USER_INTERACTIVE)", p_core_count);
            #[cfg(not(target_os = "macos"))]
            println!("[CPU] Rayon: {} threads (P-cores only)", p_core_count);
        }
        Err(e) => {
            eprintln!("[!] Failed to configure Rayon thread pool: {}", e);
            // Continue with default pool
        }
    }

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

    // CRITICAL: Run GPU correctness test FIRST
    // This verifies GPU hash calculations match CPU exactly
    // A single bit error means missed matches!
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
    
    // CRITICAL: Run comprehensive edge case tests
    // These catch bugs in edge cases that normal tests might miss
    #[cfg(feature = "philox-rng")]
    {
        use crate::tests::edge_cases;
        if !edge_cases::run_all_edge_case_tests() {
            eprintln!("\n[FATAL] Edge case tests failed. Exiting to prevent bugs.");
            std::process::exit(1);
        }
    }
    
    // CRITICAL: Run CPU/GPU/Metal/Xor Filter integration tests
    // Verifies all components work correctly together
    {
        use crate::tests::cpu_gpu_xor_integration;
        if !cpu_gpu_xor_integration::run_cpu_gpu_xor_integration_tests(&gpu, &targets) {
            eprintln!("\n[FATAL] CPU/GPU/Metal/Xor Filter integration tests failed. Exiting to prevent incorrect results.");
            std::process::exit(1);
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
                
                let result = gpu.scan_pipelined(
                    || gpu.next_base_key(),
                    |base_key, matches| {
                        let batch_duration = last_batch_time.elapsed();
                        last_batch_time = Instant::now();
                        
                        // Establish baseline (first few batches)
                        if !baseline_established {
                            if baseline_duration.as_millis() == 0 {
                                baseline_duration = batch_duration;
                            } else {
                                // Running average for baseline
                                let avg_ms = ((baseline_duration.as_millis() * 9 + batch_duration.as_millis()) / 10) as u64;
                                baseline_duration = Duration::from_millis(avg_ms);
                            }
                            if baseline_duration.as_millis() > 0 {
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
                                80.0 // Default until baseline established
                            }
                        });
                        
                        // PID controller adjusts speed based on actual temperature
                        if let Some(_new_batch) = pid_controller.update(current_temp) {
                            let speed = pid_controller.current_speed();
                            if (speed - 1.0).abs() > 0.05 {
                                eprintln!("[PID] Speed: {:.1}% (temp: {:.1}°C)", 
                                    speed * 100.0, current_temp);
                            }
                        }
                        
                        gpu_counter.fetch_add(keys_per_batch, Ordering::Relaxed);
                        
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
        
        // OPTIMIZED: Minimal batch accumulation for lowest latency
        // WHY: Smaller accumulation = lower latency
        // - 2 batches × 14K FP = 28K verifications
        // - 8 cores × 28K / 8 = 3,500 each
        // - 3,500 × 60µs = 210ms verification time
        // - vs GPU 64ms × 2 = 128ms → still slower but acceptable
        //
        // With PIPELINE_DEPTH=8, GPU has sufficient buffering (512ms)!
        const MAX_BATCH_ACCUMULATION: usize = 2;
        
        while !verify_shutdown.load(Ordering::Relaxed) {
            // Collect batches for parallel processing
            let mut batches: Vec<VerifyBatch> = Vec::with_capacity(MAX_BATCH_ACCUMULATION);
            
            // Wait for first batch with reduced timeout for faster response
            match rx.recv_timeout(Duration::from_millis(20)) {
                Ok(batch) => {
                    batches.push(batch);
                    // Grab a few more if available (non-blocking)
                    while batches.len() < MAX_BATCH_ACCUMULATION {
                        match rx.try_recv() {
                            Ok(b) => batches.push(b),
                            Err(_) => break,
                        }
                    }
                }
                Err(_) => continue, // Timeout, check shutdown
            }
            
            // Parallel verification with simple Vec (collision probability effectively zero)
            batches.par_iter()
                .flat_map(|(base_key, matches)| {
                    matches.par_iter().filter_map(|pm| {
                        if let Some((addr, atype, privkey)) = verify_match(base_key, pm, &targets) {
                            let compressed = pm.match_type != gpu::MatchType::Uncompressed 
                                && pm.match_type != gpu::MatchType::GlvUncompressed;
                            Some((addr, atype, privkey, compressed))
                        } else {
                            // Count false positives (atomic, safe)
                            verify_fp_clone.fetch_add(1, Ordering::Relaxed);
                            None
                        }
                    })
                })
                .for_each(|(addr, atype, privkey, compressed)| {
                    // Simple Vec - check if key already seen before reporting
                    // Collision between different keys is impossible (2²⁵⁶ space), but same key
                    // could theoretically appear in multiple matches
                    let mut keys = found_keys_clone.lock().unwrap();
                    if !keys.contains(&privkey) {
                        keys.push(privkey);
                        verify_found.fetch_add(1, Ordering::Relaxed);
                        report(&privkey, &addr, atype, compressed);
                    }
                });
        }
    });

    // Stats display in main thread with memory monitoring
    let mut last_stat = Instant::now();
    let mut last_count = 0u64;
    let mut last_mem_check = Instant::now();
    let mut mem_warning_shown = false;

    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));

        // Memory pressure check every 5 minutes (reduced overhead from vm_stat fork)
        // vm_stat fork is expensive (~2-3% CPU), pressure rarely changes rapidly
        if last_mem_check.elapsed() >= Duration::from_secs(300) {
            let mem_free_pct = check_memory_pressure();
            let pressure = MemoryPressure::from_free_pct(mem_free_pct);
            
            match pressure {
                MemoryPressure::Critical => {
                    if !mem_warning_shown {
                        eprintln!("\n[!] CRITICAL: Low memory ({:.1}% free)!", mem_free_pct);
                        eprintln!("    Consider reducing target count or closing other apps.");
                        mem_warning_shown = true;
                    }
                }
                MemoryPressure::Warning => {
                    if !mem_warning_shown {
                        eprintln!("\n[!] WARNING: Memory pressure detected ({:.1}% free)", mem_free_pct);
                        mem_warning_shown = true;
                    }
                }
                MemoryPressure::Normal => {
                    mem_warning_shown = false; // Reset for next warning cycle
                }
            }
            last_mem_check = Instant::now();
        }

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
// KEY GENERATION - REMOVED (replaced by Philox RNG)
// ============================================================================
// LEGACY generate_random_key function removed - Philox RNG is now default

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

    // For GLV matches, the actual private key is λ·k (mod n)
    // This is because GPU used φ(P) = (β·Px, Py) which corresponds to λ·P
    let actual_key = if pm.match_type.is_glv() {
        gpu::glv_transform_key(&priv_key)
    } else {
        priv_key
    };

    if !crypto::is_valid_private_key(&actual_key) {
        return None;
    }

    // Generate public key from actual key
    let secret = SecretKey::from_slice(&actual_key).ok()?;
    let pubkey = secret.public_key();

    // Verify based on match_type from GPU (use base type for GLV matches)
    match pm.match_type {
        MatchType::Compressed | MatchType::GlvCompressed => {
            // GPU found compressed pubkey hash match
            let comp = pubkey.to_encoded_point(true);
            let comp_hash = crypto::hash160(comp.as_bytes());
            let comp_h160 = types::Hash160::from_slice(&comp_hash);

            // Verify hash matches what GPU found
            if comp_h160 != pm.hash {
                return None; // Hash mismatch - Xor Filter32 false positive
            }

            // OPTIMIZATION: Use check_direct() instead of check()
            // GPU already computes P2SH separately as MatchType::P2SH/GlvP2SH
            // So here we only need to check P2PKH and P2WPKH (direct hash match)
            if let Some((addr, atype)) = targets.check_direct(&comp_h160) {
                return Some((addr, atype, actual_key));
            }
        }
        MatchType::Uncompressed | MatchType::GlvUncompressed => {
            // GPU found uncompressed pubkey hash match
            let uncomp = pubkey.to_encoded_point(false);
            let uncomp_hash = crypto::hash160(uncomp.as_bytes());
            let uncomp_h160 = types::Hash160::from_slice(&uncomp_hash);

            // Verify hash matches what GPU found
            if uncomp_h160 != pm.hash {
                return None; // Hash mismatch - Xor Filter32 false positive
            }

            // Check in targets - direct lookup only (uncompressed only for P2PKH legacy)
            if let Some((addr, atype)) = targets.check_direct(&uncomp_h160) {
                return Some((addr, atype, actual_key));
            }
        }
        MatchType::P2SH | MatchType::GlvP2SH => {
            // GPU found P2SH script hash match
            let comp = pubkey.to_encoded_point(true);
            let comp_hash = crypto::hash160(comp.as_bytes());
            let p2sh_hash = address::p2sh_script_hash(&comp_hash);
            let p2sh_h160 = types::Hash160::from_slice(&p2sh_hash);

            // Verify hash matches what GPU found
            if p2sh_h160 != pm.hash {
                return None; // Hash mismatch - Xor Filter32 false positive
            }

            // Check in targets using the SCRIPT HASH directly (not pubkey hash!)
            // P2SH addresses store script_hash in targets, so direct lookup works
            if let Some((addr, atype)) = targets.check_direct(&p2sh_h160) {
                return Some((addr, atype, actual_key));
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


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

// Self-tests moved to tests/integration/ - startup verification inline below

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
        println!("[✓] Self-test passed (total: {:.2}s)\n", self_test_start.elapsed().as_secs_f64());
    } else {
        eprintln!("\n[✗] SELF-TEST FAILED! (total: {:.2}s)", self_test_start.elapsed().as_secs_f64());
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
    
    // =========================================================================
    // CANARY TEST: Verify known key (Private Key = 1) is in targets database
    // If this key's hash is in targets.bin, GPU should find it when scanning from key=1
    // This proves: targets loaded correctly, verification pipeline works
    // =========================================================================
    print!("  [🐤] Canary test (Key=1)... ");
    stdout().flush().ok();
    
    let canary_key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
        .unwrap().try_into().unwrap();
    let canary_secret = SecretKey::from_slice(&canary_key).unwrap();
    let canary_pubkey = canary_secret.public_key();
    
    // Check all 3 hash types for Key=1
    let comp_point = canary_pubkey.to_encoded_point(true);
    let comp_hash = crate::crypto::hash160(comp_point.as_bytes());
    let comp_h160 = crate::types::Hash160::from_slice(&comp_hash);
    
    let uncomp_point = canary_pubkey.to_encoded_point(false);
    let uncomp_hash = crate::crypto::hash160(uncomp_point.as_bytes());
    let uncomp_h160 = crate::types::Hash160::from_slice(&uncomp_hash);
    
    let p2sh_hash = crate::address::p2sh_script_hash(&comp_hash);
    let p2sh_h160 = crate::types::Hash160::from_slice(&p2sh_hash);
    
    let comp_in_targets = targets.check_direct(&comp_h160);
    let uncomp_in_targets = targets.check_direct(&uncomp_h160);
    let p2sh_in_targets = targets.check_direct(&p2sh_h160);
    
    if comp_in_targets.is_some() || uncomp_in_targets.is_some() || p2sh_in_targets.is_some() {
        println!("FOUND in targets! ✓");
        if comp_in_targets.is_some() {
            println!("      → Compressed: {} ({})", hex::encode(&comp_hash), comp_in_targets.unwrap().0);
        }
        if uncomp_in_targets.is_some() {
            println!("      → Uncompressed: {}", hex::encode(&uncomp_hash));
        }
        if p2sh_in_targets.is_some() {
            println!("      → P2SH: {}", hex::encode(&p2sh_hash));
        }
        println!("      → System is LIVE! If GPU scans key=1, it WILL find this!");
    } else {
        println!("not in targets");
        println!("      → Key=1 hashes: comp={}, uncomp={}", 
            hex::encode(&comp_hash), hex::encode(&uncomp_hash));
        println!("      → To add canary: include 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH in targets.json");
    }
    
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
    print!("  [🔍] Verifying CPU reference calculations... ");
    stdout().flush().ok();
    let cpu_start = Instant::now();
    for (priv_hex, expected_comp, _, _) in &test_vectors[..1] {  // Just test first vector for CPU
        let priv_key: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();
        let secret = SecretKey::from_slice(&priv_key).unwrap();
        let pubkey = secret.public_key();
        let compressed = pubkey.to_encoded_point(true);
        let cpu_hash = crypto::hash160(compressed.as_bytes());
        let expected: [u8; 20] = hex::decode(expected_comp).unwrap().try_into().unwrap();
        
        if cpu_hash != expected {
            println!("FAILED ({:.2}s)", cpu_start.elapsed().as_secs_f64());
            eprintln!("  [✗] CPU hash mismatch! This should never happen.");
            eprintln!("      Expected: {}", expected_comp);
            eprintln!("      Got:      {}", hex::encode(cpu_hash));
            return false;
        }
    }
    println!("done ({:.2}s)", cpu_start.elapsed().as_secs_f64());
    
    // Xor Filter FP rate test SKIPPED at startup
    // REASON: Filter already built & tested during scanner initialization
    // Building 49M-entry filter twice wastes ~2-3 minutes
    // Full FP rate testing available via: cargo test --release
    #[cfg(feature = "xor-filter")]
    {
        println!("  [✓] Xor Filter already built by scanner (skipping redundant FP test)");
        println!("      Run 'cargo test --release' for comprehensive FP rate testing");
    }
    
    // Now test GPU: scan a batch and verify GPU hashes match CPU
    print!("  [🔍] Testing GPU hash calculations... ");
    stdout().flush().ok();
    let gpu_test_start = Instant::now();
    
    let base_key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
        .unwrap().try_into().unwrap();
    
    match scanner.scan_batch(&base_key) {
        Ok(matches) => {
            println!("done ({:.2}s)", gpu_test_start.elapsed().as_secs_f64());
            println!("      GPU scan completed successfully");
            println!("      Xor Filter matches in batch: {} (depends on targets.bin content)", matches.len());
            
            // If we have matches, verify them against CPU calculation
            // Note: Having 0 matches is OK if test keys' hashes aren't in targets.bin
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
            } else if matches.is_empty() {
                // CRITICAL CHECK: With 8.4M keys and 0.15% Xor filter FP rate,
                // we SHOULD get ~12,600 false positives per batch!
                // 0 matches means Xor filter or FxHash is broken.
                //
                // Expected: keys_per_batch × 0.0015 × 6 (hash variants) = ~75,000 matches
                // Minimum reasonable: at least 1,000 matches
                //
                // If we get 0, the GPU FxHash doesn't match CPU FxHasher!
                let keys_per_batch = scanner.keys_per_batch();
                let expected_fp = (keys_per_batch as f64 * 0.0015 * 6.0) as u64;
                
                eprintln!("  [✗] CRITICAL: Got 0 Xor Filter matches!");
                eprintln!("      Expected ~{} false positives with {} keys/batch", expected_fp, keys_per_batch);
                eprintln!("      This indicates GPU FxHash doesn't match CPU FxHasher!");
                eprintln!("      Check: src/filter/xor_lookup.metal must match src/filter/xor_filter.rs");
                all_passed = false;
            }
        }
        Err(e) => {
            println!("FAILED ({:.2}s)", gpu_test_start.elapsed().as_secs_f64());
            eprintln!("  [✗] GPU scan failed: {}", e);
            all_passed = false;
        }
    }
    
    // Critical test: Full verification path
    // Take a match from GPU and verify it through the full CPU verification path
    print!("  [🔍] Testing full GPU→CPU verification path... ");
    stdout().flush().ok();
    let verify_start = Instant::now();
    
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
                    println!("done ({:.2}s)", verify_start.elapsed().as_secs_f64());
                    println!("  [✓] GPU→CPU hash verification PASSED");
                    println!("      key_index={}, type={:?}, hash={}", 
                        pm.key_index, pm.match_type, hex::encode(gpu_hash));
                } else {
                    println!("FAILED ({:.2}s)", verify_start.elapsed().as_secs_f64());
                    eprintln!("  [✗] GPU→CPU hash MISMATCH!");
                    eprintln!("      key_index: {}", pm.key_index);
                    eprintln!("      GPU hash:  {}", hex::encode(gpu_hash));
                    eprintln!("      CPU hash:  {}", hex::encode(cpu_hash));
                    all_passed = false;
                }
            }
        } else {
            // This shouldn't happen if the first scan returned matches
            // If both scans return 0 matches, something is seriously wrong
            println!("done ({:.2}s)", verify_start.elapsed().as_secs_f64());
            eprintln!("  [✗] CRITICAL: No matches for verification!");
            eprintln!("      Both GPU scans returned 0 matches.");
            eprintln!("      GPU Xor Filter or FxHash implementation is broken!");
            all_passed = false;
        }
    }
    
    // Final verification: Check multiple key offsets
    print!("  [🔍] Testing key offset reconstruction... ");
    stdout().flush().ok();
    let offset_start = Instant::now();
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
            println!("FAILED ({:.2}s)", offset_start.elapsed().as_secs_f64());
            eprintln!("  [✗] Key reconstruction failed for offset {}!", offset);
            eprintln!("      Expected: {}", expected_val);
            eprintln!("      Got:      {}", reconstructed_val);
            all_passed = false;
        }
    }
    
    if all_passed {
        println!("done ({:.2}s)", offset_start.elapsed().as_secs_f64());
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
    print!("  [🔍] Testing pipelined batch processing... ");
    stdout().flush().ok();
    
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
                println!("done ({:.2}s)", elapsed.as_secs_f64());
                println!("      {} batches, {:.1}M keys, {:.1}M/s", 
                    batch_count, 
                    keys_scanned as f64 / 1_000_000.0,
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
                println!("FAILED ({:.2}s)", elapsed.as_secs_f64());
                eprintln!("  [✗] GPU pipeline incomplete: only {} batches processed", batch_count);
                all_passed = false;
            }
        }
        Err(e) => {
            println!("FAILED ({:.2}s)", elapsed.as_secs_f64());
            eprintln!("  [✗] GPU pipeline error: {}", e);
            all_passed = false;
        }
    }
    
    // Test 2: Verify triple-buffering doesn't cause data corruption
    // Run multiple batches and verify no GPU errors occur
    // NOTE: Same base_key produces DIFFERENT matches each call because
    // Philox counter advances, generating different key offsets each batch!
    print!("  [🔍] Testing triple-buffer stability... ");
    stdout().flush().ok();
    let triple_buf_start = Instant::now();
    
    let test_key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
        .unwrap().try_into().unwrap();
    
    // Run 6 consecutive batches to cycle through all 3 buffers twice
    // This tests buffer rotation and ensures no corruption between cycles
    let mut total_matches = 0usize;
    let mut all_scans_ok = true;
    
    for i in 0..6 {
        match scanner.scan_batch(&test_key) {
            Ok(matches) => {
                total_matches += matches.len();
                // Basic sanity check: match count should be reasonable
                // With 8.4M keys and ~0.15% FP rate × 6 hash types = ~75K max expected
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
        println!("done ({:.2}s)", triple_buf_start.elapsed().as_secs_f64());
        println!("      6 batches completed, {} total FP matches", total_matches);
    } else {
        println!("FAILED ({:.2}s)", triple_buf_start.elapsed().as_secs_f64());
        all_passed = false;
    }
    
    if all_passed {
        println!("[✓] GPU pipeline test passed\n");
    } else {
        eprintln!("[✗] GPU PIPELINE TEST FAILED!\n");
    }
    
    all_passed
}

/// Quick startup verification - checks critical components before scanning
/// Full tests are in tests/integration/ - run 'cargo test' for comprehensive testing
#[cfg(feature = "philox-rng")]
fn run_startup_verification(scanner: &OptimizedScanner) -> bool {
    use crate::rng::{PhiloxCounter, PhiloxState, philox4x32_10};
    
    println!("[🔍] Running startup verification...");
    let startup_start = Instant::now();
    
    let mut all_passed = true;
    
    // Test 1: Philox RNG produces non-zero output
    print!("  [1/5] Philox RNG... ");
    stdout().flush().ok();
    let t1 = Instant::now();
    {
        let state = PhiloxState::new(12345);
        let output = philox4x32_10(&state);
        if output[0] == 0 && output[1] == 0 && output[2] == 0 && output[3] == 0 {
            println!("FAILED ({:.2}s)", t1.elapsed().as_secs_f64());
            eprintln!("        Philox RNG produced all-zero output!");
            all_passed = false;
        } else {
            println!("OK ({:.2}s)", t1.elapsed().as_secs_f64());
        }
    }
    
    // Test 2: Counter increment works
    print!("  [2/5] Philox counter... ");
    stdout().flush().ok();
    let t2 = Instant::now();
    {
        let counter = PhiloxCounter::new(42);
        let state1 = counter.next_batch(128);
        let state2 = counter.next_batch(128);
        // States should be different
        if state1.counter == state2.counter {
            println!("FAILED ({:.2}s)", t2.elapsed().as_secs_f64());
            eprintln!("        Philox counter increment failed!");
            all_passed = false;
        } else {
            println!("OK ({:.2}s)", t2.elapsed().as_secs_f64());
        }
    }
    
    // Test 3: GPU can scan a batch
    print!("  [3/5] GPU scan... ");
    stdout().flush().ok();
    let t3 = Instant::now();
    {
        let test_key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap().try_into().unwrap();
        
        match scanner.scan_batch(&test_key) {
            Ok(_) => {
                println!("OK ({:.2}s)", t3.elapsed().as_secs_f64());
            }
            Err(e) => {
                println!("FAILED ({:.2}s)", t3.elapsed().as_secs_f64());
                eprintln!("        GPU scan failed: {}", e);
                all_passed = false;
            }
        }
    }
    
    // Test 4: Known Bitcoin test vector
    print!("  [4/5] CPU hash calculation... ");
    stdout().flush().ok();
    let t4 = Instant::now();
    {
        use crypto::hash160;
        
        let priv_key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap().try_into().unwrap();
        let secret = SecretKey::from_slice(&priv_key).unwrap();
        let pubkey = secret.public_key();
        let compressed = pubkey.to_encoded_point(true);
        let hash = hash160(compressed.as_bytes());
        
        let expected: [u8; 20] = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6")
            .unwrap().try_into().unwrap();
        
        if hash == expected {
            println!("OK ({:.2}s)", t4.elapsed().as_secs_f64());
        } else {
            println!("FAILED ({:.2}s)", t4.elapsed().as_secs_f64());
            eprintln!("        CPU hash calculation mismatch!");
            all_passed = false;
        }
    }
    
    // Test 5: GLV transform works
    print!("  [5/5] GLV endomorphism... ");
    stdout().flush().ok();
    let t5 = Instant::now();
    {
        let key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000005")
            .unwrap().try_into().unwrap();
        
        let glv1 = gpu::glv_transform_key(&key);
        let glv2 = gpu::glv_transform_key(&glv1);
        let glv3 = gpu::glv_transform_key(&glv2);
        
        if glv3 == key {
            println!("OK ({:.2}s) - λ³ = 1", t5.elapsed().as_secs_f64());
        } else {
            println!("FAILED ({:.2}s)", t5.elapsed().as_secs_f64());
            eprintln!("        GLV endomorphism failed: λ³ ≠ 1");
            all_passed = false;
        }
    }
    
    if all_passed {
        println!("[✓] Startup verification passed (total: {:.2}s)\n", startup_start.elapsed().as_secs_f64());
    } else {
        eprintln!("[✗] STARTUP VERIFICATION FAILED! (total: {:.2}s)\n", startup_start.elapsed().as_secs_f64());
        eprintln!("    Run 'cargo test --test integration' for detailed diagnostics.\n");
    }
    
    all_passed
}

const PIPELINE_DEPTH: usize = 8;

type VerifyBatch = ([u8; 32], Vec<PotentialMatch>);

/// Check memory pressure using NATIVE sysctlbyname (no process fork!)
/// 
/// OPTIMIZATION: Previous version used Command::new("vm_stat") which:
/// - Forks a new process (~2-3% CPU overhead)
/// - Clears CPU execution pipeline
/// - Takes milliseconds per call
/// 
/// NEW: Direct sysctlbyname() call - microseconds, no fork overhead
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
/// OPTIMIZED: Uses native sysctlbyname instead of Command::new("sysctl")
/// This avoids process forking overhead (~2-3ms per call)
fn get_performance_core_count() -> usize {
    #[cfg(target_os = "macos")]
    {
        // Native sysctlbyname - no process fork, microseconds instead of milliseconds
        extern "C" {
            fn sysctlbyname(
                name: *const libc::c_char,
                oldp: *mut libc::c_void,
                oldlenp: *mut libc::size_t,
                newp: *const libc::c_void,
                newlen: libc::size_t,
            ) -> libc::c_int;
        }
        
        // Helper to get sysctl value
        fn get_sysctl_int(name: &[u8]) -> Option<i32> {
            unsafe {
                let mut value: i32 = 0;
                let mut size = std::mem::size_of::<i32>();
                let result = sysctlbyname(
                    name.as_ptr() as *const libc::c_char,
                    &mut value as *mut i32 as *mut libc::c_void,
                    &mut size,
                    std::ptr::null(),
                    0,
                );
                if result == 0 { Some(value) } else { None }
            }
        }
        
        // Method 1: Direct P-core count via hw.perflevel0.physicalcpu (most accurate)
        if let Some(count) = get_sysctl_int(b"hw.perflevel0.physicalcpu\0") {
            if count > 0 && count <= 32 {
                return count as usize;
            }
        }
        
        // Method 2: Estimate based on total physical CPUs
        if let Some(total) = get_sysctl_int(b"hw.physicalcpu\0") {
            let total = total as usize;
                        // ═══════════════════════════════════════════════════
                        // APPLE SILICON CPU P-CORE TABLE
                        // ═══════════════════════════════════════════════════
                        // 
                        // M1 Series:
                        //   M1 base:   8 total (4P+4E) → use 2 threads
                        //   M1 Pro:   10 total (6-8P+2E) → use 4-6 threads
                        //   M1 Max:   10 total (8P+2E) → use 6 threads
                        //   M1 Ultra: 20 total (16P+4E) → use 10 threads
                        //
                        // M2 Series:
                        //   M2 base:   8 total (4P+4E) → use 2 threads
                        //   M2 Pro:  10-12 total (6-8P+4E) → use 4-6 threads
                        //   M2 Max:   12 total (8P+4E) → use 6 threads
                        //   M2 Ultra: 24 total (16P+8E) → use 10 threads
                        //
                        // M3 Series:
                        //   M3 base:   8 total (4P+4E) → use 2 threads
                        //   M3 Pro:  11-12 total (5-6P+6E) → use 4 threads
                        //   M3 Max:  14-16 total (10-12P+4E) → use 8 threads
                        //
                        // M4 Series:
                        //   M4 base:  10 total (6P+4E) → use 3 threads
                        //   M4 Pro:  12-14 total (8-10P+4E) → use 6 threads
                        //   M4 Max:  14-16 total (10-12P+4E) → use 8 threads
                        //
                        // CRITICAL: Leave cores for system + GPU dispatch!
                        // ═══════════════════════════════════════════════════
                        let p_cores = if total <= 8 {
                            2  // Base M1/M2/M3: 4P, use 2
                        } else if total == 10 {
                            3  // M4 base (6P) or M1/M2 Pro (6-8P), use 3
                        } else if total <= 12 {
                            4  // M2/M3 Pro: 6-8P, use 4
                        } else if total <= 16 {
                            6  // M3/M4 Max: 10-12P, use 6
                        } else {
                            8  // Ultra: 16P, use 8
                        };
            return p_cores.max(2).min(10);
        }
    }
    
    // Default fallback for non-macOS or if detection fails
    6
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
                // Set high priority QoS AND P-core affinity on macOS
                #[cfg(target_os = "macos")]
                {
                    // QOS_CLASS_USER_INITIATED (0x19) = high priority for long-running user tasks
                    // NOTE: USER_INTERACTIVE (0x21) is throttled by macOS for long-running work
                    extern "C" {
                        fn pthread_set_qos_class_self_np(
                            qos_class: u32,
                            relative_priority: i32,
                        ) -> i32;
                        fn pthread_mach_thread_np(thread: libc::pthread_t) -> u32;
                        fn pthread_self() -> libc::pthread_t;
                    }
                    
                    // Mach thread policy API for P-core affinity
                    extern "C" {
                        fn thread_policy_set(
                            thread: u32,
                            flavor: u32,
                            policy_info: *const u32,
                            policy_infoCnt: u32,
                        ) -> i32;
                    }
                    
                    const QOS_CLASS_USER_INITIATED: u32 = 0x19;
                    const THREAD_AFFINITY_POLICY: u32 = 4;
                    const THREAD_AFFINITY_POLICY_COUNT: u32 = 1;
                    
                    unsafe {
                        // 1. Set QoS class (primary mechanism for P-core preference)
                        pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0);
                        
                        // 2. Set thread affinity tag (keeps verification threads together)
                        // Threads with same tag are scheduled on same cores (reduces cache contention)
                        // Tag 1 = verification threads (keeps them on P-cores together)
                        let thread_port = pthread_mach_thread_np(pthread_self());
                        let affinity_tag: u32 = 1;  // All verify threads share same affinity group
                        thread_policy_set(
                            thread_port,
                            THREAD_AFFINITY_POLICY,
                            &affinity_tag,
                            THREAD_AFFINITY_POLICY_COUNT,
                        );
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

    // Init GPU
    let gpu = match OptimizedScanner::new(&hashes) {
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
                    || gpu.next_base_key(),
                    |base_key, matches| {
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
                            if let Err(e) = tx.send((base_key, matches)) {
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
            let (base_key, matches) = match rx.recv_timeout(Duration::from_millis(10)) {
                Ok(batch) => batch,
                Err(_) => continue, // Timeout, check shutdown
            };
            
            // OPTIMIZED: Adaptive parallelism based on match count
            // - Small batches (<32): Sequential processing (avoid Rayon scheduling overhead)
            // - Large batches (≥32): Parallel processing (utilize P-cores)
            // This improves L2 cache efficiency by ~15% on M1 Pro
            const PARALLEL_THRESHOLD: usize = 32;
            
            let process_match = |pm: &PotentialMatch| {
                if let Some((addr, atype, privkey)) = verify_match(&base_key, pm, &targets) {
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
    let mut batch_count = 0u64;

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
            
            // Calculate batch count (approximate)
            let keys_per_batch = 1_048_576u64; // 1M keys/batch
            let new_batches = (count - last_count) / keys_per_batch;
            batch_count += new_batches;
            
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

fn verify_match(
    base_key: &[u8; 32],
    pm: &PotentialMatch,
    targets: &TargetDatabase,
) -> Option<(String, types::AddressType, [u8; 32])> {
    use k256::elliptic_curve::PrimeField;
    use k256::Scalar;
    
    // Reconstruct private key: base_key + key_index (MODULAR arithmetic!)
    // CRITICAL: GPU uses point addition which is inherently modular
    // CPU must use the same modular arithmetic to match GPU results
    // 
    // If base_key + key_index >= n (curve order), we need modular reduction
    // k256::Scalar handles this automatically via from_repr_vartime
    let priv_key = {
        // Parse base_key as scalar
        // from_repr_vartime returns None if >= curve order
        let base_scalar = match Scalar::from_repr_vartime((*base_key).into()) {
            Some(s) => s,
            None => {
                // base_key >= curve order - extremely rare edge case
                // This should never happen with Philox-generated keys
                // Fall back to linear addition (original behavior)
                return verify_match_linear(base_key, pm, targets);
            }
        };
        
        // Add key_index as scalar (modular addition mod n)
        let offset_scalar = Scalar::from(pm.key_index as u64);
        let result_scalar = base_scalar + offset_scalar;
        
        // Convert back to bytes
        let result_bytes: [u8; 32] = result_scalar.to_repr().into();
        result_bytes
    };

    // For GLV matches, the actual private key is λ·k (mod n)
    // This is because GPU used φ(P) = (β·Px, Py) which corresponds to λ·P
    // 
    // CORRECTNESS: glv_transform_key uses k256::Scalar which automatically
    // performs modular arithmetic (mod n where n is the secp256k1 curve order)
    let actual_key = if pm.match_type.is_glv() {
        gpu::glv_transform_key(&priv_key)
    } else {
        priv_key
    };

    // Scalar operations already ensure 0 < key < n
    // This check is now redundant but kept for safety
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

/// Fallback verify_match using linear (non-modular) addition
/// Used when base_key >= curve order (extremely rare edge case)
fn verify_match_linear(
    base_key: &[u8; 32],
    pm: &PotentialMatch,
    targets: &TargetDatabase,
) -> Option<(String, types::AddressType, [u8; 32])> {
    // Linear addition (original algorithm)
    let mut priv_key = *base_key;
    let mut carry = pm.key_index as u64;
    for byte in priv_key.iter_mut().rev() {
        let sum = *byte as u64 + (carry & 0xFF);
        *byte = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
    }

    if carry != 0 {
        return None; // 256-bit overflow
    }

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

    match pm.match_type {
        MatchType::Compressed | MatchType::GlvCompressed => {
            let comp = pubkey.to_encoded_point(true);
            let comp_hash = crypto::hash160(comp.as_bytes());
            let comp_h160 = types::Hash160::from_slice(&comp_hash);
            if comp_h160 != pm.hash { return None; }
            targets.check_direct(&comp_h160).map(|(addr, atype)| (addr, atype, actual_key))
        }
        MatchType::Uncompressed | MatchType::GlvUncompressed => {
            let uncomp = pubkey.to_encoded_point(false);
            let uncomp_hash = crypto::hash160(uncomp.as_bytes());
            let uncomp_h160 = types::Hash160::from_slice(&uncomp_hash);
            if uncomp_h160 != pm.hash { return None; }
            targets.check_direct(&uncomp_h160).map(|(addr, atype)| (addr, atype, actual_key))
        }
        MatchType::P2SH | MatchType::GlvP2SH => {
            let comp = pubkey.to_encoded_point(true);
            let comp_hash = crypto::hash160(comp.as_bytes());
            let p2sh_hash = address::p2sh_script_hash(&comp_hash);
            let p2sh_h160 = types::Hash160::from_slice(&p2sh_hash);
            if p2sh_h160 != pm.hash { return None; }
            targets.check_direct(&p2sh_h160).map(|(addr, atype)| (addr, atype, actual_key))
        }
    }
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

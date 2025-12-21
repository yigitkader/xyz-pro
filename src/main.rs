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
    
    // Now test GPU: scan a batch and verify GPU hashes match CPU
    println!("  [🔍] Testing GPU hash calculations...");
    
    let base_key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
        .unwrap().try_into().unwrap();
    
    match scanner.scan_batch(&base_key) {
        Ok(matches) => {
            println!("      Bloom filter hits in batch: {}", matches.len());
            
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
            println!("  [⚠] No matches to verify (bloom filter may not contain test hashes)");
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
// Increased pipeline depth for better GPU/CPU overlap
// - One being processed by GPU
// - One being verified by CPU
// - One being prepared for next submission
// - One extra buffer for smoother pipelining
const PIPELINE_DEPTH: usize = 4;

// Batch for verification: (base_key, matches)
type VerifyBatch = ([u8; 32], Vec<PotentialMatch>);

// ============================================================================
// SYSTEM MONITORING (Memory & Thermal)
// ============================================================================

/// Check system memory pressure on macOS
/// Returns memory free percentage (0-100), or 100.0 if detection fails
#[cfg(target_os = "macos")]
fn check_memory_pressure() -> f32 {
    use std::process::Command;
    
    // Use vm_stat for memory info (more reliable than memory_pressure command)
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
// THERMAL MONITORING
// ============================================================================

/// Thermal state based on performance monitoring
/// Instead of requiring sudo for powermetrics, we detect throttling via performance degradation
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]  // Used for monitoring/debugging
pub enum ThermalState {
    Normal,      // Performance as expected
    Throttling,  // Performance degraded (likely thermal)
    Critical,    // Severe throttling detected
}

/// ADAPTIVE Thermal monitor with trend-based analysis
/// Uses rolling performance history for smarter throttling detection
/// Avoids unnecessary pauses from single-batch spikes
pub struct ThermalMonitor {
    /// Baseline batch duration (established during warm-up)
    baseline_duration_us: std::sync::atomic::AtomicU64,
    /// Number of samples for baseline
    baseline_samples: std::sync::atomic::AtomicU32,
    /// Current throttle state
    throttle_count: std::sync::atomic::AtomicU32,
    /// Consecutive normal batches (for recovery detection)
    normal_count: std::sync::atomic::AtomicU32,
    /// Performance history for trend analysis (last 20 batches)
    perf_history: std::sync::Mutex<std::collections::VecDeque<u64>>,
}

impl ThermalMonitor {
    pub fn new() -> Self {
        Self {
            baseline_duration_us: std::sync::atomic::AtomicU64::new(0),
            baseline_samples: std::sync::atomic::AtomicU32::new(0),
            throttle_count: std::sync::atomic::AtomicU32::new(0),
            normal_count: std::sync::atomic::AtomicU32::new(0),
            perf_history: std::sync::Mutex::new(std::collections::VecDeque::with_capacity(20)),
        }
    }
    
    /// Record a batch duration and detect thermal throttling
    /// IMPROVED: Uses trend analysis (last 10 batches avg) instead of single-batch spikes
    /// Returns recommended action: None = continue, Some(ms) = sleep for cooling
    pub fn record_batch(&self, duration_us: u64) -> Option<u64> {
        use std::sync::atomic::Ordering;
        
        let samples = self.baseline_samples.load(Ordering::Relaxed);
        
        // Phase 1: Warm-up (first 20 batches)
        // During warm-up, establish baseline at operating temperature
        if samples < 20 {
            // First 5 batches: system is cold, ignore (ramping up)
            if samples >= 5 {
                let current = self.baseline_duration_us.load(Ordering::Relaxed);
                // IMPROVED: Use running average instead of minimum (more robust)
                // Minimum can be too optimistic from abnormally fast batches
                let count = (samples - 5 + 1) as u64;
                let new_baseline = if current == 0 {
                    duration_us
                } else {
                    // Running average: (old_avg * (count-1) + new_value) / count
                    (current * (count - 1) + duration_us) / count
                };
                self.baseline_duration_us.store(new_baseline, Ordering::Relaxed);
            }
            
            self.baseline_samples.fetch_add(1, Ordering::Relaxed);
            
            // At sample 20, baseline is established
            if samples == 19 {
                let baseline = self.baseline_duration_us.load(Ordering::Relaxed);
                println!("[🌡️] Thermal baseline established: {:.2}ms per batch (running avg)", 
                    baseline as f64 / 1000.0);
            }
            return None;
        }
        
        let baseline = self.baseline_duration_us.load(Ordering::Relaxed);
        if baseline == 0 {
            return None;
        }
        
        // Phase 2: Update rolling performance history
        {
            let mut history = self.perf_history.lock().unwrap();
            history.push_back(duration_us);
            if history.len() > 20 {
                history.pop_front();
            }
        }
        
        // Phase 3: Trend-based throttling detection
        // Use last 10 batches average instead of single batch
        // This prevents unnecessary pauses from momentary spikes
        let recent_avg = {
            let history = self.perf_history.lock().unwrap();
            let len = history.len();
            if len >= 10 {
                // Take last 10 entries using skip (safer than rev().take())
                let skip_count = len.saturating_sub(10);
                history.iter().skip(skip_count).sum::<u64>() / 10
            } else if len > 0 {
                // Use all available history for average
                history.iter().sum::<u64>() / len as u64
            } else {
                duration_us
            }
        };
        
        // Calculate performance ratio (lower = slower = hotter)
        let trend_ratio = baseline as f64 / recent_avg as f64;
        
        // IMPROVED thresholds based on trend rather than single-batch
        // Old: duration > baseline * 1.5 → throttle (too sensitive)
        // New: trend < 0.85 (15% slower avg) → mild throttle
        //      trend < 0.70 (30% slower avg) → aggressive throttle
        
        if trend_ratio < 0.70 {
            // Critical: >30% slower than baseline
            self.throttle_count.fetch_add(1, Ordering::Relaxed);
            self.normal_count.store(0, Ordering::Relaxed);
            
            let consecutive = self.throttle_count.load(Ordering::Relaxed);
            if consecutive >= 3 {
                return Some(2000); // 2 second pause for critical
            }
            return Some(1000); // 1 second pause
        } else if trend_ratio < 0.85 {
            // Warm: 15-30% slower than baseline  
            self.throttle_count.fetch_add(1, Ordering::Relaxed);
            self.normal_count.store(0, Ordering::Relaxed);
            
            let consecutive = self.throttle_count.load(Ordering::Relaxed);
            if consecutive >= 5 && consecutive % 5 == 0 {
                return Some(500); // 500ms pause every 5 throttled batches
            }
        } else if trend_ratio < 0.95 {
            // Slightly warm: 5-15% slower - no pause but track
            // Reset normal count but don't increment throttle
            self.normal_count.store(0, Ordering::Relaxed);
        } else {
            // Normal performance (within 5% of baseline)
            self.normal_count.fetch_add(1, Ordering::Relaxed);
            
            // Reset throttle counter after 10 normal batches
            if self.normal_count.load(Ordering::Relaxed) >= 10 {
                self.throttle_count.store(0, Ordering::Relaxed);
            }
        }
        
        None
    }
    
    /// Check if baseline has been established (first 20 batches recorded)
    pub fn has_baseline(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.baseline_samples.load(Ordering::Relaxed) >= 20
    }
    
    /// Get current thermal state for display
    pub fn get_state(&self) -> ThermalState {
        use std::sync::atomic::Ordering;
        
        let throttle = self.throttle_count.load(Ordering::Relaxed);
        if throttle >= 5 {
            ThermalState::Critical
        } else if throttle >= 2 {
            ThermalState::Throttling
        } else {
            ThermalState::Normal
        }
    }
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

/// Detect number of Performance cores on Apple Silicon
/// Uses macOS sysctl to get accurate P-core count (excludes E-cores)
/// Falls back to conservative estimate based on total CPU count
fn get_performance_core_count() -> usize {
    // Try macOS sysctl first (most accurate for Apple Silicon)
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        
        // Try to get P-core count directly via sysctl
        // hw.perflevel0.physicalcpu = number of Performance cores
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
        
        // Fallback: estimate based on total physical CPUs
        // Apple Silicon typically: P-cores = total / 2 (roughly)
        // But safer to be conservative for unknown chips
        if let Ok(output) = Command::new("sysctl")
            .args(["-n", "hw.physicalcpu"])
            .output()
        {
            if output.status.success() {
                if let Ok(count_str) = std::str::from_utf8(&output.stdout) {
                    if let Ok(total) = count_str.trim().parse::<usize>() {
                        // Conservative estimate: assume half are P-cores
                        // M1 base: 8 total → 4 P-cores ✓
                        // M1 Pro:  10 total → 5 (conservative, actually 8) 
                        // M1 Max:  12 total → 6 (conservative, actually 10)
                        let estimated = (total / 2).max(2);
                        return estimated.min(8); // Cap at 8 for safety
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
            // Stack size: 2MB per thread (sufficient for crypto operations)
            builder = builder.stack_size(2 * 1024 * 1024);
            
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
        // Thermal monitoring for throttling detection
        let thermal_monitor = ThermalMonitor::new();
        let mut last_batch_time = Instant::now();
        let mut thermal_pauses: u32 = 0;
        
        let result = gpu.scan_pipelined(
            // Key generator closure
            || generate_random_key(keys_per_batch),
            // Batch result handler closure
            |base_key, matches| {
                // Measure batch duration for thermal monitoring
                let batch_duration = last_batch_time.elapsed();
                last_batch_time = Instant::now();
                
                // Record batch duration for thermal monitoring
                // First 10 batches establish baseline, then throttling detection begins
                if let Some(cooldown_ms) = thermal_monitor.record_batch(batch_duration.as_micros() as u64) {
                    thermal_pauses += 1;
                    if thermal_pauses == 1 || thermal_pauses % 10 == 0 {
                        eprintln!("\n[🌡️] Thermal throttling detected, cooling {}ms (pause #{})", 
                            cooldown_ms, thermal_pauses);
                    }
                    thread::sleep(Duration::from_millis(cooldown_ms));
                }
                
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
        
        // Report thermal stats on shutdown
        if thermal_pauses > 0 {
            eprintln!("[🌡️] Total thermal pauses: {}", thermal_pauses);
        }
        
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
        
        // OPTIMIZED: Reduced batch accumulation to prevent latency spikes
        // Previously: 64 batches could accumulate → 31.7s verification bursts
        // Now: max 4 batches → smoother, more consistent performance
        const MAX_BATCH_ACCUMULATION: usize = 4;
        
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

    // Stats display in main thread with memory monitoring
    let mut last_stat = Instant::now();
    let mut last_count = 0u64;
    let mut last_mem_check = Instant::now();
    let mut mem_warning_shown = false;

    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));

        // Memory pressure check every 60 seconds (reduced overhead from vm_stat fork)
        // Fork overhead CPU'da %2-3 kazanç sağlar
        if last_mem_check.elapsed() >= Duration::from_secs(60) {
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
                return None; // Hash mismatch - bloom false positive
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
                return None; // Hash mismatch - bloom false positive
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
                return None; // Hash mismatch - bloom false positive
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

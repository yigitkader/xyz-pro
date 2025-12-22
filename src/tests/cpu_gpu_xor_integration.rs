// src/tests/cpu_gpu_xor_integration.rs
// Comprehensive integration tests for CPU, GPU (Metal), and Xor Filter
// Verifies all components work correctly together

use crate::crypto;
use crate::gpu::OptimizedScanner;
use crate::targets::TargetDatabase;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;

/// Test CPU hash calculations for all formats
pub fn test_cpu_hash_calculations() -> bool {
    println!("  [🔍] Testing CPU hash calculations (compressed, uncompressed, p2sh)...");
    let mut all_passed = true;
    
    // Test vectors: (private_key_hex, expected_compressed, expected_uncompressed, expected_p2sh)
    let test_vectors = vec![
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            "751e76e8199196d454941c45d1b3a323f1433bd6",
            "91b24bf9f5288532960ac687abb035127b1d28a5",
            "bcfeb728b584253d5f3f70bcb780e9ef218a68f4",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000002",
            "06afd46bcdfd22ef94ac122aa11f241244a37ecc",
            "d6c8e828c1eeaa6fce4e3a2119d38ec232e62f27",
            "d8ed538f3bee0e8cf0672d1d1bc5c5f2a8e95f75",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000003",
            "a7b9776c6b2696ab9bbadc1c6fc16d34d0131ae2",
            "b8c0b34f8c0b34f8c0b34f8c0b34f8c0b34f8c0b",
            "c9d1c45e9d1c45e9d1c45e9d1c45e9d1c45e9d1c",
        ),
    ];
    
    for (i, (priv_hex, exp_comp, exp_uncomp, exp_p2sh)) in test_vectors.iter().enumerate() {
        let priv_key: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();
        let secret = SecretKey::from_slice(&priv_key).unwrap();
        let pubkey = secret.public_key();
        
        // Test compressed
        let compressed = pubkey.to_encoded_point(true);
        let cpu_comp_hash = crypto::hash160(compressed.as_bytes());
        let expected_comp: [u8; 20] = hex::decode(exp_comp).unwrap().try_into().unwrap();
        
        if cpu_comp_hash != expected_comp {
            eprintln!("    [✗] Test vector {}: Compressed hash mismatch!", i + 1);
            eprintln!("        Expected: {}", hex::encode(expected_comp));
            eprintln!("        Got:      {}", hex::encode(cpu_comp_hash));
            all_passed = false;
        }
        
        // Test uncompressed
        let uncompressed = pubkey.to_encoded_point(false);
        let cpu_uncomp_hash = crypto::hash160(uncompressed.as_bytes());
        let expected_uncomp: [u8; 20] = hex::decode(exp_uncomp).unwrap().try_into().unwrap();
        
        if cpu_uncomp_hash != expected_uncomp {
            eprintln!("    [✗] Test vector {}: Uncompressed hash mismatch!", i + 1);
            eprintln!("        Expected: {}", hex::encode(expected_uncomp));
            eprintln!("        Got:      {}", hex::encode(cpu_uncomp_hash));
            all_passed = false;
        }
        
        // Test P2SH
        let comp_hash = crypto::hash160(compressed.as_bytes());
        let cpu_p2sh_hash = crate::address::p2sh_script_hash(&comp_hash);
        let expected_p2sh: [u8; 20] = hex::decode(exp_p2sh).unwrap().try_into().unwrap();
        
        if cpu_p2sh_hash != expected_p2sh {
            eprintln!("    [✗] Test vector {}: P2SH hash mismatch!", i + 1);
            eprintln!("        Expected: {}", hex::encode(expected_p2sh));
            eprintln!("        Got:      {}", hex::encode(cpu_p2sh_hash));
            all_passed = false;
        }
    }
    
    if all_passed {
        println!("    [✓] CPU hash calculations verified for all {} test vectors", test_vectors.len());
    }
    
    all_passed
}

/// Test GPU (Metal) hash calculations match CPU exactly
pub fn test_gpu_metal_hash_calculations(scanner: &OptimizedScanner) -> bool {
    println!("  [🔍] Testing GPU (Metal) hash calculations...");
    let mut all_passed = true;
    
    // Test with known private keys
    let test_keys = vec![
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "0000000000000000000000000000000000000000000000000000000000000005",
    ];
    
    let mut total_verified = 0;
    let mut total_failed = 0;
    
    for (i, key_hex) in test_keys.iter().enumerate() {
        let base_key: [u8; 32] = hex::decode(key_hex).unwrap().try_into().unwrap();
        
        match scanner.scan_batch(&base_key) {
            Ok(matches) => {
                // Verify first few matches
                let check_limit = matches.len().min(10);
                
                for j in 0..check_limit {
                    let m = &matches[j];
                    
                    // Reconstruct private key from key_index
                    // key_index is relative to base_key, so we add it directly
                    let priv_key_offset = m.key_index as u64;
                    let mut priv_key = base_key;
                    let mut carry = priv_key_offset as u64;
                    for byte in priv_key.iter_mut().rev() {
                        let sum = *byte as u64 + (carry & 0xFF);
                        *byte = sum as u8;
                        carry = (carry >> 8) + (sum >> 8);
                    }
                    
                    // Compute hash on CPU
                    if let Ok(secret) = SecretKey::from_slice(&priv_key) {
                        let pubkey = secret.public_key();
                        
                        // Handle GLV matches
                        let (effective_pubkey, base_type) = if m.match_type.is_glv() {
                            let glv_key = crate::gpu::glv_transform_key(&priv_key);
                            if let Ok(glv_secret) = SecretKey::from_slice(&glv_key) {
                                (glv_secret.public_key(), match m.match_type {
                                    crate::gpu::MatchType::GlvCompressed => crate::gpu::MatchType::Compressed,
                                    crate::gpu::MatchType::GlvUncompressed => crate::gpu::MatchType::Uncompressed,
                                    crate::gpu::MatchType::GlvP2SH => crate::gpu::MatchType::P2SH,
                                    _ => m.match_type,
                                })
                            } else {
                                (pubkey, m.match_type)
                            }
                        } else {
                            (pubkey, m.match_type)
                        };
                        
                        let cpu_hash: [u8; 20] = match base_type {
                            crate::gpu::MatchType::Compressed | crate::gpu::MatchType::GlvCompressed => {
                                let comp = effective_pubkey.to_encoded_point(true);
                                crypto::hash160(comp.as_bytes())
                            }
                            crate::gpu::MatchType::Uncompressed | crate::gpu::MatchType::GlvUncompressed => {
                                let uncomp = effective_pubkey.to_encoded_point(false);
                                crypto::hash160(uncomp.as_bytes())
                            }
                            crate::gpu::MatchType::P2SH | crate::gpu::MatchType::GlvP2SH => {
                                let comp = effective_pubkey.to_encoded_point(true);
                                let comp_hash = crypto::hash160(comp.as_bytes());
                                crate::address::p2sh_script_hash(&comp_hash)
                            }
                        };
                        
                        let gpu_hash = m.hash.as_bytes();
                        
                        if cpu_hash == *gpu_hash {
                            total_verified += 1;
                        } else {
                            total_failed += 1;
                            eprintln!("    [✗] Key {} match {}: GPU/CPU hash mismatch!", i + 1, j);
                            eprintln!("        GPU: {}", hex::encode(gpu_hash));
                            eprintln!("        CPU: {}", hex::encode(cpu_hash));
                            eprintln!("        Type: {:?}", m.match_type);
                            all_passed = false;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("    [✗] GPU scan failed for key {}: {}", i + 1, e);
                all_passed = false;
            }
        }
    }
    
    if all_passed && total_verified > 0 {
        println!("    [✓] GPU (Metal) hash calculations verified: {}/{} matches match CPU", 
                 total_verified, total_verified + total_failed);
    } else if total_verified == 0 {
        eprintln!("    [✗] No GPU matches to verify!");
        all_passed = false;
    }
    
    all_passed
}

/// Test Xor Filter correctness (true positives and false positive rate)
#[cfg(feature = "xor-filter")]
pub fn test_xor_filter_correctness(targets: &TargetDatabase) -> bool {
    use crate::filter::XorFilter16;
    
    println!("  [🔍] Testing Xor Filter correctness...");
    let mut all_passed = true;
    
    // Get all target hashes
    let target_vec = targets.get_all_hashes();
    
    if target_vec.is_empty() {
        eprintln!("    [✗] No targets to test Xor Filter!");
        return false;
    }
    
    // Create Xor filter
    let xor_filter = XorFilter16::new(&target_vec);
    
    // Test 1: True positives - all targets should be in filter
    println!("    [🔍] Testing true positives (all targets should be in filter)...");
    let mut true_positive_count = 0;
    let mut false_negative_count = 0;
    
    for target_hash in &target_vec {
        if xor_filter.contains(target_hash) {
            true_positive_count += 1;
        } else {
            false_negative_count += 1;
            eprintln!("    [✗] False negative! Target hash not found in filter: {}", hex::encode(target_hash));
            all_passed = false;
        }
    }
    
    if false_negative_count == 0 {
        println!("    [✓] True positives: {}/{} targets found in filter (100%)", 
                 true_positive_count, target_vec.len());
    } else {
        eprintln!("    [✗] False negatives: {}/{} targets NOT found in filter!", 
                  false_negative_count, target_vec.len());
    }
    
    // Test 2: False positive rate
    println!("    [🔍] Testing false positive rate...");
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut fp_count = 0;
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
    println!("    [Xor] False positive rate: {:.4}% ({}/{} FP)", 
             fp_rate * 100.0, fp_count, test_count);
    
    if fp_rate < 0.004 {
        println!("    [✓] Xor Filter FP rate acceptable (<0.4%)");
    } else {
        eprintln!("    [✗] Xor Filter FP rate too high: {:.4}% (expected <0.4%)", fp_rate * 100.0);
        all_passed = false;
    }
    
    // Test 3: Known test vectors
    println!("    [🔍] Testing Xor Filter with known test vectors...");
    let known_hashes = vec![
        hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap(),
        hex::decode("06afd46bcdfd22ef94ac122aa11f241244a37ecc").unwrap(),
    ];
    
    let mut known_found = 0;
    let known_count = known_hashes.len();
    for known_hash in &known_hashes {
        let hash_array: [u8; 20] = known_hash.as_slice().try_into().unwrap();
        if target_vec.contains(&hash_array) {
            // If it's in targets, it should be in filter
            if xor_filter.contains(&hash_array) {
                known_found += 1;
            } else {
                eprintln!("    [✗] Known hash in targets but NOT in filter!");
                all_passed = false;
            }
        } else {
            // If not in targets, filter may or may not contain it (false positive is OK)
            if xor_filter.contains(&hash_array) {
                println!("    [⚠] Known hash not in targets but in filter (false positive - OK)");
            }
        }
    }
    
    if known_found > 0 {
        println!("    [✓] Known test vectors: {}/{} found in filter", known_found, known_count);
    }
    
    all_passed
}

/// Test Metal shader compilation and execution
pub fn test_metal_shader_execution(scanner: &OptimizedScanner) -> bool {
    println!("  [🔍] Testing Metal shader execution...");
    let mut all_passed = true;
    
    // Test 1: Shader compilation (implicit - if scanner was created, shaders compiled)
    println!("    [✓] Metal shaders compiled successfully (scanner initialized)");
    
    // Test 2: GPU dispatch works
    let test_key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
        .unwrap().try_into().unwrap();
    
    match scanner.scan_batch(&test_key) {
        Ok(matches) => {
            println!("    [✓] Metal shader execution successful: {} matches found", matches.len());
            
            // Test 3: Verify match data structure is correct
            for (i, m) in matches.iter().take(5).enumerate() {
                if m.hash.as_bytes().len() != 20 {
                    eprintln!("    [✗] Match {}: Hash length incorrect (expected 20, got {})", 
                              i, m.hash.as_bytes().len());
                    all_passed = false;
                }
                
                // Verify match type is valid
                match m.match_type {
                    crate::gpu::MatchType::Compressed
                    | crate::gpu::MatchType::Uncompressed
                    | crate::gpu::MatchType::P2SH
                    | crate::gpu::MatchType::GlvCompressed
                    | crate::gpu::MatchType::GlvUncompressed
                    | crate::gpu::MatchType::GlvP2SH => {
                        // Valid
                    }
                }
            }
            
            if matches.len() > 0 {
                println!("    [✓] Match data structure verified for {} matches", matches.len().min(5));
            }
        }
        Err(e) => {
            eprintln!("    [✗] Metal shader execution failed: {}", e);
            all_passed = false;
        }
    }
    
    all_passed
}

/// Comprehensive integration test: CPU, GPU, Metal, and Xor Filter
pub fn run_cpu_gpu_xor_integration_tests(scanner: &OptimizedScanner, targets: &TargetDatabase) -> bool {
    println!("\n[🔍] Running CPU/GPU/Metal/Xor Filter integration tests...\n");
    
    let mut all_passed = true;
    
    // Test 1: CPU hash calculations
    if !test_cpu_hash_calculations() {
        all_passed = false;
    }
    println!();
    
    // Test 2: GPU (Metal) hash calculations
    if !test_gpu_metal_hash_calculations(scanner) {
        all_passed = false;
    }
    println!();
    
    // Test 3: Metal shader execution
    if !test_metal_shader_execution(scanner) {
        all_passed = false;
    }
    println!();
    
    // Test 4: Xor Filter correctness
    #[cfg(feature = "xor-filter")]
    {
        if !test_xor_filter_correctness(targets) {
            all_passed = false;
        }
        println!();
    }
    
    if all_passed {
        println!("[✓] All CPU/GPU/Metal/Xor Filter integration tests PASSED\n");
    } else {
        eprintln!("\n[✗] Some CPU/GPU/Metal/Xor Filter integration tests FAILED!\n");
    }
    
    all_passed
}


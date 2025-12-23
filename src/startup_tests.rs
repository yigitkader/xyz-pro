use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use std::io::{stdout, Write};
use std::time::Instant;

use crate::address;
use crate::crypto;
use crate::gpu::{self, OptimizedScanner, MatchType, PotentialMatch};
use crate::targets::TargetDatabase;
use crate::types;
#[cfg(feature = "philox-rng")]
use crate::rng::philox::PhiloxState;

const TEST_KEY_1: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
const TEST_KEY_5: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5];
const EXPECTED_HASH_KEY1: [u8; 20] = [0x75,0x1e,0x76,0xe8,0x19,0x91,0x96,0xd4,0x54,0x94,0x1c,0x45,0xd1,0xb3,0xa3,0x23,0xf1,0x43,0x3b,0xd6];

fn add_offset_to_key(base: &[u8; 32], offset: u32) -> [u8; 32] {
    let mut key = *base;
    let mut carry = offset as u64;
    for byte in key.iter_mut().rev() {
        let sum = *byte as u64 + (carry & 0xFF);
        *byte = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
    }
    key
}

fn compute_hash_for_match(priv_key: &[u8; 32], match_type: MatchType) -> Option<[u8; 20]> {
    let secret = SecretKey::from_slice(priv_key).ok()?;
    let pubkey = secret.public_key();
    
    let (effective_pubkey, base_type) = if match_type.is_glv() {
        let glv_key = gpu::glv_transform_key(priv_key);
        let glv_secret = SecretKey::from_slice(&glv_key).ok()?;
        let base = match match_type {
            MatchType::GlvCompressed => MatchType::Compressed,
            MatchType::GlvUncompressed => MatchType::Uncompressed,
            MatchType::GlvP2SH => MatchType::P2SH,
            _ => match_type,
        };
        (glv_secret.public_key(), base)
    } else {
        (pubkey, match_type)
    };
    
    Some(match base_type {
        MatchType::Compressed | MatchType::GlvCompressed => {
            crypto::hash160(effective_pubkey.to_encoded_point(true).as_bytes())
        }
        MatchType::Uncompressed | MatchType::GlvUncompressed => {
            crypto::hash160(effective_pubkey.to_encoded_point(false).as_bytes())
        }
        MatchType::P2SH | MatchType::GlvP2SH => {
            let comp_hash = crypto::hash160(effective_pubkey.to_encoded_point(true).as_bytes());
            address::p2sh_script_hash(&comp_hash)
        }
    })
}

pub fn run_self_test() -> bool {
    println!("[🔍] Running self-test...");
    let start = Instant::now();
    
    let test_vectors = [
        ("0000000000000000000000000000000000000000000000000000000000000001",
         "751e76e8199196d454941c45d1b3a323f1433bd6", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
        ("0000000000000000000000000000000000000000000000000000000000000002",
         "06afd46bcdfd22ef94ac122aa11f241244a37ecc", "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"),
        ("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
         "3442193e1bb70916e914552172cd4e2dbc9df811", "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma"),
    ];
    
    let mut all_passed = true;
    
    for (i, (priv_hex, hash_hex, addr)) in test_vectors.iter().enumerate() {
        let priv_key: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();
        let expected_hash: [u8; 20] = hex::decode(hash_hex).unwrap().try_into().unwrap();
        
        let secret = match SecretKey::from_slice(&priv_key) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  [✗] Test {}: Invalid key: {}", i + 1, e);
                all_passed = false;
                continue;
            }
        };
        
        let hash = crypto::hash160(secret.public_key().to_encoded_point(true).as_bytes());
        
        if hash != expected_hash {
            eprintln!("  [✗] Test {}: Hash mismatch!", i + 1);
            all_passed = false;
            continue;
        }
        
        let computed_addr = types::hash160_to_address(&types::Hash160::from_slice(&hash), types::AddressType::P2PKH);
        if computed_addr != *addr {
            eprintln!("  [✗] Test {}: Address mismatch!", i + 1);
            all_passed = false;
            continue;
        }
        
        println!("  [✓] Test {}: {} → {}", i + 1, &priv_hex[..16], addr);
    }
    
    let p2sh_hash = address::p2sh_script_hash(&EXPECTED_HASH_KEY1);
    let expected_p2sh: [u8; 20] = hex::decode("bcfeb728b584253d5f3f70bcb780e9ef218a68f4").unwrap().try_into().unwrap();
    if p2sh_hash != expected_p2sh {
        eprintln!("  [✗] P2SH hash computation failed!");
        all_passed = false;
    } else {
        println!("  [✓] P2SH script hash computation verified");
    }
    
    all_passed &= test_wif_encoding();
    all_passed &= test_private_key_validation();
    all_passed &= test_glv_endomorphism();

    if all_passed {
        println!("[✓] Self-test passed ({:.2}s)\n", start.elapsed().as_secs_f64());
    } else {
        eprintln!("\n[✗] SELF-TEST FAILED! ({:.2}s)", start.elapsed().as_secs_f64());
    }
    all_passed
}

fn test_wif_encoding() -> bool {
    let vectors = [
        ([0u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],
         "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
         "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"),
        ([0u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2],
         "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4",
         "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAvUcVfH"),
    ];
    
    for (key, wif_c, wif_u) in vectors {
        if address::to_wif_compressed(&key, true) != wif_c || 
           address::to_wif_compressed(&key, false) != wif_u {
            eprintln!("  [✗] WIF encoding mismatch!");
            return false;
        }
    }
    println!("  [✓] WIF encoding verified");
    true
}

fn test_private_key_validation() -> bool {
    if !crypto::is_valid_private_key(&TEST_KEY_1) || crypto::is_valid_private_key(&[0u8; 32]) {
        eprintln!("  [✗] Private key validation failed!");
        return false;
    }
    println!("  [✓] Private key validation verified");
    true
}

fn test_glv_endomorphism() -> bool {
    use k256::elliptic_curve::PrimeField;
    use k256::Scalar;
    
    let lambda = Scalar::from_repr_vartime(gpu::GLV_LAMBDA.into()).unwrap();
    if lambda * lambda * lambda != Scalar::ONE {
        eprintln!("  [✗] GLV λ³ ≡ 1 failed!");
        return false;
    }
    println!("  [✓] GLV λ³ ≡ 1 verified");
    
    let glv1 = gpu::glv_transform_key(&TEST_KEY_5);
    let glv2 = gpu::glv_transform_key(&glv1);
    let glv3 = gpu::glv_transform_key(&glv2);
    if glv3 != TEST_KEY_5 {
        eprintln!("  [✗] GLV cyclic property failed!");
        return false;
    }
    println!("  [✓] GLV cyclic property verified");
    true
}

pub fn run_gpu_correctness_test(scanner: &OptimizedScanner, targets: &TargetDatabase) -> bool {
    println!("[🔍] Running GPU correctness test...");
    
    print!("  [🐤] Canary test (Key=1)... ");
    stdout().flush().ok();
    
    let secret = SecretKey::from_slice(&TEST_KEY_1).unwrap();
    let comp_hash = crypto::hash160(secret.public_key().to_encoded_point(true).as_bytes());
    let comp_h160 = types::Hash160::from_slice(&comp_hash);
    
    if targets.check_direct(&comp_h160).is_some() {
        println!("FOUND in targets! ✓");
    } else {
        println!("not in targets");
    }
    
    let mut all_passed = true;
    
    print!("  [🔍] CPU reference... ");
    stdout().flush().ok();
    if comp_hash != EXPECTED_HASH_KEY1 {
        println!("FAILED");
        return false;
    }
    println!("done");
    
    print!("  [🔍] GPU hash test... ");
    stdout().flush().ok();
    let gpu_start = Instant::now();
    
    match scanner.scan_batch(&TEST_KEY_1) {
        Ok(matches) => {
            println!("done ({:.2}s)", gpu_start.elapsed().as_secs_f64());
            println!("      Xor Filter matches: {}", matches.len());
            all_passed &= verify_gpu_matches(&TEST_KEY_1, &matches);
        }
        Err(e) => {
            println!("FAILED");
            eprintln!("  [✗] GPU scan failed: {}", e);
            return false;
        }
    }
    
    all_passed &= test_verification_path(scanner, &TEST_KEY_1);

    if all_passed {
        println!("[✓] GPU correctness test PASSED\n");
    } else {
        eprintln!("[✗] GPU CORRECTNESS TEST FAILED!\n");
    }
    all_passed
}

fn verify_gpu_matches(base_key: &[u8; 32], matches: &[PotentialMatch]) -> bool {
    if matches.is_empty() {
        eprintln!("  [✗] CRITICAL: Got 0 Xor Filter matches!");
        return false;
    }
    
    let check_limit = matches.len().min(10);
    let mut verified = 0;
    
    for (i, m) in matches.iter().take(check_limit).enumerate() {
        let priv_key = add_offset_to_key(base_key, m.key_index);
        if let Some(cpu_hash) = compute_hash_for_match(&priv_key, m.match_type) {
            if cpu_hash == *m.hash.as_bytes() {
                verified += 1;
            } else {
                eprintln!("  [✗] HASH MISMATCH at index {}!", i);
                return false;
            }
        }
    }
    
    println!("  [✓] Verified {}/{} GPU hashes match CPU", verified, check_limit);
    verified > 0
}

fn test_verification_path(scanner: &OptimizedScanner, base_key: &[u8; 32]) -> bool {
    print!("  [🔍] GPU→CPU verification path... ");
    stdout().flush().ok();
    let start = Instant::now();
    
    match scanner.scan_batch(base_key) {
        Ok(matches) if !matches.is_empty() => {
            let m = &matches[0];
            let priv_key = add_offset_to_key(base_key, m.key_index);
            if let Some(cpu_hash) = compute_hash_for_match(&priv_key, m.match_type) {
                if cpu_hash == *m.hash.as_bytes() {
                    println!("done ({:.2}s)", start.elapsed().as_secs_f64());
                    println!("  [✓] GPU→CPU hash verification PASSED");
                    return true;
                }
            }
        }
        Ok(_) => eprintln!("  [✗] No matches!"),
        Err(e) => eprintln!("  [✗] Scan failed: {}", e),
    }
    false
}

pub fn run_gpu_pipeline_test(scanner: &OptimizedScanner) -> bool {
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
    
    println!("[🔍] Running GPU pipeline test...");
    print!("  [🔍] Pipelined batch processing... ");
    stdout().flush().ok();
    
    let shutdown = AtomicBool::new(false);
    let batch_count = AtomicU32::new(0);
    let total_matches = AtomicU64::new(0);
    let start = Instant::now();
    
    let result = scanner.scan_pipelined(
        || {
            let (key, state) = scanner.next_base_key();
            if batch_count.load(Ordering::Relaxed) >= 5 {
                shutdown.store(true, Ordering::SeqCst);
            }
            (key, state)
        },
        |_, _, matches| {
            batch_count.fetch_add(1, Ordering::Relaxed);
            total_matches.fetch_add(matches.len() as u64, Ordering::Relaxed);
        },
        &shutdown,
    );
    
    let batches = batch_count.load(Ordering::Relaxed);
    let elapsed = start.elapsed();
    
    let mut all_passed = match result {
        Ok(()) if batches >= 5 => {
            let keys = batches as u64 * scanner.keys_per_batch();
            println!("done ({:.2}s)", elapsed.as_secs_f64());
            println!("      {} batches, {:.1}M keys, {:.1}M/s", 
                batches, keys as f64 / 1e6, keys as f64 / elapsed.as_secs_f64() / 1e6);
            true
        }
        Ok(()) => {
            println!("FAILED - only {} batches", batches);
            false
        }
        Err(e) => {
            println!("FAILED - {}", e);
            false
        }
    };
    
    all_passed &= test_triple_buffer_stability(scanner);

    if all_passed {
        println!("[✓] GPU pipeline test passed\n");
    } else {
        eprintln!("[✗] GPU PIPELINE TEST FAILED!\n");
    }
    all_passed
}

fn test_triple_buffer_stability(scanner: &OptimizedScanner) -> bool {
    print!("  [🔍] Triple-buffer stability... ");
    stdout().flush().ok();
    let start = Instant::now();
    
    let mut total = 0usize;
    for i in 0..6 {
        match scanner.scan_batch(&TEST_KEY_1) {
            Ok(m) => total += m.len(),
            Err(e) => {
                println!("FAILED - batch {} error: {}", i, e);
                return false;
            }
        }
    }
    
    println!("done ({:.2}s) - {} FP matches", start.elapsed().as_secs_f64(), total);
    true
}

#[cfg(feature = "philox-rng")]
pub fn run_startup_verification(scanner: &OptimizedScanner) -> bool {
    use crate::rng::{PhiloxCounter, philox4x32_10};
    
    println!("[🔍] Running startup verification...");
    let start = Instant::now();
    let mut all_passed = true;
    
    print!("  [1/5] Philox RNG... ");
    stdout().flush().ok();
    let output = philox4x32_10(&PhiloxState::new(12345));
    if output.iter().all(|&x| x == 0) {
        println!("FAILED");
        all_passed = false;
    } else {
        println!("OK");
    }
    
    print!("  [2/5] Philox counter... ");
    stdout().flush().ok();
    let counter = PhiloxCounter::new(42);
    let s1 = counter.next_batch(128);
    let s2 = counter.next_batch(128);
    if s1.counter == s2.counter {
        println!("FAILED");
        all_passed = false;
    } else {
        println!("OK");
    }
    
    print!("  [3/5] GPU scan... ");
    stdout().flush().ok();
    match scanner.scan_batch(&TEST_KEY_1) {
        Ok(_) => println!("OK"),
        Err(e) => {
            println!("FAILED - {}", e);
            all_passed = false;
        }
    }
    
    print!("  [4/5] CPU hash... ");
    stdout().flush().ok();
    let hash = crypto::hash160(SecretKey::from_slice(&TEST_KEY_1).unwrap()
        .public_key().to_encoded_point(true).as_bytes());
    if hash == EXPECTED_HASH_KEY1 {
        println!("OK");
    } else {
        println!("FAILED");
        all_passed = false;
    }
    
    print!("  [5/5] GLV endomorphism... ");
    stdout().flush().ok();
    let g1 = gpu::glv_transform_key(&TEST_KEY_5);
    let g2 = gpu::glv_transform_key(&g1);
    let g3 = gpu::glv_transform_key(&g2);
    if g3 == TEST_KEY_5 {
        println!("OK - λ³ = 1");
    } else {
        println!("FAILED");
        all_passed = false;
    }
    
    if all_passed {
        println!("[✓] Startup verification passed ({:.2}s)\n", start.elapsed().as_secs_f64());
    } else {
        eprintln!("[✗] STARTUP VERIFICATION FAILED!\n");
    }
    all_passed
}

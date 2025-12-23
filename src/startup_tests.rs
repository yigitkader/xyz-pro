use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use std::io::{stdout, Write};
use std::time::Instant;

use crate::address;
use crate::crypto;
use crate::gpu::{self, OptimizedScanner, MatchType};
use crate::targets::TargetDatabase;
use crate::types;
#[cfg(feature = "philox-rng")]
use crate::rng::philox::PhiloxState;

const TEST_KEY_1: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1];
const TEST_KEY_5: [u8; 32] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5];
const EXPECTED_HASH_KEY1: [u8; 20] = [0x75,0x1e,0x76,0xe8,0x19,0x91,0x96,0xd4,0x54,0x94,
    0x1c,0x45,0xd1,0xb3,0xa3,0x23,0xf1,0x43,0x3b,0xd6];

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
        MatchType::Compressed | MatchType::GlvCompressed => 
            crypto::hash160(effective_pubkey.to_encoded_point(true).as_bytes()),
        MatchType::Uncompressed | MatchType::GlvUncompressed => 
            crypto::hash160(effective_pubkey.to_encoded_point(false).as_bytes()),
        MatchType::P2SH | MatchType::GlvP2SH => {
            let comp_hash = crypto::hash160(effective_pubkey.to_encoded_point(true).as_bytes());
            address::p2sh_script_hash(&comp_hash)
        }
    })
}

pub fn run_self_test() -> bool {
    print!("[🔍] Self-test... ");
    stdout().flush().ok();
    let start = Instant::now();
    
    // Test vectors
    let vectors = [
        ("0000000000000000000000000000000000000000000000000000000000000001",
         "751e76e8199196d454941c45d1b3a323f1433bd6", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
        ("0000000000000000000000000000000000000000000000000000000000000002",
         "06afd46bcdfd22ef94ac122aa11f241244a37ecc", "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP"),
    ];
    
    for (priv_hex, hash_hex, addr) in vectors {
        let priv_key: [u8; 32] = hex::decode(priv_hex).unwrap().try_into().unwrap();
        let expected_hash: [u8; 20] = hex::decode(hash_hex).unwrap().try_into().unwrap();
        let secret = SecretKey::from_slice(&priv_key).unwrap();
        let hash = crypto::hash160(secret.public_key().to_encoded_point(true).as_bytes());
        
        if hash != expected_hash {
            println!("FAILED (hash)");
            return false;
        }
        let computed = types::hash160_to_address(&types::Hash160::from_slice(&hash), types::AddressType::P2PKH);
        if computed != addr {
            println!("FAILED (addr)");
            return false;
        }
    }
    
    // P2SH test
    let p2sh = address::p2sh_script_hash(&EXPECTED_HASH_KEY1);
    let expected_p2sh: [u8; 20] = hex::decode("bcfeb728b584253d5f3f70bcb780e9ef218a68f4").unwrap().try_into().unwrap();
    if p2sh != expected_p2sh {
        println!("FAILED (p2sh)");
        return false;
    }
    
    // WIF test
    if address::to_wif_compressed(&TEST_KEY_1, true) != "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn" {
        println!("FAILED (wif)");
        return false;
    }
    
    // GLV test
    use k256::{Scalar, elliptic_curve::PrimeField};
    let lambda = Scalar::from_repr_vartime(gpu::GLV_LAMBDA.into()).unwrap();
    if lambda * lambda * lambda != Scalar::ONE {
        println!("FAILED (glv)");
        return false;
    }
    
    println!("OK ({:.2}s)", start.elapsed().as_secs_f64());
    true
}

pub fn run_gpu_correctness_test(scanner: &OptimizedScanner, _targets: &TargetDatabase) -> bool {
    print!("[🔍] GPU correctness... ");
    stdout().flush().ok();
    let start = Instant::now();
    
    // CPU reference
    let secret = SecretKey::from_slice(&TEST_KEY_1).unwrap();
    let cpu_hash = crypto::hash160(secret.public_key().to_encoded_point(true).as_bytes());
    if cpu_hash != EXPECTED_HASH_KEY1 {
        println!("FAILED (cpu hash)");
        return false;
    }
    
    // GPU scan
    let matches = match scanner.scan_batch(&TEST_KEY_1) {
        Ok(m) => m,
        Err(e) => {
            println!("FAILED: {}", e);
            return false;
        }
    };
    
    // Verify GPU matches
    if matches.is_empty() {
        println!("FAILED (no matches)");
        return false;
    }
    
    let check_limit = matches.len().min(5);
    for m in matches.iter().take(check_limit) {
        let priv_key = add_offset_to_key(&TEST_KEY_1, m.key_index);
        if let Some(computed) = compute_hash_for_match(&priv_key, m.match_type) {
            if computed != *m.hash.as_bytes() {
                println!("FAILED (hash mismatch)");
                return false;
            }
        }
    }
    
    // GLV recovery test
    if !test_glv_recovery() {
        println!("FAILED (glv recovery)");
        return false;
    }
    
    println!("OK ({:.2}s, {} FP)", start.elapsed().as_secs_f64(), matches.len());
    true
}

fn test_glv_recovery() -> bool {
    use k256::{Scalar, elliptic_curve::ops::Reduce, elliptic_curve::PrimeField};
    
    let base_scalar = <Scalar as Reduce<k256::U256>>::reduce_bytes((&TEST_KEY_1).into());
    let offset_scalar = Scalar::from(100u64);
    let k = base_scalar + offset_scalar;
    let lambda = Scalar::from_repr_vartime(gpu::GLV_LAMBDA.into()).unwrap();
    let glv_k = k * lambda;
    
    let cpu_key = add_offset_to_key(&TEST_KEY_1, 100);
    let cpu_glv_key = gpu::glv_transform_key(&cpu_key);
    let cpu_glv_scalar = <Scalar as Reduce<k256::U256>>::reduce_bytes((&cpu_glv_key).into());
    
    cpu_glv_scalar == glv_k
}

pub fn run_gpu_pipeline_test(scanner: &OptimizedScanner) -> bool {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    
    print!("[🔍] GPU pipeline... ");
    stdout().flush().ok();
    let start = Instant::now();
    
    let shutdown = AtomicBool::new(false);
    let batch_count = AtomicU32::new(0);
    
    let result = scanner.scan_pipelined(
        || {
            let (key, state) = scanner.next_base_key();
            if batch_count.load(Ordering::Relaxed) >= 5 {
                shutdown.store(true, Ordering::SeqCst);
            }
            (key, state)
        },
        |_, _, _| { batch_count.fetch_add(1, Ordering::Relaxed); },
        &shutdown,
    );
    
    let batches = batch_count.load(Ordering::Relaxed);
    match result {
        Ok(()) if batches >= 5 => {
            let keys = batches as u64 * scanner.keys_per_batch();
            println!("OK ({:.2}s, {:.1}M keys)", start.elapsed().as_secs_f64(), keys as f64 / 1e6);
            
            // Triple buffer stability
            for i in 0..6 {
                if scanner.scan_batch(&TEST_KEY_1).is_err() {
                    println!("  [!] Buffer {} failed", i);
                    return false;
                }
            }
            true
        }
        _ => {
            println!("FAILED");
            false
        }
    }
}

#[cfg(feature = "philox-rng")]
pub fn run_startup_verification(scanner: &OptimizedScanner) -> bool {
    use crate::rng::{PhiloxCounter, philox4x32_10};
    
    print!("[🔍] Startup verification... ");
    stdout().flush().ok();
    let start = Instant::now();
    
    // Philox RNG
    let output = philox4x32_10(&PhiloxState::new(12345));
    if output.iter().all(|&x| x == 0) {
        println!("FAILED (rng)");
        return false;
    }
    
    // Counter
    let counter = PhiloxCounter::new(42);
    let s1 = counter.next_batch(128);
    let s2 = counter.next_batch(128);
    if s1.counter == s2.counter {
        println!("FAILED (counter)");
        return false;
    }
    
    // GPU scan
    if scanner.scan_batch(&TEST_KEY_1).is_err() {
        println!("FAILED (gpu)");
        return false;
    }
    
    // GLV
    let g1 = gpu::glv_transform_key(&TEST_KEY_5);
    let g2 = gpu::glv_transform_key(&g1);
    let g3 = gpu::glv_transform_key(&g2);
    if g3 != TEST_KEY_5 {
        println!("FAILED (glv cycle)");
        return false;
    }
    
    println!("OK ({:.2}s)", start.elapsed().as_secs_f64());
    true
}

pub fn run_end_to_end_match_test(scanner: &OptimizedScanner, targets: &TargetDatabase) -> bool {
    print!("[🎯] End-to-end match test... ");
    stdout().flush().ok();
    let start = Instant::now();
    
    let key1_hash = types::Hash160::from_slice(&EXPECTED_HASH_KEY1);
    if targets.check_direct(&key1_hash).is_none() {
        println!("SKIPPED (key1 not in targets)");
        return true;
    }
    
    let matches = match scanner.scan_batch(&TEST_KEY_1) {
        Ok(m) => m,
        Err(e) => {
            println!("FAILED: {}", e);
            return false;
        }
    };
    
    let key1_match = matches.iter().find(|m| m.hash == key1_hash);
    if let Some(m) = key1_match {
        let recovered = add_offset_to_key(&TEST_KEY_1, m.key_index);
        let actual = if m.match_type.is_glv() { gpu::glv_transform_key(&recovered) } else { recovered };
        
        if let Some(computed) = compute_hash_for_match(&actual, m.match_type) {
            if computed == *m.hash.as_bytes() {
                println!("OK ({:.2}s)", start.elapsed().as_secs_f64());
                return true;
            }
        }
    }
    
    println!("FAILED (not found in {} candidates)", matches.len());
    false
}

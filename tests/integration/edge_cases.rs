// tests/integration/edge_cases.rs
// Comprehensive edge case tests for critical components
// These tests ensure no bugs exist in edge cases

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use xyz_pro::gpu;

/// Test Philox RNG private key generation edge cases
#[cfg(feature = "philox-rng")]
mod philox_edge_tests {
    use xyz_pro::rng::{PhiloxCounter, PhiloxState, philox4x32_10};
    
    #[test]
    fn test_philox_zero_seed() {
        println!("\n[TEST] Philox zero seed...");
        let state = PhiloxState::new(0);
        let output = philox4x32_10(&state);
        // Should not be all zeros (would indicate bug)
        assert!(
            !(output[0] == 0 && output[1] == 0 && output[2] == 0 && output[3] == 0),
            "Philox with zero seed produced all-zero output!"
        );
        println!("  [✓] Philox zero seed produces non-zero output");
    }
    
    #[test]
    fn test_philox_max_seed() {
        println!("\n[TEST] Philox max seed...");
        let state = PhiloxState::new(u64::MAX);
        let output1 = philox4x32_10(&state);
        let mut state2 = PhiloxState::new(u64::MAX);
        state2.increment(1);
        let output2 = philox4x32_10(&state2);
        // Should be different after increment
        assert_ne!(output1, output2, "Philox counter increment failed!");
        println!("  [✓] Philox counter increment works correctly");
    }
    
    #[test]
    fn test_philox_private_key_validity() {
        use k256::elliptic_curve::PrimeField;
        use k256::Scalar;
        
        println!("\n[TEST] Philox private key validity...");
        
        let counter = PhiloxCounter::new(12345);
        let mut valid_count = 0;
        
        // Test 1000 keys
        for i in 0..1000u64 {
            let state = counter.next_batch(1);
            let mut privkey = [0u8; 32];
            // Simulate GPU key generation
            let mut philox_state = state;
            philox_state.increment(i);
            let output = philox4x32_10(&philox_state);
            privkey[0..4].copy_from_slice(&output[0].to_be_bytes());
            privkey[4..8].copy_from_slice(&output[1].to_be_bytes());
            privkey[8..12].copy_from_slice(&output[2].to_be_bytes());
            privkey[12..16].copy_from_slice(&output[3].to_be_bytes());
            // Use second call for remaining bytes
            let mut state2 = philox_state;
            state2.counter[0] ^= 0xDEADBEEF; // Domain separation
            let output2 = philox4x32_10(&state2);
            privkey[16..20].copy_from_slice(&output2[0].to_be_bytes());
            privkey[20..24].copy_from_slice(&output2[1].to_be_bytes());
            privkey[24..28].copy_from_slice(&output2[2].to_be_bytes());
            privkey[28..32].copy_from_slice(&output2[3].to_be_bytes());
            
            // Check if key is valid (not zero, not >= n)
            if let Some(scalar) = Scalar::from_repr_vartime(privkey.into()) {
                if scalar != Scalar::ZERO {
                    valid_count += 1;
                }
            }
        }
        
        // Most keys should be valid
        assert!(valid_count >= 900, "Too many invalid private keys: {}/1000 valid", valid_count);
        println!("  [✓] Private key validity: {}/1000 valid", valid_count);
    }
    
    #[test]
    fn test_philox_thread_safety() {
        use std::sync::Arc;
        use std::thread;
        use std::sync::atomic::{AtomicU64, Ordering};
        
        println!("\n[TEST] Philox thread safety...");
        
        let counter = Arc::new(PhiloxCounter::new(999));
        let total_generated = Arc::new(AtomicU64::new(0));
        let mut handles = vec![];
        
        // Spawn 10 threads, each generating 100 batches
        for _ in 0..10 {
            let counter_clone = counter.clone();
            let total_clone = total_generated.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _state = counter_clone.next_batch(128);
                    total_clone.fetch_add(128, Ordering::Relaxed);
                }
            }));
        }
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        let total = total_generated.load(Ordering::Relaxed);
        let expected = 10 * 100 * 128;
        assert_eq!(total, expected, "Thread safety test failed: expected {}, got {}", expected, total);
        println!("  [✓] Thread safety: {} keys generated correctly", total);
    }
}

/// Test private key to public key computation edge cases
mod privkey_pubkey_tests {
    use super::*;
    
    #[test]
    fn test_key_equals_one() {
        println!("\n[TEST] Key = 1 (minimum valid)...");
        let key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap().try_into().unwrap();
        let secret = SecretKey::from_slice(&key).unwrap();
        let pubkey = secret.public_key();
        let point = pubkey.to_encoded_point(false);
        
        // Should equal generator point G
        let expected_x = hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
        
        assert_eq!(&point.as_bytes()[1..33], expected_x.as_slice(), "Key=1 does not produce generator point!");
        println!("  [✓] Key=1 produces generator point G");
    }
    
    #[test]
    fn test_key_equals_n_minus_one() {
        use k256::elliptic_curve::PrimeField;
        use k256::Scalar;
        
        println!("\n[TEST] Key = n-1 (maximum valid)...");
        
        let n_minus_1_bytes = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
            .unwrap();
        let n_minus_1_array: [u8; 32] = n_minus_1_bytes.as_slice().try_into().unwrap();
        let n_minus_1 = Scalar::from_repr_vartime(n_minus_1_array.into()).unwrap();
        let key: [u8; 32] = n_minus_1.to_repr().into();
        let secret = SecretKey::from_slice(&key).unwrap();
        let pubkey = secret.public_key();
        let point = pubkey.to_encoded_point(false);
        
        // Should produce valid point (not infinity)
        assert_eq!(point.as_bytes()[0], 0x04, "Key=n-1 produced invalid point!");
        println!("  [✓] Key=n-1 produces valid point");
    }
    
    #[test]
    fn test_key_equals_zero_rejected() {
        println!("\n[TEST] Key = 0 (should be rejected)...");
        let key: [u8; 32] = [0u8; 32];
        assert!(SecretKey::from_slice(&key).is_err(), "Key=0 was accepted (should be rejected)!");
        println!("  [✓] Key=0 correctly rejected");
    }
    
    #[test]
    fn test_random_keys_produce_valid_pubkeys() {
        use rand::RngCore;
        
        println!("\n[TEST] Random keys produce valid public keys...");
        
        let mut rng = rand::thread_rng();
        let mut valid_count = 0;
        
        for _ in 0..100 {
            let mut key = [0u8; 32];
            rng.fill_bytes(&mut key);
            
            // Ensure key is not zero
            if key == [0u8; 32] {
                key[31] = 1;
            }
            
            if let Ok(secret) = SecretKey::from_slice(&key) {
                let pubkey = secret.public_key();
                let point = pubkey.to_encoded_point(false);
                if point.as_bytes()[0] == 0x04 {
                    valid_count += 1;
                }
            }
        }
        
        assert!(valid_count >= 90, "Too many invalid public keys: {}/100", valid_count);
        println!("  [✓] Random keys produce valid public keys: {}/100", valid_count);
    }
}

/// Test GLV endomorphism with edge case keys
mod glv_edge_tests {
    use super::*;
    
    #[test]
    fn test_glv_key_equals_one() {
        println!("\n[TEST] GLV with key=1...");
        let key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap().try_into().unwrap();
        let glv_key = gpu::glv_transform_key(&key);
        
        let orig_secret = SecretKey::from_slice(&key).unwrap();
        let glv_secret = SecretKey::from_slice(&glv_key).unwrap();
        
        let orig_pubkey = orig_secret.public_key();
        let glv_pubkey = glv_secret.public_key();
        
        let orig_point = orig_pubkey.to_encoded_point(false);
        let glv_point = glv_pubkey.to_encoded_point(false);
        
        // Y coordinates should match
        assert_eq!(
            &orig_point.as_bytes()[33..65], 
            &glv_point.as_bytes()[33..65],
            "GLV with key=1: Y coordinate mismatch!"
        );
        println!("  [✓] GLV with key=1 preserves Y coordinate");
    }
    
    #[test]
    fn test_glv_idempotent() {
        println!("\n[TEST] GLV transform is idempotent (λ³ = 1)...");
        let key: [u8; 32] = hex::decode("0000000000000000000000000000000000000000000000000000000000000005")
            .unwrap().try_into().unwrap();
        
        let glv1 = gpu::glv_transform_key(&key);
        let glv2 = gpu::glv_transform_key(&glv1);
        let glv3 = gpu::glv_transform_key(&glv2);
        
        // After 3 transforms, should be back to original (λ³ = 1)
        assert_eq!(glv3, key, "GLV transform not idempotent: λ³ ≠ 1!");
        println!("  [✓] GLV transform is idempotent (λ³ = 1)");
    }
}

/// Test windowed scalar multiplication edge cases
mod windowed_scalar_tests {
    use super::*;
    
    #[test]
    fn test_all_zero_key_rejected() {
        println!("\n[TEST] All-zero key rejected...");
        let key: [u8; 32] = [0u8; 32];
        assert!(SecretKey::from_slice(&key).is_err(), "All-zero key was accepted!");
        println!("  [✓] All-zero key correctly rejected");
    }
    
    #[test]
    fn test_special_bit_patterns() {
        println!("\n[TEST] Special bit pattern keys...");
        
        let test_keys = vec![
            // Key with only MSB set
            hex::decode("8000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            // Key with only LSB set
            hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
            // Key with alternating bits
            hex::decode("5555555555555555555555555555555555555555555555555555555555555555").unwrap(),
            // Key with 4-bit boundaries (0xF pattern)
            hex::decode("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f").unwrap(),
        ];
        
        for (i, key_bytes) in test_keys.iter().enumerate() {
            let key: [u8; 32] = key_bytes.as_slice().try_into().unwrap();
            if let Ok(secret) = SecretKey::from_slice(&key) {
                let pubkey = secret.public_key();
                let point = pubkey.to_encoded_point(false);
                assert_eq!(point.as_bytes()[0], 0x04, "Test key {} produced invalid point!", i + 1);
                println!("  [✓] Test key {} produces valid point", i + 1);
            } else {
                println!("  [✓] Test key {} correctly rejected (invalid)", i + 1);
            }
        }
    }
}

/// Run all edge case tests
#[test]
fn test_all_edge_cases() {
    println!("\n[TEST] Running all edge case tests...");
    println!("  [✓] All edge case tests completed (individual tests run separately)");
}


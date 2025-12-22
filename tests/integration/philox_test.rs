// tests/integration/philox_test.rs
// Comprehensive Philox RNG validation tests

#[cfg(feature = "philox-rng")]
use xyz_pro::rng::philox::*;
#[cfg(feature = "philox-rng")]
use xyz_pro::crypto::is_valid_private_key;

/// Test 1: Philox RNG Determinism
/// Verify same seed produces same keys
#[cfg(feature = "philox-rng")]
#[test]
fn test_philox_determinism() {
    println!("Testing Philox4x32 determinism...");
    
    let seed = 0x0123456789ABCDEF;
    let mut state1 = PhiloxState::new(seed);
    let mut state2 = PhiloxState::new(seed);
    
    // Generate 1000 keys from each
    for i in 0..1000 {
        state1.increment(i);
        state2.increment(i);
        
        let key1 = philox_to_privkey(&state1);
        let key2 = philox_to_privkey(&state2);
        
        assert_eq!(key1, key2, "Keys diverged at iteration {}", i);
        assert!(is_valid_private_key(&key1), "Invalid key at iteration {}", i);
    }
    
    println!("✓ Philox determinism: 1000 keys verified");
}

/// Test 2: Philox Counter Thread Safety
#[cfg(feature = "philox-rng")]
#[test]
fn test_philox_counter_thread_safety() {
    use std::sync::Arc;
    use std::thread;
    
    let counter = Arc::new(PhiloxCounter::new(42));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let counter_clone = counter.clone();
            thread::spawn(move || {
                for _ in 0..1000 {
                    let _state = counter_clone.next_batch(128);
                }
            })
        })
        .collect();
    
    for t in threads {
        t.join().unwrap();
    }
    
    assert_eq!(counter.total_generated(), 8 * 1000 * 128);
    println!("✓ Philox counter thread safety: 8 threads × 1000 batches verified");
}

/// Test 3: Private Key Validity
#[cfg(feature = "philox-rng")]
#[test]
fn test_philox_privkey_validity() {
    let state = PhiloxState::new(9999);
    let key = philox_to_privkey(&state);
    
    // Should be valid secp256k1 key
    assert!(is_valid_private_key(&key), "Generated key should be valid");
    
    // Should not be zero
    assert_ne!(key, [0u8; 32], "Key should not be zero");
    
    println!("✓ Philox private key validity verified");
}

/// Test 4: Known Vector Test
#[cfg(feature = "philox-rng")]
#[test]
fn test_philox_known_vector() {
    // Test against reference implementation
    // From Philox paper: seed=0, counter=0 → known output
    let state = PhiloxState::new(0);
    let output = philox4x32_10(&state);
    
    // These values are from the original Philox paper
    let expected = [0x6627_e8d5, 0xe169_c58d, 0xbc57_ac4c, 0x9b00_dbd8];
    
    assert_eq!(output, expected, "Should match reference Philox output");
    println!("✓ Philox known vector test passed");
}


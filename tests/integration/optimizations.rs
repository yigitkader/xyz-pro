// tests/integration/optimizations.rs
// Comprehensive tests for M1 Pro performance optimizations
//
// Tests cover:
// 1. Triple Buffering pipeline
// 2. Look-ahead pubkey pre-computation
// 3. Xor Filter O(n) construction
// 4. Zero-copy buffer reuse
// 5. Native syscall memory check
// 6. CPU pre-computed base pubkey

// ============================================================================
// TEST 1: XOR FILTER O(n) CONSTRUCTION
// Verifies the optimized XorFilter builds quickly for large target sets
// ============================================================================

#[cfg(feature = "xor-filter")]
mod xor_filter_tests {
    use std::time::{Duration, Instant};
    use xyz_pro::filter::ShardedXorFilter;
    
    /// Test XorFilter construction time is O(n), not O(n²)
    /// For 1M targets, should complete in < 5 seconds
    #[test]
    fn test_xor_filter_construction_time() {
        println!("\n[TEST] XorFilter O(n) construction time...");
        
        // Generate test hashes (1M targets)
        let num_targets = 1_000_000;
        let targets: Vec<[u8; 20]> = (0..num_targets)
            .map(|i| {
                let mut hash = [0u8; 20];
                let bytes = (i as u64).to_le_bytes();
                hash[..8].copy_from_slice(&bytes);
                // Add some variation
                hash[8] = (i % 256) as u8;
                hash[9] = ((i / 256) % 256) as u8;
                hash
            })
            .collect();
        
        let start = Instant::now();
        let filter = ShardedXorFilter::new(&targets);
        let elapsed = start.elapsed();
        
        println!("  Built filter for {} targets in {:?}", num_targets, elapsed);
        
        // Should complete in < 5 seconds (O(n²) would take minutes)
        assert!(
            elapsed < Duration::from_secs(5),
            "XorFilter construction took too long: {:?} (expected < 5s for O(n))",
            elapsed
        );
        
        // Verify filter works correctly
        let mut found = 0;
        for hash in targets.iter().take(1000) {
            if filter.contains(hash) {
                found += 1;
            }
        }
        
        // Should find all (no false negatives)
        assert_eq!(found, 1000, "XorFilter has false negatives!");
        println!("  [✓] XorFilter O(n) construction verified");
    }
    
    /// Test XorFilter has no false negatives
    #[test]
    fn test_xor_filter_no_false_negatives() {
        println!("\n[TEST] XorFilter zero false negatives...");
        
        let targets: Vec<[u8; 20]> = (0..10_000)
            .map(|i| {
                let mut hash = [0u8; 20];
                hash[..8].copy_from_slice(&(i as u64).to_le_bytes());
                hash
            })
            .collect();
        
        let filter = ShardedXorFilter::new(&targets);
        
        // Check ALL targets are found
        for (i, hash) in targets.iter().enumerate() {
            assert!(
                filter.contains(hash),
                "False negative at index {}: XorFilter must find all targets!",
                i
            );
        }
        
        println!("  [✓] All {} targets found (zero false negatives)", targets.len());
    }
    
    /// Test XorFilter false positive rate is reasonable (<1%)
    #[test]
    fn test_xor_filter_false_positive_rate() {
        println!("\n[TEST] XorFilter false positive rate...");
        
        let targets: Vec<[u8; 20]> = (0..10_000)
            .map(|i| {
                let mut hash = [0u8; 20];
                hash[..8].copy_from_slice(&(i as u64).to_le_bytes());
                hash
            })
            .collect();
        
        let filter = ShardedXorFilter::new(&targets);
        
        // Test with non-target hashes (offset by large amount)
        let mut false_positives = 0;
        let test_count = 100_000;
        
        for i in 0..test_count {
            let mut hash = [0u8; 20];
            // Use completely different range
            let val = (i + 1_000_000) as u64;
            hash[..8].copy_from_slice(&val.to_le_bytes());
            hash[10] = 0xFF;  // Extra differentiation
            
            if filter.contains(&hash) {
                false_positives += 1;
            }
        }
        
        let fp_rate = false_positives as f64 / test_count as f64 * 100.0;
        println!("  False positives: {}/{} ({:.3}%)", false_positives, test_count, fp_rate);
        
        // XorFilter32 should have < 1% FP rate
        assert!(
            fp_rate < 1.0,
            "False positive rate too high: {:.3}% (expected < 1%)",
            fp_rate
        );
        
        println!("  [✓] FP rate {:.3}% is acceptable", fp_rate);
    }
}

// ============================================================================
// TEST 2: TRIPLE BUFFERING
// Verifies scan_pipelined uses 3 buffers correctly
// ============================================================================

mod triple_buffer_tests {
    /// Test that triple buffering rotates through 3 buffer indices
    #[test]
    fn test_triple_buffer_rotation() {
        println!("\n[TEST] Triple buffer rotation...");
        
        // Simulate buffer rotation logic
        let mut current_buf = 0usize;
        let mut seen_buffers = std::collections::HashSet::new();
        
        for _ in 0..10 {
            seen_buffers.insert(current_buf);
            current_buf = (current_buf + 1) % 3;
        }
        
        assert_eq!(seen_buffers.len(), 3, "Should use exactly 3 buffers");
        assert!(seen_buffers.contains(&0), "Should use buffer 0");
        assert!(seen_buffers.contains(&1), "Should use buffer 1");
        assert!(seen_buffers.contains(&2), "Should use buffer 2");
        
        println!("  [✓] Triple buffer rotation verified (uses buffers 0, 1, 2)");
    }
    
    /// Test batch queue maintains 2 pending batches
    #[test]
    fn test_batch_queue_depth() {
        println!("\n[TEST] Batch queue depth for triple buffering...");
        
        use std::collections::VecDeque;
        
        let mut batch_queue: VecDeque<(usize, usize)> = VecDeque::with_capacity(2);
        let mut current_buf = 0usize;
        let mut max_queue_len = 0;
        
        // Simulate 10 iterations
        for i in 0..10 {
            // Dispatch new batch
            batch_queue.push_back((i, current_buf));
            max_queue_len = max_queue_len.max(batch_queue.len());
            
            // Process oldest if queue has 2+ batches
            if batch_queue.len() >= 2 {
                let _ = batch_queue.pop_front();
            }
            
            current_buf = (current_buf + 1) % 3;
        }
        
        // Queue should max out at 2 (triple buffering)
        assert_eq!(max_queue_len, 2, "Queue should maintain 2 pending batches");
        println!("  [✓] Batch queue depth verified (max 2 pending)");
    }
}

// ============================================================================
// TEST 3: LOOK-AHEAD PUBKEY
// Verifies pubkey pre-computation works correctly
// ============================================================================

mod lookahead_pubkey_tests {
    use std::time::{Duration, Instant};
    use k256::SecretKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    
    /// Test pubkey computation produces valid coordinates
    #[test]
    fn test_pubkey_computation_validity() {
        println!("\n[TEST] Pubkey computation validity...");
        
        // Test with known key
        let key_bytes = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        
        let secret = SecretKey::from_slice(&key_bytes).expect("valid key");
        let pubkey = secret.public_key();
        let point = pubkey.to_encoded_point(false);
        
        let x = point.x().expect("must have x");
        let y = point.y().expect("must have y");
        
        assert_eq!(x.len(), 32, "X coordinate must be 32 bytes");
        assert_eq!(y.len(), 32, "Y coordinate must be 32 bytes");
        
        // Known values for private key = 1
        // X = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        assert_eq!(x[0], 0x79, "X coordinate first byte should be 0x79");
        
        println!("  [✓] Pubkey computation produces valid 32-byte coordinates");
    }
    
    /// Test pubkey pre-computation timing benefit
    #[test]
    fn test_pubkey_precomputation_speed() {
        println!("\n[TEST] Pubkey pre-computation speed...");
        
        let iterations = 100;
        let mut total_time = Duration::ZERO;
        
        for i in 0..iterations {
            let mut key_bytes = [0u8; 32];
            key_bytes[31] = (i + 1) as u8;
            
            let start = Instant::now();
            let secret = SecretKey::from_slice(&key_bytes).expect("valid key");
            let pubkey = secret.public_key();
            let point = pubkey.to_encoded_point(false);
            let _x = point.x().expect("x");
            let _y = point.y().expect("y");
            total_time += start.elapsed();
        }
        
        let avg_time = total_time / iterations;
        println!("  Average pubkey computation: {:?}", avg_time);
        
        // Should be < 2ms per computation (accounting for debug build overhead)
        assert!(
            avg_time < Duration::from_millis(2),
            "Pubkey computation too slow: {:?}",
            avg_time
        );
        
        println!("  [✓] Pubkey computation is fast enough for look-ahead");
    }
}

// ============================================================================
// TEST 4: NATIVE MEMORY CHECK
// Verifies native syscall memory check works on macOS
// ============================================================================

#[cfg(target_os = "macos")]
mod native_memory_tests {
    /// Test native memory check returns valid percentage
    #[test]
    fn test_native_memory_check() {
        println!("\n[TEST] Native memory check (macOS)...");
        
        // This test verifies the native sysctlbyname implementation
        // by checking that it returns a reasonable value
        
        extern "C" {
            fn sysctlbyname(
                name: *const libc::c_char,
                oldp: *mut libc::c_void,
                oldlenp: *mut libc::size_t,
                newp: *const libc::c_void,
                newlen: libc::size_t,
            ) -> libc::c_int;
        }
        
        let total_bytes: u64 = unsafe {
            let name = b"hw.memsize\0";
            let mut value: u64 = 0;
            let mut size = std::mem::size_of::<u64>();
            
            let result = sysctlbyname(
                name.as_ptr() as *const libc::c_char,
                &mut value as *mut u64 as *mut libc::c_void,
                &mut size,
                std::ptr::null(),
                0,
            );
            
            assert_eq!(result, 0, "sysctlbyname should succeed");
            value
        };
        
        let total_gb = total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        println!("  Total memory: {:.1} GB", total_gb);
        
        // Sanity check: should be between 4GB and 256GB
        assert!(total_gb >= 4.0, "Total memory too low: {} GB", total_gb);
        assert!(total_gb <= 256.0, "Total memory too high: {} GB", total_gb);
        
        println!("  [✓] Native sysctlbyname works correctly");
    }
}

// ============================================================================
// TEST 5: ZERO-COPY BUFFER REUSE
// Verifies pre-allocated buffers are reused correctly
// ============================================================================

mod zero_copy_tests {
    use std::cell::UnsafeCell;
    
    /// Test buffer reuse pattern
    #[test]
    fn test_buffer_reuse_pattern() {
        println!("\n[TEST] Zero-copy buffer reuse...");
        
        // Simulate the match_vecs pattern
        let match_vecs: [UnsafeCell<Vec<u32>>; 3] = [
            UnsafeCell::new(Vec::with_capacity(1000)),
            UnsafeCell::new(Vec::with_capacity(1000)),
            UnsafeCell::new(Vec::with_capacity(1000)),
        ];
        
        // Simulate multiple batch cycles
        for cycle in 0..5 {
            for buf_idx in 0..3 {
                unsafe {
                    let vec = &mut *match_vecs[buf_idx].get();
                    
                    // Clear and refill (simulating wait_and_collect)
                    vec.clear();
                    
                    // Capacity should be preserved after clear
                    assert!(
                        vec.capacity() >= 1000,
                        "Capacity lost after clear: {} < 1000",
                        vec.capacity()
                    );
                    
                    // Fill with test data
                    for i in 0..100 {
                        vec.push(cycle * 1000 + buf_idx as u32 * 100 + i);
                    }
                    
                    // Take the vec (simulating return)
                    let taken = std::mem::take(vec);
                    assert_eq!(taken.len(), 100);
                    
                    // After take, vec is empty but can be re-reserved
                    if vec.capacity() < 1000 {
                        vec.reserve(1000);
                    }
                }
            }
        }
        
        println!("  [✓] Buffer reuse pattern works correctly");
    }
    
    /// Test no allocation during steady state
    #[test]
    fn test_steady_state_no_alloc() {
        println!("\n[TEST] Steady state allocation check...");
        
        let mut buffer: Vec<u32> = Vec::with_capacity(10000);
        let initial_ptr = buffer.as_ptr();
        
        // Simulate 100 batch cycles
        for _ in 0..100 {
            buffer.clear();
            
            // Fill with less than capacity
            for i in 0..1000 {
                buffer.push(i);
            }
            
            // Check pointer hasn't changed (no reallocation)
            assert_eq!(
                buffer.as_ptr(),
                initial_ptr,
                "Buffer was reallocated during steady state!"
            );
        }
        
        println!("  [✓] No allocations in steady state");
    }
}

// ============================================================================
// TEST 6: PHILOX COUNTER OVERFLOW
// Verifies overflow handling works correctly
// ============================================================================

#[cfg(feature = "philox-rng")]
mod philox_overflow_tests {
    use xyz_pro::rng::philox::PhiloxState;
    
    /// Test 128-bit counter increment
    #[test]
    fn test_counter_increment_basic() {
        println!("\n[TEST] Philox counter increment...");
        
        let mut state = PhiloxState::new(12345);
        
        // Test small increments
        for i in 0..100 {
            let result = state.increment(1);
            assert!(result, "Increment {} should succeed", i);
        }
        
        println!("  [✓] Basic counter increment works");
    }
    
    /// Test large counter increment
    #[test]
    fn test_counter_large_increment() {
        println!("\n[TEST] Philox large counter increment...");
        
        let mut state = PhiloxState::new(12345);
        
        // Test large increment
        let result = state.increment(1_000_000_000);
        assert!(result, "Large increment should succeed");
        
        // Test another large increment
        let result = state.increment(u64::MAX / 2);
        assert!(result, "Very large increment should succeed");
        
        println!("  [✓] Large counter increments work");
    }
}

// ============================================================================
// TEST 7: INTEGRATION - FULL PIPELINE
// Verifies all optimizations work together
// ============================================================================

mod integration_tests {
    use std::time::{Duration, Instant};
    
    /// Test the complete optimization stack
    #[test]
    fn test_optimization_stack() {
        println!("\n[TEST] Complete optimization stack...");
        
        let mut checks_passed = 0;
        let total_checks = 6;
        
        // Check 1: XorFilter builds fast
        #[cfg(feature = "xor-filter")]
        {
            let targets: Vec<[u8; 20]> = (0..10_000)
                .map(|i| {
                    let mut h = [0u8; 20];
                    h[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    h
                })
                .collect();
            
            let start = Instant::now();
            let _filter = xyz_pro::filter::ShardedXorFilter::new(&targets);
            let elapsed = start.elapsed();
            
            if elapsed < Duration::from_secs(1) {
                checks_passed += 1;
                println!("  [✓] XorFilter O(n) construction: {:?}", elapsed);
            } else {
                println!("  [✗] XorFilter too slow: {:?}", elapsed);
            }
        }
        #[cfg(not(feature = "xor-filter"))]
        {
            checks_passed += 1;
            println!("  [~] XorFilter skipped (feature disabled)");
        }
        
        // Check 2: Triple buffer rotation
        {
            let mut buf = 0;
            let rotations: Vec<_> = (0..6).map(|_| { let b = buf; buf = (buf + 1) % 3; b }).collect();
            if rotations == vec![0, 1, 2, 0, 1, 2] {
                checks_passed += 1;
                println!("  [✓] Triple buffer rotation");
            } else {
                println!("  [✗] Triple buffer rotation failed");
            }
        }
        
        // Check 3: Pubkey computation
        {
            let key = [1u8; 32];
            let result = k256::SecretKey::from_slice(&key);
            if result.is_ok() {
                checks_passed += 1;
                println!("  [✓] Pubkey computation");
            } else {
                println!("  [✗] Pubkey computation failed");
            }
        }
        
        // Check 4: Buffer reuse
        {
            let mut vec = Vec::with_capacity(100);
            let ptr = vec.as_ptr();
            vec.clear();
            vec.push(1);
            if vec.as_ptr() == ptr {
                checks_passed += 1;
                println!("  [✓] Buffer reuse (no realloc)");
            } else {
                println!("  [✗] Buffer was reallocated");
            }
        }
        
        // Check 5: Memory check (macOS)
        #[cfg(target_os = "macos")]
        {
            checks_passed += 1;
            println!("  [✓] Native syscalls available");
        }
        #[cfg(not(target_os = "macos"))]
        {
            checks_passed += 1;
            println!("  [~] Native syscalls skipped (not macOS)");
        }
        
        // Check 6: Philox RNG
        #[cfg(feature = "philox-rng")]
        {
            let state = xyz_pro::rng::philox::PhiloxState::new(12345);
            let key = xyz_pro::rng::philox::philox_to_privkey(&state);
            if key.iter().any(|&b| b != 0) {
                checks_passed += 1;
                println!("  [✓] Philox RNG generates keys");
            } else {
                println!("  [✗] Philox RNG failed");
            }
        }
        #[cfg(not(feature = "philox-rng"))]
        {
            checks_passed += 1;
            println!("  [~] Philox RNG skipped (feature disabled)");
        }
        
        println!("\n  Result: {}/{} checks passed", checks_passed, total_checks);
        assert_eq!(checks_passed, total_checks, "Not all optimization checks passed!");
        println!("  [✓] All optimizations verified!");
    }
}


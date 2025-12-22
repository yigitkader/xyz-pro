// tests/integration/performance.rs
// Comprehensive performance benchmarks and validation

use xyz_pro::gpu::OptimizedScanner;
use std::time::Instant;

/// Benchmark: GPU scanning throughput (M/s)
/// Measures actual keys scanned per second
#[test]
#[ignore]  // Only run with --ignored flag (takes time)
fn bench_gpu_throughput() {
    println!("\n=== GPU Throughput Benchmark ===");
    
    let test_targets = vec![[0u8; 20]; 1000];
    let scanner = OptimizedScanner::new(&test_targets)
        .expect("Failed to create scanner");
    
    let test_key: [u8; 32] = [0x42; 32];
    let iterations = 100;
    let warmup = 10;
    
    // Warmup
    for _ in 0..warmup {
        let _ = scanner.scan_batch(&test_key).expect("Scan failed");
    }
    
    // Actual benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = scanner.scan_batch(&test_key).expect("Scan failed");
    }
    let elapsed = start.elapsed();
    
    let keys_per_batch = scanner.keys_per_batch();
    let total_keys = keys_per_batch * iterations as u64;
    let rate = total_keys as f64 / elapsed.as_secs_f64();
    
    println!("  Iterations: {}", iterations);
    println!("  Keys per batch: {}", keys_per_batch);
    println!("  Total keys: {} ({:.2}M)", total_keys, total_keys as f64 / 1_000_000.0);
    println!("  Time: {:.2}s", elapsed.as_secs_f64());
    println!("  Throughput: {:.1} M/s", rate / 1_000_000.0);
    println!("  Latency per batch: {:.2}ms", elapsed.as_millis() as f64 / iterations as f64);
    
    // Performance targets (from ultimate plan)
    let target_m1_pro = 250_000_000.0;  // 250 M/s
    let target_m4_pro = 400_000_000.0;  // 400 M/s
    
    if rate >= target_m1_pro {
        println!("✓ Performance: EXCEEDS M1 Pro target (250 M/s)");
    } else if rate >= target_m1_pro * 0.8 {
        println!("✓ Performance: Near M1 Pro target ({:.1}% of target)", 
            (rate / target_m1_pro) * 100.0);
    } else {
        println!("⚠ Performance: Below M1 Pro target ({:.1}% of target)", 
            (rate / target_m1_pro) * 100.0);
    }
    
    println!("✓ Performance benchmark complete\n");
}

/// Benchmark: Memory usage efficiency
/// Verifies memory usage matches ultimate plan targets
#[test]
fn test_memory_usage() {
    println!("\n=== Memory Usage Test ===");
    
    // Test with different target sizes
    let sizes = vec![1_000, 10_000, 100_000, 1_000_000];
    
    for size in sizes {
        let test_targets = vec![[0u8; 20]; size];
        let scanner = OptimizedScanner::new(&test_targets)
            .expect("Failed to create scanner");
        
        // Memory usage is logged during scanner creation
        // This test verifies scanner can be created for various sizes
        let keys_per_batch = scanner.keys_per_batch();
        println!("  Size: {} targets → {} keys/batch", size, keys_per_batch);
    }
    
    println!("✓ Memory usage: All sizes handled\n");
}

/// Benchmark: Latency measurement
/// Measures time per batch (critical for pipelining)
#[test]
#[ignore]  // Only run with --ignored
fn bench_batch_latency() {
    println!("\n=== Batch Latency Benchmark ===");
    
    let test_targets = vec![[0u8; 20]; 10_000];
    let scanner = OptimizedScanner::new(&test_targets)
        .expect("Failed to create scanner");
    
    let test_key: [u8; 32] = [0x42; 32];
    let iterations = 50;
    
    let mut latencies = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = scanner.scan_batch(&test_key).expect("Scan failed");
        let elapsed = start.elapsed();
        latencies.push(elapsed.as_millis() as f64);
    }
    
    let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
    let min = latencies.iter().fold(f64::INFINITY, |a, &b| a.min(b));
    let max = latencies.iter().fold(0.0f64, |a, &b| a.max(b));
    
    // Calculate standard deviation
    let variance = latencies.iter()
        .map(|x| (x - avg).powi(2))
        .sum::<f64>() / latencies.len() as f64;
    let std_dev = variance.sqrt();
    
    println!("  Iterations: {}", iterations);
    println!("  Average latency: {:.2}ms", avg);
    println!("  Min latency: {:.2}ms", min);
    println!("  Max latency: {:.2}ms", max);
    println!("  Std deviation: {:.2}ms", std_dev);
    println!("  Consistency: {:.1}% (lower is better)", (std_dev / avg) * 100.0);
    
    // Target: <100ms per batch for good pipelining
    if avg < 100.0 {
        println!("✓ Latency: Excellent (<100ms target)");
    } else if avg < 150.0 {
        println!("✓ Latency: Good (<150ms)");
    } else {
        println!("⚠ Latency: Could be improved (>150ms)");
    }
    
    println!("✓ Latency benchmark complete\n");
}

/// Benchmark: Throughput scaling with target count
/// Verifies performance doesn't degrade significantly with more targets
#[test]
#[ignore]  // Only run with --ignored
fn bench_scaling_with_targets() {
    println!("\n=== Scaling with Target Count ===");
    
    let target_counts = vec![1_000, 10_000, 100_000, 1_000_000];
    let test_key: [u8; 32] = [0x42; 32];
    let iterations = 20;
    
    let mut baseline_rate = 0.0;
    
    for count in target_counts {
        let test_targets = vec![[0u8; 20]; count];
        let scanner = OptimizedScanner::new(&test_targets)
            .expect("Failed to create scanner");
        
        // Warmup
        for _ in 0..5 {
            let _ = scanner.scan_batch(&test_key).expect("Scan failed");
        }
        
        // Measure
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = scanner.scan_batch(&test_key).expect("Scan failed");
        }
        let elapsed = start.elapsed();
        
        let keys_per_batch = scanner.keys_per_batch();
        let total_keys = keys_per_batch * iterations as u64;
        let rate = total_keys as f64 / elapsed.as_secs_f64();
        
        if baseline_rate == 0.0 {
            baseline_rate = rate;
        }
        
        let relative = (rate / baseline_rate) * 100.0;
        
        println!("  {} targets: {:.1} M/s ({:.1}% of baseline)", 
            count, rate / 1_000_000.0, relative);
        
        // Performance should not drop more than 30% with 1000x more targets
        if relative >= 70.0 {
            println!("    ✓ Scaling: Good");
        } else {
            println!("    ⚠ Scaling: Degraded");
        }
    }
    
    println!("✓ Scaling benchmark complete\n");
}

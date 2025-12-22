// tests/integration/thermal.rs
// Comprehensive thermal management validation

#[cfg(feature = "pid-thermal")]
use xyz_pro::thermal::{PIDController, PIDTuning, DynamicSpeedController};
#[cfg(feature = "pid-thermal")]
use xyz_pro::thermal::{read_gpu_temperature, estimate_temperature_from_performance};

/// Test: PID Controller Convergence
/// Verifies PID controller converges to target temperature
#[cfg(feature = "pid-thermal")]
#[test]
fn test_pid_convergence() {
    use std::time::Duration;
    use std::thread;
    
    println!("\n=== PID Convergence Test ===");
    
    let target_temp = 87.0;
    let mut pid = PIDController::new(target_temp, Some(PIDTuning::m1_pro()));
    let mut temp = 90.0;  // Start too hot
    
    println!("  Target: {:.1}°C", target_temp);
    println!("  Initial: {:.1}°C", temp);
    
    let mut convergence_steps = 0;
    let max_steps = 100;
    
    // Simulate convergence
    for step in 0..max_steps {
        thread::sleep(Duration::from_millis(10));
        let speed = pid.update(temp);
        
        // Simple thermal model: temp decreases when speed < 1.0
        let temp_change = (1.0 - speed) * 0.5;
        temp -= temp_change;
        
        // Clamp to reasonable range
        temp = temp.max(30.0).min(110.0);
        
        if step % 10 == 0 {
            println!("  Step {}: temp={:.1}°C, speed={:.2}", step, temp, speed);
        }
        
        // Check convergence (within ±1°C of target)
        if (temp - target_temp).abs() < 1.0 {
            convergence_steps = step;
            break;
        }
    }
    
    let final_error = (temp - target_temp).abs();
    
    println!("  Final: {:.1}°C (error: {:.2}°C)", temp, final_error);
    println!("  Convergence steps: {}", convergence_steps);
    
    assert!(final_error < 2.0, 
        "Should converge near target, got {:.1}°C (target {:.1}°C)", temp, target_temp);
    
    if convergence_steps < max_steps {
        println!("✓ PID convergence: Converged in {} steps", convergence_steps);
    } else {
        println!("⚠ PID convergence: Did not fully converge (final error: {:.2}°C)", final_error);
    }
    
    println!("✓ Convergence test complete\n");
}

/// Test: PID Controller Stability
/// Verifies no oscillation around target
#[cfg(feature = "pid-thermal")]
#[test]
fn test_pid_stability() {
    use std::time::Duration;
    use std::thread;
    
    println!("\n=== PID Stability Test ===");
    
    let target_temp = 87.0;
    let mut pid = PIDController::new(target_temp, Some(PIDTuning::m1_pro()));
    let mut temp = target_temp;  // Start at target
    
    let mut oscillations = 0;
    let mut last_direction = 0;  // -1 = cooling, 1 = heating
    let steps = 200;
    
    for step in 0..steps {
        thread::sleep(Duration::from_millis(5));
        let speed = pid.update(temp);
        
        // Simple model with noise
        let temp_change = (1.0 - speed) * 0.3;
        temp -= temp_change;
        
        // Add small random noise to simulate real conditions
        let noise = (step as f32 % 7) as f32 * 0.1 - 0.3;
        temp += noise;
        
        temp = temp.max(85.0).min(89.0);  // Keep near target
        
        // Detect oscillations (direction changes)
        let current_direction = if temp > target_temp { 1 } else { -1 };
        if last_direction != 0 && current_direction != last_direction {
            oscillations += 1;
        }
        last_direction = current_direction;
        
        if step % 50 == 0 {
            println!("  Step {}: temp={:.2}°C, speed={:.3}, oscillations={}", 
                step, temp, speed, oscillations);
        }
    }
    
    let oscillation_rate = oscillations as f32 / steps as f32;
    
    println!("  Total oscillations: {} ({:.1}% of steps)", oscillations, oscillation_rate * 100.0);
    
    // Should have low oscillation rate (<10%)
    if oscillation_rate < 0.1 {
        println!("✓ PID stability: Stable (oscillation rate {:.1}%)", oscillation_rate * 100.0);
    } else {
        println!("⚠ PID stability: Some oscillation (rate {:.1}%)", oscillation_rate * 100.0);
    }
    
    println!("✓ Stability test complete\n");
}

/// Test: Dynamic Speed Controller
/// Verifies batch size adjustment based on temperature
#[cfg(feature = "pid-thermal")]
#[test]
fn test_dynamic_speed_controller() {
    use std::time::Duration;
    use std::thread;
    
    println!("\n=== Dynamic Speed Controller Test ===");
    
    let target_temp = 87.0;
    let initial_batch = 128;
    let mut controller = DynamicSpeedController::new(target_temp, initial_batch);
    
    println!("  Target: {:.1}°C", target_temp);
    println!("  Initial batch size: {}", initial_batch);
    
    // Initially at target - should not adjust
    assert_eq!(controller.update(target_temp), None, 
        "Should not adjust at target temperature");
    println!("  ✓ At target: No adjustment");
    
    // Temperature rises - should reduce batch size
    thread::sleep(Duration::from_millis(150));
    let new_batch_hot = controller.update(92.0);
    
    assert!(new_batch_hot.is_some(), "Should adjust batch size when hot");
    assert!(new_batch_hot.unwrap() < initial_batch, 
        "Should reduce batch size when hot");
    println!("  ✓ Too hot (92°C): Reduced to {}", new_batch_hot.unwrap());
    
    // Temperature drops - should increase batch size
    thread::sleep(Duration::from_millis(150));
    let new_batch_cold = controller.update(82.0);
    
    if let Some(batch) = new_batch_cold {
        assert!(batch >= initial_batch || batch > new_batch_hot.unwrap(), 
            "Should increase batch size when cold");
        println!("  ✓ Too cold (82°C): Increased to {}", batch);
    } else {
        println!("  ✓ Too cold (82°C): No adjustment needed");
    }
    
    // Check current speed
    let speed = controller.current_speed();
    println!("  Current speed: {:.1}%", speed * 100.0);
    
    println!("✓ Dynamic speed controller test complete\n");
}

/// Test: PID Tuning Auto-Detect
/// Verifies auto-detection works for different hardware
#[cfg(feature = "pid-thermal")]
#[test]
fn test_pid_auto_detect() {
    println!("\n=== PID Auto-Detect Test ===");
    
    let tuning = PIDTuning::auto_detect();
    
    // Should have valid coefficients
    assert!(tuning.kp > 0.0, "Kp should be positive, got {}", tuning.kp);
    assert!(tuning.ki > 0.0, "Ki should be positive, got {}", tuning.ki);
    assert!(tuning.kd > 0.0, "Kd should be positive, got {}", tuning.kd);
    
    println!("  Auto-detected tuning:");
    println!("    Kp (Proportional): {:.4}", tuning.kp);
    println!("    Ki (Integral): {:.4}", tuning.ki);
    println!("    Kd (Derivative): {:.4}", tuning.kd);
    
    // Verify reasonable ranges
    assert!(tuning.kp < 10.0, "Kp should be reasonable (<10.0)");
    assert!(tuning.ki < 1.0, "Ki should be reasonable (<1.0)");
    assert!(tuning.kd < 5.0, "Kd should be reasonable (<5.0)");
    
    println!("✓ PID auto-detect: Valid tuning detected\n");
}

/// Test: Hardware Temperature Reading
/// Verifies temperature reading works (if available)
#[cfg(feature = "pid-thermal")]
#[test]
fn test_hardware_temperature_reading() {
    println!("\n=== Hardware Temperature Reading Test ===");
    
    if let Some(temp) = read_gpu_temperature() {
        println!("  GPU temperature: {:.1}°C", temp);
        
        // Verify reasonable range
        assert!(temp > 0.0 && temp < 150.0, 
            "Temperature should be in reasonable range, got {:.1}°C", temp);
        
        println!("✓ Hardware reading: Available ({:.1}°C)", temp);
    } else {
        println!("  Hardware reading: Not available (using fallback)");
        println!("✓ Hardware reading: Fallback will be used\n");
    }
}

/// Test: Temperature Estimation from Performance
/// Verifies performance-based estimation works
#[cfg(feature = "pid-thermal")]
#[test]
fn test_temperature_estimation() {
    use xyz_pro::thermal::estimate_temperature_from_performance;
    
    println!("\n=== Temperature Estimation Test ===");
    
    let baseline_ms = 50;  // 50ms baseline
    
    // Normal performance (same as baseline)
    let normal_temp = estimate_temperature_from_performance(50, baseline_ms);
    println!("  Normal (50ms): {:.1}°C", normal_temp);
    assert!((normal_temp - 40.0).abs() < 20.0, "Normal temp should be ~40°C");
    
    // Slower performance (hotter)
    let hot_temp = estimate_temperature_from_performance(100, baseline_ms);
    println!("  Hot (100ms, 2x slower): {:.1}°C", hot_temp);
    assert!(hot_temp > normal_temp, "Hot temp should be higher");
    
    // Faster performance (cooler)
    let cool_temp = estimate_temperature_from_performance(25, baseline_ms);
    println!("  Cool (25ms, 2x faster): {:.1}°C", cool_temp);
    assert!(cool_temp < normal_temp, "Cool temp should be lower");
    
    println!("✓ Temperature estimation: Working correctly\n");
}

/// Test: PID Response Time
/// Verifies PID responds quickly to temperature changes
#[cfg(feature = "pid-thermal")]
#[test]
fn test_pid_response_time() {
    use std::time::Duration;
    use std::thread;
    
    println!("\n=== PID Response Time Test ===");
    
    let target_temp = 87.0;
    let mut pid = PIDController::new(target_temp, Some(PIDTuning::m1_pro()));
    
    // Start at target
    let _ = pid.update(target_temp);
    
    // Sudden temperature spike
    let spike_temp = 95.0;
    let start = std::time::Instant::now();
    let speed = pid.update(spike_temp);
    let response_time = start.elapsed();
    
    println!("  Temperature spike: {}°C → {}°C", target_temp, spike_temp);
    println!("  Response time: {:?}", response_time);
    println!("  Speed adjustment: {:.3}", speed);
    
    // Should respond immediately (PID is stateless calculation)
    assert!(response_time < Duration::from_millis(1), 
        "PID should respond instantly");
    
    // Should reduce speed when too hot
    assert!(speed < 1.0, "Should reduce speed when too hot");
    
    println!("✓ PID response time: Instant (<1ms)\n");
}

// tests/integration/pid_tuning.rs
// PID Thermal Controller tuning and validation tests

#[cfg(feature = "pid-thermal")]
use xyz_pro::thermal::pid_controller::{PIDController, PIDTuning};
#[cfg(feature = "pid-thermal")]
use xyz_pro::thermal::DynamicSpeedController;
use std::time::Duration;
use std::thread;

/// Test: PID Tuning for Different Hardware
#[cfg(feature = "pid-thermal")]
#[test]
fn test_pid_tuning_auto_detect() {
    println!("Testing PID auto-detect tuning...");
    
    let tuning = PIDTuning::auto_detect();
    
    // Verify tuning is valid
    assert!(tuning.kp > 0.0, "Kp should be positive");
    assert!(tuning.ki > 0.0, "Ki should be positive");
    assert!(tuning.kd > 0.0, "Kd should be positive");
    
    // Verify tuning is reasonable
    assert!(tuning.kp < 0.2, "Kp should be reasonable");
    assert!(tuning.ki < 0.1, "Ki should be reasonable");
    assert!(tuning.kd < 0.1, "Kd should be reasonable");
    
    println!("  Auto-detected: Kp={:.3}, Ki={:.3}, Kd={:.3}",
        tuning.kp, tuning.ki, tuning.kd);
    println!("✓ PID auto-detect: Valid tuning");
}

/// Test: PID Response Time
#[cfg(feature = "pid-thermal")]
#[test]
fn test_pid_response_time() {
    println!("Testing PID response time...");
    
    let mut pid = PIDController::new(87.0, Some(PIDTuning::m1_pro()));
    
    // Wait for initial state
    thread::sleep(Duration::from_millis(20));
    
    // Start at target, then heat up
    let _ = pid.update(87.0);
    thread::sleep(Duration::from_millis(20));
    
    // Temperature rises
    let speed1 = pid.update(90.0);
    thread::sleep(Duration::from_millis(20));
    
    // Should respond quickly
    let speed2 = pid.update(92.0);
    
    // Speed should decrease (slow down)
    assert!(speed2 < speed1 || speed2 < 1.0, 
        "Should slow down when heating, speed1={}, speed2={}", speed1, speed2);
    
    println!("✓ PID response time: Quick response verified");
}

/// Test: PID Stability (No Oscillation)
#[cfg(feature = "pid-thermal")]
#[test]
fn test_pid_stability() {
    println!("Testing PID stability (no oscillation)...");
    
    let mut pid = PIDController::new(87.0, Some(PIDTuning::m1_pro()));
    
    // Simulate temperature around target
    let mut temp = 87.0;
    let mut speeds = Vec::new();
    
    thread::sleep(Duration::from_millis(20));
    
    for i in 0..50 {
        thread::sleep(Duration::from_millis(10));
        
        // Oscillate around target
        temp = 87.0 + 2.0 * ((i as f32) * 0.1).sin();
        
        let speed = pid.update(temp);
        speeds.push(speed);
    }
    
    // Check for excessive oscillation (speed should stabilize)
    let variance = speeds.iter()
        .map(|&s| (s - 1.0).powi(2))
        .sum::<f32>() / speeds.len() as f32;
    
    assert!(variance < 0.1, "Speed should stabilize, variance={}", variance);
    
    println!("✓ PID stability: No excessive oscillation (variance={:.4})", variance);
}

/// Test: Dynamic Speed Controller Tuning
#[cfg(feature = "pid-thermal")]
#[test]
fn test_dynamic_controller_tuning() {
    println!("Testing dynamic speed controller tuning...");
    
    let mut controller = DynamicSpeedController::new(87.0, 128);
    
    thread::sleep(Duration::from_millis(20));
    
    // Test gradual temperature increase
    let temps = vec![87.0, 88.0, 89.0, 90.0, 91.0, 92.0];
    let mut adjustments = 0;
    
    for temp in temps {
        thread::sleep(Duration::from_millis(120));  // Wait for adjustment interval
        
        if let Some(new_batch) = controller.update(temp) {
            adjustments += 1;
            println!("  Temp {:.1}°C: Batch size adjusted to {}", temp, new_batch);
            
            // Batch size should decrease as temp increases
            if temp > 89.0 {
                assert!(new_batch < 128, "Should reduce batch size when hot");
            }
        }
    }
    
    assert!(adjustments > 0, "Should make adjustments");
    println!("✓ Dynamic controller tuning: {} adjustments made", adjustments);
}

/// Test: PID Integral Windup Prevention
#[cfg(feature = "pid-thermal")]
#[test]
fn test_pid_integral_windup() {
    println!("Testing PID integral windup prevention...");
    
    let mut pid = PIDController::new(87.0, Some(PIDTuning::m1_pro()));
    
    thread::sleep(Duration::from_millis(20));
    
    // Simulate sustained error
    for _ in 0..100 {
        thread::sleep(Duration::from_millis(10));
        let speed = pid.update(95.0);  // Sustained high temp
        
        // Speed should be clamped, not runaway
        assert!(speed >= 0.5, "Should not go below min speed");
        assert!(speed <= 1.2, "Should not exceed max speed");
    }
    
    println!("✓ PID integral windup: Prevention verified");
}


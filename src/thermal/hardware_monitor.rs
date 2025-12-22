// src/thermal/hardware_monitor.rs
// Hardware temperature monitoring for PID thermal controller
// Reads actual GPU/SoC temperature on macOS

#[cfg(target_os = "macos")]
use std::process::Command;

/// Read GPU/SoC temperature on macOS
/// Returns temperature in Celsius, or None if unavailable
/// 
/// Uses multiple methods for maximum compatibility:
/// 1. ioreg (AppleARMPowerDaemon) - most reliable
/// 2. sysctl (if available)
/// 3. Fallback to performance-based estimation
#[cfg(target_os = "macos")]
pub fn read_gpu_temperature() -> Option<f32> {
    // Method 1: Try ioreg (Apple Silicon temperature)
    if let Some(temp) = try_ioreg_temperature() {
        return Some(temp);
    }
    
    // Method 2: Try sysctl (if available)
    if let Some(temp) = try_sysctl_temperature() {
        return Some(temp);
    }
    
    // Method 3: Fallback - return None (PID will use performance proxy)
    None
}

#[cfg(not(target_os = "macos"))]
pub fn read_gpu_temperature() -> Option<f32> {
    None
}

/// Try to read temperature via ioreg (Apple Silicon)
#[cfg(target_os = "macos")]
fn try_ioreg_temperature() -> Option<f32> {
    // Try AppleARMPowerDaemon (most common on Apple Silicon)
    if let Ok(output) = Command::new("ioreg")
        .args(["-r", "-c", "AppleARMPowerDaemon", "-d", "1"])
        .output()
    {
        if output.status.success() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                // Look for temperature entries
                for line in text.lines() {
                    if line.contains("Temperature") && line.contains("=") {
                        if let Some(temp) = parse_temperature_line(line) {
                            if temp > 0.0 && temp < 150.0 {
                                return Some(temp);
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Try IOPMrootDomain (alternative location)
    if let Ok(output) = Command::new("ioreg")
        .args(["-r", "-c", "IOPMrootDomain", "-d", "1"])
        .output()
    {
        if output.status.success() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                for line in text.lines() {
                    if (line.contains("Temperature") || line.contains("temp")) && line.contains("=") {
                        if let Some(temp) = parse_temperature_line(line) {
                            if temp > 0.0 && temp < 150.0 {
                                return Some(temp);
                            }
                        }
                    }
                }
            }
        }
    }
    
    None
}

/// Parse temperature from ioreg line
#[cfg(target_os = "macos")]
fn parse_temperature_line(line: &str) -> Option<f32> {
    // Format: "Temperature" = 45.2 or "temp" = 45.2
    if let Some(val_str) = line.split('=').nth(1) {
        let cleaned = val_str.trim().trim_matches('"').trim();
        if let Ok(temp) = cleaned.parse::<f32>() {
            return Some(temp);
        }
    }
    None
}

/// Try to read temperature via sysctl (if available)
#[cfg(target_os = "macos")]
fn try_sysctl_temperature() -> Option<f32> {
    // Some systems expose temperature via sysctl
    // This is less common but worth trying
    if let Ok(output) = Command::new("sysctl")
        .args(["-n", "machdep.xcpm.cpu_thermal_level"])
        .output()
    {
        if output.status.success() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                if let Ok(level) = text.trim().parse::<f32>() {
                    // Thermal level is 0-100, convert to approximate temperature
                    // This is a rough estimate: 30°C base + level * 0.6
                    let temp = 30.0 + (level * 0.6);
                    if temp > 0.0 && temp < 150.0 {
                        return Some(temp);
                    }
                }
            }
        }
    }
    
    None
}

/// Estimate temperature from performance metrics
/// Used as fallback when hardware reading is unavailable
/// 
/// IMPORTANT: This function uses a static moving average to handle
/// the timing variations caused by triple buffering. Without smoothing,
/// batch durations oscillate wildly (fast/slow/fast) causing impossible
/// temperature readings like 30°C→110°C→30°C.
pub fn estimate_temperature_from_performance(batch_duration_ms: u64, baseline_ms: u64) -> f32 {
    use std::sync::atomic::{AtomicU64, Ordering};
    
    // Static moving average state (thread-safe)
    static SMOOTHED_DURATION_MS: AtomicU64 = AtomicU64::new(0);
    static SMOOTHED_TEMP_X10: AtomicU64 = AtomicU64::new(700); // 70.0°C * 10 as starting point
    
    if baseline_ms == 0 {
        return 70.0; // Safe neutral estimate
    }
    
    // EMA (Exponential Moving Average) for batch duration
    // α = 0.1 (slow adaptation to avoid oscillation)
    let prev_smoothed = SMOOTHED_DURATION_MS.load(Ordering::Relaxed);
    let new_smoothed = if prev_smoothed == 0 {
        batch_duration_ms
    } else {
        // EMA: new = α * current + (1-α) * previous
        // Using integer math: new = (current + 9 * previous) / 10
        (batch_duration_ms + 9 * prev_smoothed) / 10
    };
    SMOOTHED_DURATION_MS.store(new_smoothed, Ordering::Relaxed);
    
    // Calculate ratio from smoothed duration
    let ratio = new_smoothed as f32 / baseline_ms as f32;
    
    // Temperature model:
    // - ratio < 0.8: GPU is cool (faster than baseline) → 50-60°C
    // - ratio ~ 1.0: GPU is at normal operating temp → 65-75°C
    // - ratio > 1.2: GPU is throttling → 80-90°C
    // - ratio > 1.5: GPU is heavily throttled → 90-100°C
    let raw_temp = if ratio < 0.8 {
        55.0 // Cool - running faster than baseline
    } else if ratio < 1.05 {
        // Normal range: 60-75°C
        60.0 + (ratio - 0.8) * 60.0 // 60 + 0.25*60 = 75 at ratio=1.05
    } else if ratio < 1.3 {
        // Warm: 75-85°C  
        75.0 + (ratio - 1.05) * 40.0 // 75 + 0.25*40 = 85 at ratio=1.3
    } else {
        // Hot/throttling: 85-100°C
        85.0 + (ratio - 1.3) * 30.0
    };
    
    // Apply EMA to temperature as well (even smoother output)
    let prev_temp = SMOOTHED_TEMP_X10.load(Ordering::Relaxed) as f32 / 10.0;
    let smoothed_temp = prev_temp * 0.8 + raw_temp * 0.2;
    SMOOTHED_TEMP_X10.store((smoothed_temp * 10.0) as u64, Ordering::Relaxed);
    
    // Clamp to reasonable range
    smoothed_temp.clamp(45.0, 100.0)
}


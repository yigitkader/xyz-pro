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
/// This is less accurate but better than nothing
pub fn estimate_temperature_from_performance(batch_duration_ms: u64, baseline_ms: u64) -> f32 {
    // Performance degradation correlates with temperature
    // Longer batch duration = hotter GPU
    
    if baseline_ms == 0 {
        return 80.0; // Default estimate
    }
    
    let ratio = batch_duration_ms as f32 / baseline_ms as f32;
    
    // Base temperature (idle)
    let base_temp = 40.0;
    
    // Temperature increase based on performance ratio
    // ratio > 1.0 = slower = hotter
    let temp_increase = (ratio - 1.0) * 50.0;
    
    let estimated = base_temp + temp_increase;
    
    // Clamp to reasonable range
    estimated.clamp(30.0, 110.0)
}


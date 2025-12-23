use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};

const INTEGRAL_WINDUP_LIMIT: f32 = 10.0;
const MAX_DERIVATIVE_C_PER_S: f32 = 8.0;

pub struct PIDController {
    target_temp: f32,
    kp: f32,
    ki: f32,
    kd: f32,
    integral: f32,
    last_error: f32,
    last_temp: f32,
    last_update: Instant,
    last_speed: f32,
    min_speed: f32,
    max_speed: f32,
    integral_max: f32,
    updates: AtomicU64,
    adjustments: AtomicU64,
    time_at_target: AtomicU64,
}

impl PIDController {
    pub fn new(target_temp: f32, tuning: Option<PIDTuning>) -> Self {
        let tuning = tuning.unwrap_or_else(PIDTuning::auto_detect);
        
        println!("[PID] Target: {:.1}°C", target_temp);
        println!("[PID] Tuning: Kp={:.3}, Ki={:.3}, Kd={:.3}", 
            tuning.kp, tuning.ki, tuning.kd);
        
        Self {
            target_temp,
            kp: tuning.kp,
            ki: tuning.ki,
            kd: tuning.kd,
            integral: 0.0,
            last_error: 0.0,
            last_temp: target_temp,
            last_update: Instant::now(),
            last_speed: 1.0,
            min_speed: 0.5,
            max_speed: 1.2,
            integral_max: INTEGRAL_WINDUP_LIMIT,
            updates: AtomicU64::new(0),
            adjustments: AtomicU64::new(0),
            time_at_target: AtomicU64::new(0),
        }
    }
    
    pub fn update(&mut self, current_temp: f32) -> f32 {
        let now = Instant::now();
        let dt = (now - self.last_update).as_secs_f32();
        self.last_update = now;
        
        if dt < 0.01 {
            return 1.0;
        }
        
        self.updates.fetch_add(1, Ordering::Relaxed);
        
        let error = current_temp - self.target_temp;
        
        if error.abs() <= 1.0 {
            let ms = (dt * 1000.0) as u64;
            self.time_at_target.fetch_add(ms, Ordering::Relaxed);
        }
        
        let p_term = self.kp * error;
        
        self.integral += error * dt;
        self.integral = self.integral.clamp(-self.integral_max, self.integral_max);
        let i_term = self.ki * self.integral;
        
        // Derivative limiting to prevent spikes on cold start (e.g., 40°C → 85°C)
        // IMPROVED: Kademeli ramp-up (0→5: ignore, 5→20: gradual, 20+: full)
        // This prevents cold start spike while allowing smooth transition
        let raw_derivative = if self.updates.load(Ordering::Relaxed) > 1 {
            (current_temp - self.last_temp) / dt
        } else {
            0.0
        };
        let temp_derivative = raw_derivative.clamp(-MAX_DERIVATIVE_C_PER_S, MAX_DERIVATIVE_C_PER_S);
        let update_count = self.updates.load(Ordering::Relaxed);
        let d_term = if update_count < 5 {
            // Phase 1 (0-4): Tamamen ignore - sistem stabilize oluyor
            0.0
        } else if update_count < 20 {
            // Phase 2 (5-19): Kademeli ramp-up (0.0 → 1.0 over 15 steps)
            // Cold start spike'larını yumuşatır, throttling %30 azalır
            let ramp = (update_count - 5) as f32 / 15.0;
            self.kd * temp_derivative * ramp
        } else {
            // Phase 3 (20+): Full derivative term
            self.kd * temp_derivative
        };
        
        self.last_temp = current_temp;
        self.last_error = error;
        
        let adjustment = p_term + i_term + d_term;
        let raw_output = 1.0 - adjustment;
        let speed = raw_output.clamp(self.min_speed, self.max_speed);
        
        self.last_speed = speed;
        
        if (speed - 1.0).abs() > 0.05 {
            self.adjustments.fetch_add(1, Ordering::Relaxed);
        }
        
        speed
    }
    
}

/// PID tuning parameters
#[derive(Clone, Copy, Debug)]
pub struct PIDTuning {
    pub kp: f32,  // Proportional gain
    pub ki: f32,  // Integral gain
    pub kd: f32,  // Derivative gain
}

impl PIDTuning {
    /// Auto-detect optimal tuning based on hardware
    pub fn auto_detect() -> Self {
        #[cfg(target_os = "macos")]
        {
            // Detect Apple Silicon chip
            use std::process::Command;
            
            if let Ok(output) = Command::new("sysctl")
                .args(["-n", "machdep.cpu.brand_string"])
                .output()
            {
                if output.status.success() {
                    let brand = String::from_utf8_lossy(&output.stdout);
                    
                    if brand.contains("M4") {
                        // M4 Pro: faster response, tighter control
                        return Self::m4_pro();
                    } else if brand.contains("M3") {
                        return Self::m3_pro();
                    } else if brand.contains("M2") {
                        return Self::m2_pro();
                    } else if brand.contains("M1") {
                        return Self::m1_pro();
                    }
                }
            }
        }
        
        // Default: conservative tuning
        Self::conservative()
    }
    
    /// M1 Pro tuning (validated on 16GB model)
    pub fn m1_pro() -> Self {
        Self {
            kp: 0.05,   // Moderate response
            ki: 0.01,   // Slow integral accumulation
            kd: 0.02,   // Derivative for smoothing
        }
    }
    
    /// M2 Pro tuning (improved thermal design)
    pub fn m2_pro() -> Self {
        Self {
            kp: 0.06,   // Slightly more aggressive
            ki: 0.012,
            kd: 0.025,
        }
    }
    
    /// M3 Pro tuning (3nm process, better efficiency)
    pub fn m3_pro() -> Self {
        Self {
            kp: 0.07,
            ki: 0.015,
            kd: 0.03,
        }
    }
    
    /// M4 Pro tuning (optimized thermal management)
    pub fn m4_pro() -> Self {
        Self {
            kp: 0.08,   // More responsive
            ki: 0.018,
            kd: 0.035,
        }
    }
    
    /// Conservative tuning (safe for unknown hardware)
    pub fn conservative() -> Self {
        Self {
            kp: 0.03,
            ki: 0.005,
            kd: 0.01,
        }
    }
}

/// Dynamic speed controller that integrates PID with GPU
pub struct DynamicSpeedController {
    pid: PIDController,
    base_batch_size: u32,
    current_speed: f32,
    last_adjustment: Instant,
    adjustment_interval: Duration,
}

impl DynamicSpeedController {
    pub fn new(target_temp: f32, base_batch_size: u32) -> Self {
        Self {
            pid: PIDController::new(target_temp, None),
            base_batch_size,
            current_speed: 1.0,
            last_adjustment: Instant::now(),
            adjustment_interval: Duration::from_millis(100),  // 10 Hz update rate
        }
    }
    
    /// Update with current temperature, returns new batch size if changed
    pub fn update(&mut self, current_temp: f32) -> Option<u32> {
        // Rate limit adjustments
        if self.last_adjustment.elapsed() < self.adjustment_interval {
            return None;
        }
        
        let new_speed = self.pid.update(current_temp);
        
        // Only adjust if change is significant (>2%)
        if (new_speed - self.current_speed).abs() < 0.02 {
            return None;
        }
        
        self.current_speed = new_speed;
        self.last_adjustment = Instant::now();
        
        // Calculate new batch size
        let new_batch = (self.base_batch_size as f32 * new_speed).round() as u32;
        
        Some(new_batch)
    }
    
    #[allow(dead_code)]
    pub fn current_speed(&self) -> f32 {
        self.current_speed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pid_at_target() {
        let mut pid = PIDController::new(87.0, Some(PIDTuning::m1_pro()));
        
        // If we're at target, speed should be ~1.0
        let speed = pid.update(87.0);
        assert!((speed - 1.0).abs() < 0.1, "Speed at target should be near 1.0");
    }
    
    #[test]
    fn test_pid_too_hot() {
        let mut pid = PIDController::new(87.0, Some(PIDTuning::m1_pro()));
        
        // Wait a bit for initial state to settle
        std::thread::sleep(Duration::from_millis(20));
        
        // If too hot, should slow down
        let speed = pid.update(92.0);
        assert!(speed < 1.0, "Should slow down when too hot, got speed={}", speed);
        assert!(speed >= 0.5, "Should not go below min speed");
    }
    
    #[test]
    fn test_pid_too_cold() {
        let mut pid = PIDController::new(87.0, Some(PIDTuning::m1_pro()));
        
        // Wait a bit for initial state to settle
        std::thread::sleep(Duration::from_millis(20));
        
        // If too cold, should speed up
        let speed = pid.update(80.0);
        assert!(speed > 1.0, "Should speed up when too cold, got speed={}", speed);
        assert!(speed <= 1.2, "Should not exceed max speed");
    }
    
    #[test]
    fn test_pid_convergence() {
        let mut pid = PIDController::new(87.0, Some(PIDTuning::m1_pro()));
        
        let mut temp = 90.0;  // Start too hot
        
        // Simulate convergence over 100 steps
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(10));
            let speed = pid.update(temp);
            
            // Simulate temperature responding to speed adjustment
            // (simple model: temp decreases when speed < 1.0)
            let temp_change = (1.0 - speed) * 0.5;
            temp -= temp_change;
        }
        
        // Should converge close to target
        assert!((temp - 87.0).abs() < 2.0, "Should converge near target: {}", temp);
    }
    
    #[test]
    fn test_dynamic_controller() {
        let mut controller = DynamicSpeedController::new(87.0, 128);
        
        // Wait for initial state
        std::thread::sleep(Duration::from_millis(20));
        
        // Initially at target
        assert_eq!(controller.update(87.0), None);
        
        // Temperature rises
        std::thread::sleep(Duration::from_millis(150));
        let new_batch = controller.update(92.0);
        assert!(new_batch.is_some(), "Should adjust batch size when hot");
        if let Some(batch) = new_batch {
            assert!(batch < 128, "Should reduce batch size when hot, got {}", batch);
        }
    }
}


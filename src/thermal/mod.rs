#[cfg(feature = "pid-thermal")]
pub mod pid_controller;

#[cfg(feature = "pid-thermal")]
pub mod hardware_monitor;

#[cfg(feature = "pid-thermal")]
pub use pid_controller::DynamicSpeedController;

#[cfg(feature = "pid-thermal")]
pub use hardware_monitor::{read_gpu_temperature, estimate_temperature_from_performance};


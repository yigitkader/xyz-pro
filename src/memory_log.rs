/// Get current OS memory usage in MB (macOS specific)
#[cfg(target_os = "macos")]
pub fn get_process_memory_mb() -> f64 {
    use std::process::Command;
    
    if let Ok(output) = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
    {
        if let Ok(rss_str) = String::from_utf8(output.stdout) {
            if let Ok(rss_kb) = rss_str.trim().parse::<u64>() {
                return rss_kb as f64 / 1024.0;
            }
        }
    }
    0.0
}

#[cfg(not(target_os = "macos"))]
pub fn get_process_memory_mb() -> f64 {
    0.0
}

//! Memory diagnostic logging module
//! Tracks allocations and helps identify memory leaks
//!
//! Most functions here are for debugging and may be unused in production.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Global memory counters
pub static TOTAL_ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
pub static PEAK_ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
pub static BUFFER_POOL_ACQUIRED: AtomicU64 = AtomicU64::new(0);
pub static BUFFER_POOL_RETURNED: AtomicU64 = AtomicU64::new(0);
pub static BATCH_COUNT: AtomicU64 = AtomicU64::new(0);
pub static MATCH_VEC_ALLOCS: AtomicU64 = AtomicU64::new(0);

/// Log an allocation with source context
pub fn log_alloc(source: &str, bytes: usize) {
    let total = TOTAL_ALLOC_BYTES.fetch_add(bytes as u64, Ordering::Relaxed) + bytes as u64;
    let mut peak = PEAK_ALLOC_BYTES.load(Ordering::Relaxed);
    while total > peak {
        match PEAK_ALLOC_BYTES.compare_exchange(peak, total, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(p) => peak = p,
        }
    }
    
    if bytes > 1_000_000 {
        eprintln!("[MEM] {} allocated {:.2} MB (total: {:.2} MB, peak: {:.2} MB)",
            source, bytes as f64 / 1e6, total as f64 / 1e6, peak as f64 / 1e6);
    }
}

/// Log buffer pool activity
pub fn log_pool_acquire() {
    BUFFER_POOL_ACQUIRED.fetch_add(1, Ordering::Relaxed);
}

pub fn log_pool_return() {
    BUFFER_POOL_RETURNED.fetch_add(1, Ordering::Relaxed);
}

/// Print memory statistics
pub fn print_stats() {
    let total = TOTAL_ALLOC_BYTES.load(Ordering::Relaxed);
    let peak = PEAK_ALLOC_BYTES.load(Ordering::Relaxed);
    let acquired = BUFFER_POOL_ACQUIRED.load(Ordering::Relaxed);
    let returned = BUFFER_POOL_RETURNED.load(Ordering::Relaxed);
    let batches = BATCH_COUNT.load(Ordering::Relaxed);
    let vec_allocs = MATCH_VEC_ALLOCS.load(Ordering::Relaxed);
    
    eprintln!("\n[MEM STATS]");
    eprintln!("  Total logged allocations: {:.2} MB", total as f64 / 1e6);
    eprintln!("  Peak memory: {:.2} MB", peak as f64 / 1e6);
    eprintln!("  Buffer pool: {} acquired, {} returned, {} leaked", acquired, returned, acquired.saturating_sub(returned));
    eprintln!("  Batches processed: {}", batches);
    eprintln!("  Match Vec allocations: {}", vec_allocs);
}

/// Get current OS memory usage (macOS specific)
#[cfg(target_os = "macos")]
pub fn get_process_memory_mb() -> f64 {
    use std::process::Command;
    
    if let Ok(_pid) = std::env::var("$$").or_else(|_| Ok::<_, ()>(std::process::id().to_string())) {
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
    }
    0.0
}

#[cfg(not(target_os = "macos"))]
pub fn get_process_memory_mb() -> f64 {
    0.0
}

/// Memory checkpoint for tracking changes
pub struct MemoryCheckpoint {
    start_time: Instant,
    start_mem: f64,
    label: String,
}

impl MemoryCheckpoint {
    pub fn new(label: &str) -> Self {
        let mem = get_process_memory_mb();
        eprintln!("[MEM] {} START: {:.1} MB", label, mem);
        Self {
            start_time: Instant::now(),
            start_mem: mem,
            label: label.to_string(),
        }
    }
}

impl Drop for MemoryCheckpoint {
    fn drop(&mut self) {
        let mem = get_process_memory_mb();
        let delta = mem - self.start_mem;
        let elapsed = self.start_time.elapsed();
        eprintln!("[MEM] {} END: {:.1} MB (Δ{:+.1} MB) in {:?}", 
            self.label, mem, delta, elapsed);
    }
}


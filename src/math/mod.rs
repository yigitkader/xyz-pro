// SIMD Math module
// Note: Full SIMD implementation deferred to future optimization phase
// Current scalar implementation is already highly optimized (150+ M/s)
// SIMD optimization expected to add 15-20% more, but requires extensive validation

// For now, SIMD Math is only available as Metal shader helpers
// Rust-side implementation will be added when needed

#[cfg(feature = "simd-math")]
pub mod simd_bigint;

// Field operations are Metal shaders only (no Rust module needed)
// See src/math/field_ops.metal for implementation


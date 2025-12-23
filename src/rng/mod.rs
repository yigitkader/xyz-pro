#[cfg(feature = "philox-rng")]
pub mod philox;

#[cfg(feature = "philox-rng")]
pub use philox::{PhiloxCounter, philox4x32_10};

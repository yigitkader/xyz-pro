#[cfg(feature = "philox-rng")]
pub mod philox;

#[cfg(feature = "philox-rng")]
pub use philox::{PhiloxCounter, PhiloxState, philox_to_privkey, philox4x32_10};


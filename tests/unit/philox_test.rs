// tests/unit/philox_test.rs
// Unit tests for Philox RNG module

#[cfg(feature = "philox-rng")]
mod tests {
    use xyz_pro::rng::philox::*;
    use xyz_pro::crypto::is_valid_private_key;
    
    #[test]
    fn test_philox_deterministic() {
        let state1 = PhiloxState::new(12345);
        let state2 = PhiloxState::new(12345);
        
        let out1 = philox4x32_10(&state1);
        let out2 = philox4x32_10(&state2);
        
        assert_eq!(out1, out2, "Same seed should give same output");
    }
    
    #[test]
    fn test_philox_different_seeds() {
        let state1 = PhiloxState::new(12345);
        let state2 = PhiloxState::new(54321);
        
        let out1 = philox4x32_10(&state1);
        let out2 = philox4x32_10(&state2);
        
        assert_ne!(out1, out2, "Different seeds should give different output");
    }
    
    #[test]
    fn test_counter_increment() {
        let mut state = PhiloxState::new(1);
        let out1 = philox4x32_10(&state);
        
        state.increment(1);
        let out2 = philox4x32_10(&state);
        
        assert_ne!(out1, out2, "Incrementing counter should change output");
    }
    
    #[test]
    fn test_privkey_validity() {
        let state = PhiloxState::new(9999);
        let key = philox_to_privkey(&state);
        
        assert!(is_valid_private_key(&key), "Generated key should be valid");
        assert_ne!(key, [0u8; 32], "Key should not be zero");
    }
}


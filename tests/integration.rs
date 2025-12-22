// tests/integration.rs
// Integration test module hub - includes all test modules from tests/integration/

mod integration {
    mod correctness;
    mod cpu_gpu_xor;
    mod edge_cases;
    mod optimizations;
    mod performance;
    mod philox_test;
    mod pid_tuning;
    mod simd_validation;
    mod thermal;
}


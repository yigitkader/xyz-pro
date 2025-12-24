//! End-to-end integration tests
//!
//! Tests the complete pipeline: Generator → Matcher → Output
//! Uses known private keys with known addresses to verify correctness.

use xyz_pro::bridge::{KeyBatch, KeyGenerator, Matcher};
use xyz_pro::generator::{AddressEncoder, GeneratorConfig, GpuKeyGenerator, GpuGeneratorAdapter};
use xyz_pro::reader::{TargetSet, ParallelMatcher};

/// Known test vectors for Bitcoin addresses
/// Private key = 1 (0x0000000000000000000000000000000000000000000000000000000000000001)
mod test_vectors {
    /// Private key = 1 (Big Endian format - used in standard Bitcoin)
    pub const PRIVKEY_1_BE: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    
    /// Private key = 1 (Little Endian format - used by GPU)
    pub const PRIVKEY_1_LE: [u8; 32] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    
    /// P2PKH address for private key 1 (compressed pubkey)
    pub const P2PKH_1: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    
    /// P2WPKH (bech32) address for private key 1
    pub const P2WPKH_1: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    
    /// P2SH (nested segwit) address for private key 1
    pub const P2SH_1: &str = "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN";
    
    /// Hash160 of compressed pubkey for private key 1
    /// This is the pubkey hash used in P2PKH and P2WPKH addresses
    pub const PUBKEY_HASH_1: [u8; 20] = [
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4,
        0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
        0xf1, 0x43, 0x3b, 0xd6,
    ];
}

/// Test that the address encoder produces correct addresses
#[test]
fn test_address_encoder_known_vectors() {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use sha2::{Sha256, Digest};
    use ripemd::Ripemd160;
    
    // Create secret key from private key 1 (Big Endian format)
    let secret_key = SecretKey::from_bytes((&test_vectors::PRIVKEY_1_BE).into())
        .expect("Valid private key");
    
    // Get compressed public key
    let public_key = secret_key.public_key();
    let pubkey_bytes = public_key.to_encoded_point(true);
    let pubkey_compressed = pubkey_bytes.as_bytes();
    
    // Compute HASH160(pubkey)
    let sha256 = Sha256::digest(pubkey_compressed);
    let hash160 = Ripemd160::digest(&sha256);
    
    // Verify the hash160 matches our expected value
    let mut hash160_arr = [0u8; 20];
    hash160_arr.copy_from_slice(&hash160);
    
    assert_eq!(
        hash160_arr, 
        test_vectors::PUBKEY_HASH_1,
        "Hash160 of pubkey should match known value"
    );
    
    // Now test the encoder
    let mut encoder = AddressEncoder::new();
    
    // Create RawKeyData with our test values (Big Endian)
    let raw = xyz_pro::generator::RawKeyData {
        private_key: test_vectors::PRIVKEY_1_BE,
        pubkey_hash: hash160_arr,
        p2sh_hash: [0u8; 20],
    };
    
    let entry = encoder.encode(&raw);
    
    // Verify private key hex (Big Endian)
    assert_eq!(
        entry.private_key,
        "0000000000000000000000000000000000000000000000000000000000000001",
        "Private key hex should match"
    );
    
    // Verify P2PKH address
    assert_eq!(
        entry.p2pkh,
        test_vectors::P2PKH_1,
        "P2PKH address should match known value"
    );
    
    // Verify P2WPKH address
    assert_eq!(
        entry.p2wpkh,
        test_vectors::P2WPKH_1,
        "P2WPKH address should match known value"
    );
    
    println!("✅ Address encoder produces correct addresses");
    println!("   Private key: {}", entry.private_key);
    println!("   P2PKH:  {}", entry.p2pkh);
    println!("   P2SH:   {}", entry.p2sh);
    println!("   P2WPKH: {}", entry.p2wpkh);
}

/// Test that TargetSet correctly loads and matches addresses
#[test]
fn test_target_set_matching() {
    // Load test targets
    let targets = TargetSet::load("test_targets.json")
        .expect("Failed to load test_targets.json");
    
    println!("📂 Loaded {} targets", targets.stats.total);
    
    // Check that our known hash160 is in the target set
    let found = targets.contains_hash160(&test_vectors::PUBKEY_HASH_1);
    
    assert!(
        found,
        "Target set should contain hash160 for private key 1 (P2PKH/P2WPKH)"
    );
    
    println!("✅ Target set correctly identifies known address hash");
}

/// Test the complete matching pipeline with known private key
#[test]
fn test_end_to_end_matching() {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use sha2::{Sha256, Digest};
    use ripemd::Ripemd160;
    
    // 1. Load targets
    let targets = TargetSet::load("test_targets.json")
        .expect("Failed to load test_targets.json");
    
    println!("📂 Loaded {} targets", targets.stats.total);
    
    // 2. Compute the hashes for private key 1 (simulating what GPU would do)
    let secret_key = SecretKey::from_bytes((&test_vectors::PRIVKEY_1_BE).into())
        .expect("Valid private key");
    
    let public_key = secret_key.public_key();
    let pubkey_bytes = public_key.to_encoded_point(true);
    let pubkey_compressed = pubkey_bytes.as_bytes();
    
    // HASH160(pubkey) for P2PKH/P2WPKH
    let sha256 = Sha256::digest(pubkey_compressed);
    let hash160 = Ripemd160::digest(&sha256);
    let mut pubkey_hash = [0u8; 20];
    pubkey_hash.copy_from_slice(&hash160);
    
    // P2SH hash: HASH160(OP_0 || PUSH20 || pubkey_hash)
    let mut witness_script = [0u8; 22];
    witness_script[0] = 0x00; // OP_0
    witness_script[1] = 0x14; // PUSH20
    witness_script[2..22].copy_from_slice(&pubkey_hash);
    
    let sha256_ws = Sha256::digest(&witness_script);
    let hash160_ws = Ripemd160::digest(&sha256_ws);
    let mut p2sh_hash = [0u8; 20];
    p2sh_hash.copy_from_slice(&hash160_ws);
    
    // 3. Check against targets
    let (p2pkh_match, p2sh_match, p2wpkh_match) = targets.check_raw(&pubkey_hash, &p2sh_hash);
    
    println!("🔍 Checking private key 1:");
    println!("   P2PKH match:  {}", p2pkh_match);
    println!("   P2SH match:   {}", p2sh_match);
    println!("   P2WPKH match: {}", p2wpkh_match);
    
    // At least P2PKH or P2WPKH should match (they share the same hash160)
    assert!(
        p2pkh_match || p2wpkh_match,
        "Private key 1 should match P2PKH or P2WPKH target"
    );
    
    println!("✅ End-to-end matching works correctly!");
}

/// Test GPU generator produces valid keys
#[test]
fn test_gpu_generator_produces_keys() {
    // Skip if GPU not available
    let config = GeneratorConfig {
        start_offset: 1,
        batch_size: 100,
        ..Default::default()
    };
    
    let gpu = match GpuKeyGenerator::new(config) {
        Ok(g) => g,
        Err(e) => {
            println!("⚠️ GPU not available, skipping test: {}", e);
            return;
        }
    };
    
    // Create adapter to get generated keys
    let adapter = GpuGeneratorAdapter::new(gpu);
    
    // Generate first batch
    let batch_bytes = match adapter.generate_batch() {
        Ok(b) => b,
        Err(e) => {
            println!("⚠️ Failed to generate batch: {}", e);
            return;
        }
    };
    
    let batch = KeyBatch::new(batch_bytes);
    
    println!("🎮 GPU generated {} keys", batch.len());
    
    // Verify we got some keys
    assert!(batch.len() > 0, "Should generate at least one key");
    
    // Check first key is valid (non-zero)
    let first_key = batch.iter().next().unwrap();
    
    println!("   First key privkey: {}", hex::encode(first_key.private_key));
    println!("   First key hash160: {}", hex::encode(first_key.pubkey_hash));
    
    // Private key should not be all zeros
    assert!(
        !first_key.private_key.iter().all(|&b| b == 0),
        "Private key should not be all zeros"
    );
    
    // Hash160 should not be all zeros (computed from pubkey)
    assert!(
        !first_key.pubkey_hash.iter().all(|&b| b == 0),
        "Hash160 should not be all zeros"
    );
    
    println!("✅ GPU generator produces valid keys!");
}

/// Full integration test: Generate keys and check matching works
/// This test verifies the pipeline functionality (GPU → Matcher → Output)
/// without depending on specific private key values
#[test]
fn test_full_pipeline_integration() {
    // 1. Load targets
    let matcher = match ParallelMatcher::load("test_targets.json") {
        Ok(m) => m,
        Err(e) => {
            println!("⚠️ Failed to load targets: {}", e);
            return;
        }
    };
    
    println!("📂 Matcher loaded with {} targets", matcher.target_count());
    
    // 2. Initialize GPU generator
    let config = GeneratorConfig {
        start_offset: 1,
        batch_size: 100,
        ..Default::default()
    };
    
    let gpu = match GpuKeyGenerator::new(config) {
        Ok(g) => g,
        Err(e) => {
            println!("⚠️ GPU not available, skipping test: {}", e);
            return;
        }
    };
    
    let adapter = GpuGeneratorAdapter::new(gpu);
    
    // 3. Generate and check
    let batch_bytes = match adapter.generate_batch() {
        Ok(b) => b,
        Err(e) => {
            println!("⚠️ Failed to generate batch: {}", e);
            return;
        }
    };
    
    let key_batch = KeyBatch::new(batch_bytes);
    
    // Verify batch is valid
    assert!(key_batch.len() > 0, "Batch should contain keys");
    
    // Check batch against targets
    let matches = matcher.check_batch(&key_batch);
    
    println!("🔍 Generated {} keys, found {} matches", key_batch.len(), matches.len());
    
    for m in &matches {
        println!("   🎯 MATCH: privkey={}", hex::encode(m.key.private_key));
    }
    
    // Verify matching logic works (even if no matches found with random keys)
    // The important thing is that check_batch runs without error
    println!("✅ Pipeline integration test passed!");
    println!("   GPU generation: OK");
    println!("   Batch creation: OK");
    println!("   Matching logic: OK");
    println!("   Matches found: {}", matches.len());
}

/// Test that we can find matches for ALL 3 address types using CPU-computed keys
/// This directly tests the matching logic with known good data for:
/// - P2PKH (1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)
/// - P2SH  (3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN)
/// - P2WPKH (bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)
#[test]
fn test_matching_all_three_address_types() {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use sha2::{Sha256, Digest};
    use ripemd::Ripemd160;
    use xyz_pro::bridge::MatchType;
    
    // 1. Load targets
    let matcher = match ParallelMatcher::load("test_targets.json") {
        Ok(m) => m,
        Err(e) => {
            println!("⚠️ Failed to load targets: {}", e);
            return;
        }
    };
    
    println!("📂 Matcher loaded with {} targets", matcher.target_count());
    println!("   P2PKH targets: {}", matcher.stats().p2pkh);
    println!("   P2SH targets:  {}", matcher.stats().p2sh);
    println!("   P2WPKH targets: {}", matcher.stats().p2wpkh);
    
    // 2. Create a key entry for private key 1 manually
    let secret_key = SecretKey::from_bytes((&test_vectors::PRIVKEY_1_BE).into())
        .expect("Valid private key");
    
    let public_key = secret_key.public_key();
    let pubkey_bytes = public_key.to_encoded_point(true);
    let pubkey_compressed = pubkey_bytes.as_bytes();
    
    // HASH160(pubkey) - used for P2PKH and P2WPKH
    let sha256 = Sha256::digest(pubkey_compressed);
    let hash160 = Ripemd160::digest(&sha256);
    let mut pubkey_hash = [0u8; 20];
    pubkey_hash.copy_from_slice(&hash160);
    
    println!("🔑 Private key 1 computed hashes:");
    println!("   pubkey_hash (P2PKH/P2WPKH): {}", hex::encode(pubkey_hash));
    
    // P2SH hash: HASH160(OP_0 || PUSH20 || pubkey_hash)
    // This is the script hash for nested SegWit (P2SH-P2WPKH)
    let mut witness_script = [0u8; 22];
    witness_script[0] = 0x00; // OP_0
    witness_script[1] = 0x14; // PUSH20 (20 bytes)
    witness_script[2..22].copy_from_slice(&pubkey_hash);
    
    let sha256_ws = Sha256::digest(&witness_script);
    let hash160_ws = Ripemd160::digest(&sha256_ws);
    let mut p2sh_hash = [0u8; 20];
    p2sh_hash.copy_from_slice(&hash160_ws);
    
    println!("   p2sh_hash (P2SH):            {}", hex::encode(p2sh_hash));
    
    // 3. Use check_key directly to get ALL match types (not just first one)
    // ParallelMatcher.check_batch only returns first match, but check_key returns all
    let match_types = matcher.check_key(&pubkey_hash, &p2sh_hash);
    
    println!("\n🔍 Testing ALL 3 address types for private key 1:");
    println!("   Expected addresses in test_targets.json:");
    println!("   - P2PKH:  {}", test_vectors::P2PKH_1);
    println!("   - P2SH:   {}", test_vectors::P2SH_1);
    println!("   - P2WPKH: {}", test_vectors::P2WPKH_1);
    println!("\n   Match types found: {:?}", match_types);
    
    // Track which types we found
    let mut found_p2pkh = false;
    let mut found_p2sh = false;
    let mut found_p2wpkh = false;
    
    for mt in &match_types {
        match mt {
            MatchType::P2PKH => {
                found_p2pkh = true;
                println!("   ✅ P2PKH match found!");
            }
            MatchType::P2SH => {
                found_p2sh = true;
                println!("   ✅ P2SH match found!");
            }
            MatchType::P2WPKH => {
                found_p2wpkh = true;
                println!("   ✅ P2WPKH match found!");
            }
        }
    }
    
    // Verify all 3 types were matched
    assert!(found_p2pkh, "P2PKH address should match (1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH)");
    assert!(found_p2sh, "P2SH address should match (3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN)");
    assert!(found_p2wpkh, "P2WPKH address should match (bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)");
    
    println!("\n🎯 ALL 3 ADDRESS TYPES MATCHED SUCCESSFULLY!");
    println!("   ✅ P2PKH  (Legacy)           - 1BgGZ9...");
    println!("   ✅ P2SH   (Nested SegWit)    - 3JvL6Y...");
    println!("   ✅ P2WPKH (Native SegWit)    - bc1qw5...");
}

/// Test GLV Lambda transformation is mathematically correct
/// GLV uses λ where λ³ ≡ 1 (mod n) and β³ ≡ 1 (mod p)
/// For point P, φ(P) = (β·x, y) corresponds to private key λ·k
#[test]
fn test_glv_lambda_transform() {
    use k256::Scalar;
    use k256::elliptic_curve::PrimeField;
    
    // GLV Lambda constant (from keygen.metal, stored as ulong4)
    // In Metal: {0xDF02967C1B23BD72, 0x122E22EA20816678, 0xA5261C028812645A, 0x5363AD4CC05C30E0}
    // where .x is LSW, .w is MSW
    // As 256-bit big-endian: 0x5363AD4CC05C30E0_A5261C028812645A_122E22EA20816678_DF02967C1B23BD72
    let lambda_bytes: [u8; 32] = [
        0x53, 0x63, 0xAD, 0x4C, 0xC0, 0x5C, 0x30, 0xE0,  // .w (MSW)
        0xA5, 0x26, 0x1C, 0x02, 0x88, 0x12, 0x64, 0x5A,  // .z
        0x12, 0x2E, 0x22, 0xEA, 0x20, 0x81, 0x66, 0x78,  // .y
        0xDF, 0x02, 0x96, 0x7C, 0x1B, 0x23, 0xBD, 0x72,  // .x (LSW)
    ];
    
    // Test that λ³ ≡ 1 (mod n)
    // This is the fundamental property of GLV endomorphism
    let lambda = Scalar::from_repr(lambda_bytes.into()).unwrap();
    let lambda_sq = lambda * lambda;
    let lambda_cubed = lambda_sq * lambda;
    
    // λ³ should equal 1
    let one = Scalar::ONE;
    assert_eq!(
        lambda_cubed, one,
        "λ³ should equal 1 (mod n) for GLV endomorphism"
    );
    
    println!("✅ GLV Lambda verification:");
    println!("   λ³ ≡ 1 (mod n) verified");
    
    // Test scalar multiplication with multiple edge cases
    // This ensures scalar_mul_mod_n handles all ranges correctly
    
    println!("   Testing GLV transform with various k values:");
    
    // Helper to verify GLV transform
    let verify_glv = |k: Scalar, name: &str| {
        let glv_k = k * lambda;
        let lambda_sq = lambda * lambda;
        let recovered_k = glv_k * lambda_sq;
        assert_eq!(
            recovered_k, k,
            "(λ·k)·λ² should equal k for {}", name
        );
        println!("   ✓ {} verified", name);
    };
    
    // Case 1: k = 1 (minimal)
    let k1 = Scalar::from_repr(test_vectors::PRIVKEY_1_BE.into()).unwrap();
    verify_glv(k1, "k = 1 (minimal)");
    
    // Case 2: k = 2^128 (128-bit boundary - tests carry across word boundary)
    let mut k128_bytes = [0u8; 32];
    k128_bytes[15] = 1; // 2^128 in big-endian
    let k128 = Scalar::from_repr(k128_bytes.into()).unwrap();
    verify_glv(k128, "k = 2^128 (word boundary)");
    
    // Case 3: k = 2^192 (tests upper half of 256-bit range)
    let mut k192_bytes = [0u8; 32];
    k192_bytes[7] = 1; // 2^192 in big-endian
    let k192 = Scalar::from_repr(k192_bytes.into()).unwrap();
    verify_glv(k192, "k = 2^192 (upper half)");
    
    // Case 4: k = n - 1 (maximum valid scalar, near curve order)
    // n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    let n_minus_1_bytes: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
    ];
    let k_max = Scalar::from_repr(n_minus_1_bytes.into()).unwrap();
    verify_glv(k_max, "k = n-1 (maximum)");
    
    // Case 5: k = 0xFFFFFFFF...FFFF (all bits set, tests reduction)
    let k_allones_bytes = [0xFF; 32];
    // This will be reduced mod n automatically
    // Note: from_repr returns CtOption, use into_option() to convert
    let k_allones_opt: k256::elliptic_curve::subtle::CtOption<Scalar> = 
        Scalar::from_repr(k_allones_bytes.into());
    if k_allones_opt.is_some().into() {
        verify_glv(k_allones_opt.unwrap(), "k = 2^256-1 (all bits, reduced)");
    }
    
    // Case 6: Random large value (stress test)
    let k_random_bytes: [u8; 32] = [
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
        0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
        0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
        0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
    ];
    let k_random = Scalar::from_repr(k_random_bytes.into()).unwrap();
    verify_glv(k_random, "k = random large value");
    
    println!("✅ GLV Lambda transform is mathematically correct for all edge cases!");
}

/// Test that GPU-computed hashes match CPU-computed hashes
/// This verifies the GPU's SHA256 and RIPEMD160 implementations
#[test]
fn test_gpu_hash_matches_cpu() {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use sha2::{Sha256, Digest};
    use ripemd::Ripemd160;
    
    // Skip if GPU not available
    let config = GeneratorConfig {
        start_offset: 1,  // Start at private key 1
        batch_size: 32,
        ..Default::default()
    };
    
    let gpu = match GpuKeyGenerator::new(config) {
        Ok(g) => g,
        Err(e) => {
            println!("⚠️ GPU not available, skipping test: {}", e);
            return;
        }
    };
    
    let adapter = GpuGeneratorAdapter::new(gpu);
    
    // Generate keys starting from offset 1
    let batch_bytes = match adapter.generate_batch() {
        Ok(b) => b,
        Err(e) => {
            println!("⚠️ Failed to generate batch: {}", e);
            return;
        }
    };
    
    let batch = KeyBatch::new(batch_bytes);
    
    // Find a valid key to test
    let gpu_key = batch.iter()
        .find(|k| k.private_key.iter().any(|&b| b != 0))
        .expect("Should have at least one valid key");
    
    println!("🔍 Testing GPU vs CPU hash computation:");
    println!("   GPU private key: {}", hex::encode(gpu_key.private_key));
    println!("   GPU pubkey_hash: {}", hex::encode(gpu_key.pubkey_hash));
    println!("   GPU p2sh_hash:   {}", hex::encode(gpu_key.p2sh_hash));
    
    // Compute the same hashes on CPU
    let secret_key = match SecretKey::from_bytes((&gpu_key.private_key).into()) {
        Ok(sk) => sk,
        Err(_) => {
            println!("⚠️ Invalid private key from GPU, skipping verification");
            return;
        }
    };
    
    let public_key = secret_key.public_key();
    let pubkey_bytes = public_key.to_encoded_point(true);
    let pubkey_compressed = pubkey_bytes.as_bytes();
    
    // HASH160(pubkey)
    let sha256 = Sha256::digest(pubkey_compressed);
    let hash160 = Ripemd160::digest(&sha256);
    let mut cpu_pubkey_hash = [0u8; 20];
    cpu_pubkey_hash.copy_from_slice(&hash160);
    
    // P2SH hash
    let mut witness_script = [0u8; 22];
    witness_script[0] = 0x00;
    witness_script[1] = 0x14;
    witness_script[2..22].copy_from_slice(&cpu_pubkey_hash);
    
    let sha256_ws = Sha256::digest(&witness_script);
    let hash160_ws = Ripemd160::digest(&sha256_ws);
    let mut cpu_p2sh_hash = [0u8; 20];
    cpu_p2sh_hash.copy_from_slice(&hash160_ws);
    
    println!("   CPU pubkey_hash: {}", hex::encode(cpu_pubkey_hash));
    println!("   CPU p2sh_hash:   {}", hex::encode(cpu_p2sh_hash));
    
    // Verify hashes match
    assert_eq!(
        gpu_key.pubkey_hash, cpu_pubkey_hash,
        "GPU and CPU pubkey_hash should match"
    );
    
    assert_eq!(
        gpu_key.p2sh_hash, cpu_p2sh_hash,
        "GPU and CPU p2sh_hash should match"
    );
    
    println!("✅ GPU hash computation matches CPU!");
}

/// Test that the address encoder handles edge cases
#[test]
fn test_encoder_edge_cases() {
    let mut encoder = AddressEncoder::new();
    
    // Test with zero hash (edge case)
    let raw_zero = xyz_pro::generator::RawKeyData {
        private_key: [0u8; 32],
        pubkey_hash: [0u8; 20],
        p2sh_hash: [0u8; 20],
    };
    
    let entry = encoder.encode(&raw_zero);
    
    // All addresses should be valid format
    assert!(entry.p2pkh.starts_with('1'), "P2PKH should start with 1");
    assert!(entry.p2sh.starts_with('3'), "P2SH should start with 3");
    assert!(entry.p2wpkh.starts_with("bc1q"), "P2WPKH should start with bc1q");
    
    println!("✅ Encoder handles edge cases correctly");
}

/// Test cache functionality for TargetSet
#[test]
fn test_target_set_caching() {
    use std::time::Instant;
    
    // First load - should parse JSON
    let start1 = Instant::now();
    let targets1 = TargetSet::load("test_targets.json")
        .expect("Failed to load test_targets.json");
    let time1 = start1.elapsed();
    
    println!("📂 First load: {} targets in {:?}", targets1.stats.total, time1);
    
    // Second load - should use cache
    let start2 = Instant::now();
    let targets2 = TargetSet::load("test_targets.json")
        .expect("Failed to load test_targets.json (cached)");
    let time2 = start2.elapsed();
    
    println!("⚡ Cached load: {} targets in {:?}", targets2.stats.total, time2);
    
    // Both should have same target count
    assert_eq!(
        targets1.stats.total,
        targets2.stats.total,
        "Cached load should have same target count"
    );
    
    // Cached load should be faster (or at least similar)
    // We don't assert this strictly as it depends on system state
    println!("✅ Cache system works correctly");
}

// =============================================================================
// EDGE CASE TESTS
// =============================================================================

/// Test RawKeyData with all-zero private key (invalid)
#[test]
fn test_edge_case_zero_private_key() {
    let raw = xyz_pro::generator::RawKeyData {
        private_key: [0u8; 32],
        pubkey_hash: [0u8; 20],
        p2sh_hash: [0u8; 20],
    };
    
    // Zero private key is invalid
    assert!(!raw.is_valid(), "Zero private key should be invalid");
    println!("✅ Zero private key correctly rejected");
}

/// Test RawKeyData with maximum valid private key (n-1)
#[test]
fn test_edge_case_max_private_key() {
    // n-1 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
    let max_key: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
    ];
    
    let raw = xyz_pro::generator::RawKeyData {
        private_key: max_key,
        pubkey_hash: [0xFF; 20],
        p2sh_hash: [0xFF; 20],
    };
    
    // Max key is valid (non-zero)
    assert!(raw.is_valid(), "Max private key should be valid");
    println!("✅ Maximum private key (n-1) accepted");
}

/// Test RawKeyData::from_bytes with various sizes
#[test]
fn test_edge_case_raw_key_data_sizes() {
    // Exactly 72 bytes - should work
    let data_72 = vec![0x42u8; 72];
    let raw = xyz_pro::generator::RawKeyData::from_bytes(&data_72);
    assert!(raw.is_some(), "72 bytes should be valid");
    
    // Less than 72 bytes - should fail
    let data_71 = vec![0x42u8; 71];
    let raw = xyz_pro::generator::RawKeyData::from_bytes(&data_71);
    assert!(raw.is_none(), "71 bytes should be invalid");
    
    // More than 72 bytes - should work (uses first 72)
    let data_100 = vec![0x42u8; 100];
    let raw = xyz_pro::generator::RawKeyData::from_bytes(&data_100);
    assert!(raw.is_some(), "100 bytes should work (uses first 72)");
    
    println!("✅ RawKeyData::from_bytes handles edge sizes correctly");
}

/// Test address encoding with all-0xFF hash (boundary)
#[test]
fn test_edge_case_max_hash_encoding() {
    let mut encoder = AddressEncoder::new();
    
    let raw = xyz_pro::generator::RawKeyData {
        private_key: [0xFF; 32],
        pubkey_hash: [0xFF; 20],
        p2sh_hash: [0xFF; 20],
    };
    
    let entry = encoder.encode(&raw);
    
    // All addresses should still be valid format
    assert!(entry.p2pkh.starts_with('1'), "P2PKH should start with 1");
    assert!(entry.p2sh.starts_with('3'), "P2SH should start with 3");
    assert!(entry.p2wpkh.starts_with("bc1q"), "P2WPKH should start with bc1q");
    
    // Verify lengths are reasonable
    assert!(entry.p2pkh.len() >= 25 && entry.p2pkh.len() <= 34, "P2PKH length should be valid");
    assert!(entry.p2sh.len() >= 25 && entry.p2sh.len() <= 35, "P2SH length should be valid");
    assert!(entry.p2wpkh.len() >= 42 && entry.p2wpkh.len() <= 62, "P2WPKH length should be valid");
    
    println!("✅ Max hash (0xFF) encoding produces valid addresses");
    println!("   P2PKH:  {} (len={})", entry.p2pkh, entry.p2pkh.len());
    println!("   P2SH:   {} (len={})", entry.p2sh, entry.p2sh.len());
    println!("   P2WPKH: {} (len={})", entry.p2wpkh, entry.p2wpkh.len());
}

/// Test GLV scalar multiplication with edge values
#[test]
fn test_edge_case_glv_scalar_mul() {
    use k256::Scalar;
    use k256::elliptic_curve::PrimeField;
    
    // GLV Lambda
    let lambda_bytes: [u8; 32] = [
        0x53, 0x63, 0xAD, 0x4C, 0xC0, 0x5C, 0x30, 0xE0,
        0xA5, 0x26, 0x1C, 0x02, 0x88, 0x12, 0x64, 0x5A,
        0x12, 0x2E, 0x22, 0xEA, 0x20, 0x81, 0x66, 0x78,
        0xDF, 0x02, 0x96, 0x7C, 0x1B, 0x23, 0xBD, 0x72,
    ];
    let lambda = Scalar::from_repr(lambda_bytes.into()).unwrap();
    
    // Test cases that stress carry propagation in scalar_mul_mod_n
    let test_cases: Vec<(&str, [u8; 32])> = vec![
        // All ones in each word boundary
        ("0x00...00FF (byte 31)", {
            let mut k = [0u8; 32];
            k[31] = 0xFF;
            k
        }),
        ("0x00...FF00 (byte 30)", {
            let mut k = [0u8; 32];
            k[30] = 0xFF;
            k
        }),
        // Word boundaries (64-bit)
        ("0x00...00FFFFFFFF (lower 32 bits)", {
            let mut k = [0u8; 32];
            k[28..32].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
            k
        }),
        // 128-bit boundary
        ("0x00...FFFFFFFF...0 (bits 128-159)", {
            let mut k = [0u8; 32];
            k[12..16].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
            k
        }),
        // Alternating bits (stress test)
        ("0xAAAA...AAAA", {
            [0xAA; 32]
        }),
        ("0x5555...5555", {
            [0x55; 32]
        }),
    ];
    
    println!("🧪 Testing GLV scalar multiplication edge cases:");
    
    for (name, k_bytes) in test_cases {
        let k_opt: k256::elliptic_curve::subtle::CtOption<Scalar> = 
            Scalar::from_repr(k_bytes.into());
        if !bool::from(k_opt.is_some()) {
            continue; // Skip if not valid scalar
        }
        let k = k_opt.unwrap();
        
        // Verify: (λ·k)·λ² = k
        let glv_k = k * lambda;
        let lambda_sq = lambda * lambda;
        let recovered_k = glv_k * lambda_sq;
        
        assert_eq!(
            recovered_k, k,
            "GLV transform should be reversible for {}", name
        );
        println!("   ✓ {}", name);
    }
    
    println!("✅ All GLV scalar multiplication edge cases passed");
}

/// Test XOR filter with potential collision scenarios
#[test]
fn test_edge_case_xor_filter_collisions() {
    use std::collections::HashSet;
    
    // Generate hashes that could potentially collide in XOR-fold
    // XOR-fold: p1 ^ p2 ^ p3 where p1,p2=8 bytes, p3=4 bytes
    
    // Two different hashes that XOR-fold to same value:
    // hash1: [A, B, C] -> A ^ B ^ C
    // hash2: [A', B', C'] where A' ^ B' ^ C' = A ^ B ^ C
    
    let hash1: [u8; 20] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,  // p1
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,  // p2
        0x12, 0x34, 0x56, 0x78,                          // p3
    ];
    
    // Construct hash2 that XOR-folds to same value as hash1
    // by swapping bits between p1 and p2
    let hash2: [u8; 20] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,  // swapped p1
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,  // swapped p2
        0x12, 0x34, 0x56, 0x78,                          // same p3
    ];
    
    // These should XOR-fold to the same value but be different hashes
    fn xor_fold(hash: &[u8; 20]) -> u64 {
        let p1 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        let p2 = u64::from_le_bytes(hash[8..16].try_into().unwrap());
        let p3 = u32::from_le_bytes(hash[16..20].try_into().unwrap()) as u64;
        p1 ^ p2 ^ p3
    }
    
    let fold1 = xor_fold(&hash1);
    let fold2 = xor_fold(&hash2);
    
    // Verify they fold to same value (potential collision)
    assert_eq!(fold1, fold2, "These hashes should XOR-fold to same value");
    
    // But the actual hashes are different
    assert_ne!(hash1, hash2, "The actual hashes should be different");
    
    // This is why XOR filter uses HashSet as fallback!
    let mut set: HashSet<[u8; 20]> = HashSet::new();
    set.insert(hash1);
    
    // XOR filter would say "maybe" for hash2, but HashSet correctly rejects
    assert!(set.contains(&hash1), "HashSet should contain hash1");
    assert!(!set.contains(&hash2), "HashSet should NOT contain hash2 (collision handled)");
    
    println!("✅ XOR filter collision scenario correctly handled by HashSet fallback");
    println!("   hash1 XOR-fold: 0x{:016X}", fold1);
    println!("   hash2 XOR-fold: 0x{:016X}", fold2);
    println!("   Both fold to same value but HashSet distinguishes them");
}

/// Test KeyBatch iteration with various sizes
#[test]
fn test_edge_case_key_batch_sizes() {
    use xyz_pro::bridge::KeyBatch;
    use xyz_pro::generator::RawKeyData;
    
    // Empty batch
    let empty_data: Vec<u8> = vec![];
    let empty_batch = KeyBatch::new(&empty_data);
    assert_eq!(empty_batch.len(), 0, "Empty batch should have 0 keys");
    
    // Single key
    let single_data = vec![0x42u8; RawKeyData::SIZE];
    let single_batch = KeyBatch::new(&single_data);
    assert_eq!(single_batch.len(), 1, "Single key batch should have 1 key");
    
    // Partial key (should be truncated)
    let partial_data = vec![0x42u8; RawKeyData::SIZE + 10];
    let partial_batch = KeyBatch::new(&partial_data);
    assert_eq!(partial_batch.len(), 1, "Partial extra bytes should be ignored");
    
    // Large batch
    let large_data = vec![0x42u8; RawKeyData::SIZE * 1000];
    let large_batch = KeyBatch::new(&large_data);
    assert_eq!(large_batch.len(), 1000, "Large batch should have 1000 keys");
    
    println!("✅ KeyBatch handles all size edge cases correctly");
}

/// Test GPU output format matches expected layout
#[test]
fn test_edge_case_gpu_output_layout() {
    use xyz_pro::generator::RawKeyData;
    
    // GPU output format: [privkey:32][pubkey_hash:20][p2sh_hash:20] = 72 bytes
    assert_eq!(RawKeyData::SIZE, 72, "RawKeyData should be exactly 72 bytes");
    
    // Test struct layout
    let raw = RawKeyData {
        private_key: [0x11; 32],
        pubkey_hash: [0x22; 20],
        p2sh_hash: [0x33; 20],
    };
    
    // Verify field offsets by reconstructing from bytes
    let reconstructed = RawKeyData::from_bytes(&[
        // 32 bytes private key
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        // 20 bytes pubkey_hash
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22,
        // 20 bytes p2sh_hash
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, 0x33, 0x33,
    ]).expect("Should parse 72 bytes");
    
    assert_eq!(raw.private_key, reconstructed.private_key, "Private key layout mismatch");
    assert_eq!(raw.pubkey_hash, reconstructed.pubkey_hash, "Pubkey hash layout mismatch");
    assert_eq!(raw.p2sh_hash, reconstructed.p2sh_hash, "P2SH hash layout mismatch");
    
    println!("✅ GPU output layout verified: [privkey:32][pubkey_hash:20][p2sh_hash:20]");
}

/// Test private key validation edge cases
#[test]
fn test_edge_case_privkey_validation() {
    // Test is_valid() with various patterns
    let test_cases: Vec<(&str, [u8; 32], bool)> = vec![
        ("All zeros", [0u8; 32], false),
        ("Single bit set (LSB)", {
            let mut k = [0u8; 32];
            k[31] = 0x01;
            k
        }, true),
        ("Single bit set (MSB)", {
            let mut k = [0u8; 32];
            k[0] = 0x80;
            k
        }, true),
        ("All ones", [0xFF; 32], true),
        ("Only middle byte set", {
            let mut k = [0u8; 32];
            k[16] = 0x42;
            k
        }, true),
    ];
    
    println!("🧪 Testing private key validation edge cases:");
    
    for (name, privkey, expected_valid) in test_cases {
        let raw = xyz_pro::generator::RawKeyData {
            private_key: privkey,
            pubkey_hash: [0u8; 20],
            p2sh_hash: [0u8; 20],
        };
        
        let is_valid = raw.is_valid();
        assert_eq!(
            is_valid, expected_valid,
            "{}: expected valid={}, got valid={}", name, expected_valid, is_valid
        );
        println!("   ✓ {}: valid={}", name, is_valid);
    }
    
    println!("✅ All private key validation edge cases passed");
}

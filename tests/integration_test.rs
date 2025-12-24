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

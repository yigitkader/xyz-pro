use sha2::{Digest, Sha256};

use crate::crypto::hash160;

/// P2SH witness script: OP_0 PUSH20 <pubkey_hash>
#[inline]
pub fn p2sh_script_hash(pubkey_hash: &[u8; 20]) -> [u8; 20] {
    let mut script = [0u8; 22];
    script[0] = 0x00; // OP_0
    script[1] = 0x14; // PUSH 20
    script[2..22].copy_from_slice(pubkey_hash);
    hash160(&script)
}

/// Private key to WIF (compressed format)
/// Use `to_wif_compressed(key, true)` for compressed, `to_wif_compressed(key, false)` for uncompressed
#[allow(dead_code)]  // Public API, may be used externally
pub fn to_wif(key: &[u8; 32]) -> String {
    to_wif_compressed(key, true)
}

/// Private key to WIF with explicit compression flag
/// - compressed=true: WIF starts with 'K' or 'L' (33 bytes + checksum)
/// - compressed=false: WIF starts with '5' (32 bytes + checksum)
/// 
/// CRITICAL: Using wrong compression flag will derive DIFFERENT address!
/// Uncompressed keys found by GPU must use compressed=false
pub fn to_wif_compressed(key: &[u8; 32], compressed: bool) -> String {
    let capacity = if compressed { 38 } else { 37 };
    let mut data = Vec::with_capacity(capacity);
    data.push(0x80); // Mainnet prefix
    data.extend_from_slice(key);
    
    if compressed {
        data.push(0x01); // Compression flag (0x01 suffix)
    }
    // Uncompressed: no 0x01 suffix (only prefix + key + checksum = 37 bytes)
    
    let checksum = Sha256::digest(&Sha256::digest(&data));
    data.extend_from_slice(&checksum[..4]);
    
    bs58::encode(data).into_string()
}

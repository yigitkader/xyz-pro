// src/crypto/mod.rs
// Cryptographic primitives module

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// secp256k1 curve order N
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Check if private key is valid (0 < key < N)
#[inline]
pub fn is_valid_private_key(key: &[u8; 32]) -> bool {
    // Not zero
    let is_zero = key.iter().all(|&b| b == 0);
    if is_zero {
        return false;
    }
    // Less than curve order
    for i in 0..32 {
        if key[i] < SECP256K1_ORDER[i] {
            return true;
        }
        if key[i] > SECP256K1_ORDER[i] {
            return false;
        }
    }
    false
}

/// Hash160 = RIPEMD160(SHA256(data))
#[inline]
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(sha);
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_key_invalid() {
        let zero_key = [0u8; 32];
        assert!(!is_valid_private_key(&zero_key), "Zero key should be invalid");
    }

    #[test]
    fn test_curve_order_key_invalid() {
        let mut order_key = SECP256K1_ORDER;
        assert!(!is_valid_private_key(&order_key), "Curve order key should be invalid");
    }

    #[test]
    fn test_valid_key() {
        let valid_key = [0x01; 32];
        assert!(is_valid_private_key(&valid_key), "Key 1 should be valid");
    }

    #[test]
    fn test_hash160() {
        let data = b"hello world";
        let hash = hash160(data);
        assert_eq!(hash.len(), 20);
    }
}


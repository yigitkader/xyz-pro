use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

#[inline]
pub fn is_valid_private_key(key: &[u8; 32]) -> bool {
    if key.iter().all(|&b| b == 0) {
        return false;
    }
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
        assert!(!is_valid_private_key(&[0u8; 32]));
    }

    #[test]
    fn test_curve_order_invalid() {
        assert!(!is_valid_private_key(&SECP256K1_ORDER));
    }

    #[test]
    fn test_valid_key() {
        assert!(is_valid_private_key(&[0x01; 32]));
    }

    #[test]
    fn test_hash160() {
        assert_eq!(hash160(b"hello world").len(), 20);
    }
}

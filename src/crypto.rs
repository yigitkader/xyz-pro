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
    fn test_order_key_invalid() {
        // N itself is invalid
        assert!(!is_valid_private_key(&SECP256K1_ORDER), "N should be invalid");
    }

    #[test]
    fn test_order_minus_one_valid() {
        // N-1 is valid
        let mut n_minus_1 = SECP256K1_ORDER;
        // Subtract 1 (big-endian)
        let mut borrow = 1u16;
        for i in (0..32).rev() {
            let diff = n_minus_1[i] as u16 - borrow;
            if diff > 255 {
                n_minus_1[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                n_minus_1[i] = diff as u8;
                borrow = 0;
            }
        }
        assert!(is_valid_private_key(&n_minus_1), "N-1 should be valid");
    }

    #[test]
    fn test_order_plus_one_invalid() {
        // N+1 is invalid (> N)
        let mut n_plus_1 = SECP256K1_ORDER;
        // Add 1 (big-endian)
        let mut carry = 1u16;
        for i in (0..32).rev() {
            let sum = n_plus_1[i] as u16 + carry;
            n_plus_1[i] = sum as u8;
            carry = sum >> 8;
        }
        assert!(!is_valid_private_key(&n_plus_1), "N+1 should be invalid");
    }

    #[test]
    fn test_one_valid() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(is_valid_private_key(&one), "1 should be valid");
    }

    #[test]
    fn test_hash160_known_vector() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // RIPEMD160(SHA256("")) = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
        let result = hash160(b"");
        let expected = hex::decode("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb").unwrap();
        assert_eq!(result.to_vec(), expected);
    }

    #[test]
    fn test_hash160_pubkey_vector() {
        // Compressed public key for private key = 1
        // 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        let pubkey = hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
        let result = hash160(&pubkey);
        // Expected: 751e76e8199196d454941c45d1b3a323f1433bd6
        let expected = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
        assert_eq!(result.to_vec(), expected);
    }
}

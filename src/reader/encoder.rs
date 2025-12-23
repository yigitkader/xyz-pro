//! Independent Address Encoder for Reader Module
//!
//! Converts hash160/script_hash to Bitcoin addresses.
//! No dependencies on generator module.

use sha2::{Sha256, Digest};

/// Standalone address encoder - no external dependencies
pub struct AddressEncoder;

impl AddressEncoder {
    pub fn new() -> Self {
        Self
    }
    
    /// Encode hash160 to P2PKH address (1...)
    pub fn encode_p2pkh(&self, hash160: &[u8; 20]) -> String {
        // Version byte 0x00 for mainnet P2PKH
        let mut payload = vec![0x00];
        payload.extend_from_slice(hash160);
        
        // Double SHA256 checksum
        let checksum = double_sha256(&payload);
        payload.extend_from_slice(&checksum[0..4]);
        
        bs58::encode(payload).into_string()
    }
    
    /// Encode script hash to P2SH address (3...)
    pub fn encode_p2sh(&self, script_hash: &[u8; 20]) -> String {
        // Version byte 0x05 for mainnet P2SH
        let mut payload = vec![0x05];
        payload.extend_from_slice(script_hash);
        
        // Double SHA256 checksum
        let checksum = double_sha256(&payload);
        payload.extend_from_slice(&checksum[0..4]);
        
        bs58::encode(payload).into_string()
    }
    
    /// Encode hash160 to P2WPKH address (bc1q...)
    pub fn encode_p2wpkh(&self, hash160: &[u8; 20]) -> String {
        use bech32::{ToBase32, Variant};
        
        // Witness version 0 + hash160
        let mut program = vec![bech32::u5::try_from_u8(0).unwrap()]; // witness version 0
        program.extend(hash160.to_base32());
        
        bech32::encode("bc", program, Variant::Bech32).unwrap_or_default()
    }
}

impl Default for AddressEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Double SHA256 hash
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_p2pkh_encoding() {
        let encoder = AddressEncoder::new();
        // Known hash160 for testing
        let hash = [0u8; 20];
        let addr = encoder.encode_p2pkh(&hash);
        assert!(addr.starts_with('1'));
    }
    
    #[test]
    fn test_p2sh_encoding() {
        let encoder = AddressEncoder::new();
        let hash = [0u8; 20];
        let addr = encoder.encode_p2sh(&hash);
        assert!(addr.starts_with('3'));
    }
    
    #[test]
    fn test_p2wpkh_encoding() {
        let encoder = AddressEncoder::new();
        let hash = [0u8; 20];
        let addr = encoder.encode_p2wpkh(&hash);
        assert!(addr.starts_with("bc1"));
    }
}


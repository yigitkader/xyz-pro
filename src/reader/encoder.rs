//! Independent Address Encoder for Reader Module
//!
//! Converts hash160/script_hash to Bitcoin addresses.
//! No dependencies on generator module.

use sha2::{Sha256, Digest};

/// Standalone address encoder with pre-allocated buffers
pub struct AddressEncoder {
    /// Reusable buffer for payload (25 bytes: version + hash + checksum)
    payload_buf: [u8; 25],
    /// Reusable buffer for bech32 encoding
    bech32_buf: Vec<bech32::u5>,
}

impl AddressEncoder {
    pub fn new() -> Self {
        Self {
            payload_buf: [0u8; 25],
            bech32_buf: Vec::with_capacity(33),
        }
    }
    
    /// Encode hash160 to P2PKH address (1...)
    pub fn encode_p2pkh(&mut self, hash160: &[u8; 20]) -> String {
        // Version byte 0x00 for mainnet P2PKH
        self.payload_buf[0] = 0x00;
        self.payload_buf[1..21].copy_from_slice(hash160);
        
        // Double SHA256 checksum
        let checksum = double_sha256(&self.payload_buf[0..21]);
        self.payload_buf[21..25].copy_from_slice(&checksum[0..4]);
        
        bs58::encode(&self.payload_buf).into_string()
    }
    
    /// Encode script hash to P2SH address (3...)
    pub fn encode_p2sh(&mut self, script_hash: &[u8; 20]) -> String {
        // Version byte 0x05 for mainnet P2SH
        self.payload_buf[0] = 0x05;
        self.payload_buf[1..21].copy_from_slice(script_hash);
        
        // Double SHA256 checksum
        let checksum = double_sha256(&self.payload_buf[0..21]);
        self.payload_buf[21..25].copy_from_slice(&checksum[0..4]);
        
        bs58::encode(&self.payload_buf).into_string()
    }
    
    /// Encode hash160 to P2WPKH address (bc1q...)
    pub fn encode_p2wpkh(&mut self, hash160: &[u8; 20]) -> String {
        use bech32::{ToBase32, Variant};
        
        // Reuse buffer - witness version 0 + hash160
        self.bech32_buf.clear();
        self.bech32_buf.push(bech32::u5::try_from_u8(0).unwrap());
        self.bech32_buf.extend(hash160.to_base32());
        
        bech32::encode("bc", &self.bech32_buf, Variant::Bech32).unwrap_or_default()
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
        let mut encoder = AddressEncoder::new();
        // Known hash160 for testing
        let hash = [0u8; 20];
        let addr = encoder.encode_p2pkh(&hash);
        assert!(addr.starts_with('1'));
    }
    
    #[test]
    fn test_p2sh_encoding() {
        let mut encoder = AddressEncoder::new();
        let hash = [0u8; 20];
        let addr = encoder.encode_p2sh(&hash);
        assert!(addr.starts_with('3'));
    }
    
    #[test]
    fn test_p2wpkh_encoding() {
        let mut encoder = AddressEncoder::new();
        let hash = [0u8; 20];
        let addr = encoder.encode_p2wpkh(&hash);
        assert!(addr.starts_with("bc1"));
    }
}


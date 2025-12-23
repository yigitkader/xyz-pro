//! Address encoding for all 3 Bitcoin address types
//! 
//! - P2PKH: Legacy addresses (1...)
//! - P2SH: Nested SegWit (3...)
//! - P2WPKH: Native SegWit Bech32 (bc1q...)

use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use bech32::{self, ToBase32, Variant};

use super::{KeyEntry, RawKeyData};

/// Address encoder with pre-allocated buffers
pub struct AddressEncoder {
    /// Reusable buffer for Base58Check encoding
    base58_buffer: Vec<u8>,
}

impl AddressEncoder {
    pub fn new() -> Self {
        Self {
            base58_buffer: Vec::with_capacity(64),
        }
    }
    
    /// Encode raw key data to full KeyEntry with all address types
    #[inline]
    pub fn encode(&mut self, raw: &RawKeyData) -> KeyEntry {
        KeyEntry {
            private_key: hex::encode(raw.private_key),
            p2pkh: self.encode_p2pkh(&raw.pubkey_hash),
            p2sh: self.encode_p2sh(&raw.pubkey_hash),
            p2wpkh: self.encode_p2wpkh(&raw.pubkey_hash),
        }
    }
    
    /// P2PKH: Legacy address (prefix 0x00 for mainnet)
    /// Format: Base58Check(0x00 || HASH160(pubkey))
    #[inline]
    fn encode_p2pkh(&mut self, pubkey_hash: &[u8; 20]) -> String {
        self.base58_buffer.clear();
        self.base58_buffer.push(0x00); // mainnet prefix
        self.base58_buffer.extend_from_slice(pubkey_hash);
        
        // Add checksum
        let checksum = double_sha256(&self.base58_buffer);
        self.base58_buffer.extend_from_slice(&checksum[..4]);
        
        bs58::encode(&self.base58_buffer).into_string()
    }
    
    /// P2SH: Nested SegWit address (prefix 0x05 for mainnet)
    /// Format: Base58Check(0x05 || HASH160(OP_0 PUSH20 <pubkey_hash>))
    #[inline]
    fn encode_p2sh(&mut self, pubkey_hash: &[u8; 20]) -> String {
        // Build witness program: OP_0 PUSH20 <20-byte-pubkey-hash>
        let mut witness_program = [0u8; 22];
        witness_program[0] = 0x00; // OP_0
        witness_program[1] = 0x14; // PUSH20 (20 bytes)
        witness_program[2..22].copy_from_slice(pubkey_hash);
        
        // HASH160 of witness program
        let script_hash = hash160(&witness_program);
        
        self.base58_buffer.clear();
        self.base58_buffer.push(0x05); // P2SH mainnet prefix
        self.base58_buffer.extend_from_slice(&script_hash);
        
        // Add checksum
        let checksum = double_sha256(&self.base58_buffer);
        self.base58_buffer.extend_from_slice(&checksum[..4]);
        
        bs58::encode(&self.base58_buffer).into_string()
    }
    
    /// P2WPKH: Native SegWit Bech32 address
    /// Format: bech32(bc, 0, pubkey_hash)
    #[inline]
    fn encode_p2wpkh(&self, pubkey_hash: &[u8; 20]) -> String {
        // Witness version 0 + pubkey hash in base32
        let mut data = vec![bech32::u5::try_from_u8(0).unwrap()];
        data.extend(pubkey_hash.to_base32());
        
        bech32::encode("bc", data, Variant::Bech32).unwrap_or_default()
    }
    
    // ========================================================================
    // GPU-optimized methods: encode directly from hash (no EC computation)
    // ========================================================================
    
    /// P2PKH from pre-computed pubkey hash
    #[inline]
    pub fn encode_p2pkh_from_hash(&mut self, pubkey_hash: &[u8; 20]) -> String {
        self.encode_p2pkh(pubkey_hash)
    }
    
    /// P2SH from pre-computed script hash
    #[inline]
    pub fn encode_p2sh_from_hash(&mut self, script_hash: &[u8; 20]) -> String {
        self.base58_buffer.clear();
        self.base58_buffer.push(0x05); // P2SH mainnet prefix
        self.base58_buffer.extend_from_slice(script_hash);
        
        let checksum = double_sha256(&self.base58_buffer);
        self.base58_buffer.extend_from_slice(&checksum[..4]);
        
        bs58::encode(&self.base58_buffer).into_string()
    }
    
    /// P2WPKH from pre-computed pubkey hash
    #[inline]
    pub fn encode_p2wpkh_from_hash(&self, pubkey_hash: &[u8; 20]) -> String {
        self.encode_p2wpkh(pubkey_hash)
    }
}

impl Default for AddressEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Double SHA256 hash
#[inline(always)]
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// HASH160 = RIPEMD160(SHA256(data))
#[inline]
fn hash160(data: &[u8]) -> [u8; 20] {
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
    fn test_p2pkh_format() {
        let mut encoder = AddressEncoder::new();
        let hash = [0u8; 20];
        let addr = encoder.encode_p2pkh(&hash);
        assert!(addr.starts_with('1'));
    }
    
    #[test]
    fn test_p2sh_format() {
        let mut encoder = AddressEncoder::new();
        let hash = [0u8; 20];
        let addr = encoder.encode_p2sh(&hash);
        assert!(addr.starts_with('3'));
    }
    
    #[test]
    fn test_p2wpkh_format() {
        let encoder = AddressEncoder::new();
        let hash = [0u8; 20];
        let addr = encoder.encode_p2wpkh(&hash);
        assert!(addr.starts_with("bc1q"));
    }
    
    #[test]
    fn test_known_vectors() {
        // Test with known test vectors
        let mut encoder = AddressEncoder::new();
        
        // Zero hash should produce deterministic addresses
        let zero_hash = [0u8; 20];
        let p2pkh = encoder.encode_p2pkh(&zero_hash);
        let p2sh = encoder.encode_p2sh(&zero_hash);
        let p2wpkh = encoder.encode_p2wpkh(&zero_hash);
        
        // Verify format consistency
        assert_eq!(p2pkh.len(), 34); // Standard P2PKH length
        assert!(p2sh.len() >= 34);   // P2SH length
        assert!(p2wpkh.starts_with("bc1q"));
    }
}


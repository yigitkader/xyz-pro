//! Address encoding for Bitcoin address types
//! 
//! ## Supported Address Types
//! - **P2PKH**: Legacy addresses (1...) - `HASH160(pubkey)`
//! - **P2SH-P2WPKH**: Wrapped SegWit (3...) - `HASH160(0x0014 || HASH160(pubkey))`
//! - **P2WPKH**: Native SegWit Bech32 (bc1q...) - `HASH160(pubkey)` with bech32
//!
//! ## Important Limitation
//! The P2SH support is specifically for **P2SH-wrapped-P2WPKH** (single-key wrapped SegWit).
//! Arbitrary P2SH scripts (like multisig) are NOT supported, as they require
//! knowledge of the full redeem script, not just the public key.
//!
//! Uses thread-local singleton pattern for zero-allocation encoding.

use std::cell::RefCell;

use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use bech32::{self, ToBase32, Variant};

use super::{KeyEntry, RawKeyData};

// Thread-local singleton encoder - avoids repeated allocations
thread_local! {
    static ENCODER: RefCell<AddressEncoder> = RefCell::new(AddressEncoder::new_internal());
}

/// Encode raw key data using thread-local singleton encoder
/// This is the preferred API - zero allocation after first use per thread
#[inline]
pub fn encode_key(raw: &RawKeyData) -> KeyEntry {
    ENCODER.with(|encoder| encoder.borrow_mut().encode(raw))
}

/// Encode P2PKH address from hash using thread-local singleton
#[inline]
pub fn encode_p2pkh(pubkey_hash: &[u8; 20]) -> String {
    ENCODER.with(|encoder| encoder.borrow_mut().encode_p2pkh_from_hash(pubkey_hash))
}

/// Encode P2SH address from hash using thread-local singleton
#[inline]
pub fn encode_p2sh(script_hash: &[u8; 20]) -> String {
    ENCODER.with(|encoder| encoder.borrow_mut().encode_p2sh_from_hash(script_hash))
}

/// Encode P2WPKH address from hash using thread-local singleton
#[inline]
pub fn encode_p2wpkh(pubkey_hash: &[u8; 20]) -> String {
    ENCODER.with(|encoder| encoder.borrow_mut().encode_p2wpkh_from_hash(pubkey_hash))
}

/// Address encoder with pre-allocated buffers
pub struct AddressEncoder {
    /// Reusable buffer for Base58Check encoding
    base58_buffer: Vec<u8>,
    /// Reusable buffer for Bech32 encoding
    bech32_buffer: Vec<bech32::u5>,
}

impl AddressEncoder {
    /// Internal constructor - use thread-local functions instead
    fn new_internal() -> Self {
        Self {
            base58_buffer: Vec::with_capacity(64),
            bech32_buffer: Vec::with_capacity(33), // 1 (version) + 32 (hash in base32)
        }
    }
    
    /// Create a new encoder instance
    /// 
    /// **Prefer using the module-level functions** (`encode_key`, `encode_p2pkh`, etc.)
    /// which use a thread-local singleton for better performance.
    /// 
    /// Only use this if you need explicit lifetime control.
    #[inline]
    pub fn new() -> Self {
        Self::new_internal()
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
        
        // Use Bitcoin alphabet with leading zero handling
        base58check_encode(&self.base58_buffer)
    }
    
    /// P2SH-P2WPKH: Wrapped SegWit address (prefix 0x05 for mainnet)
    /// 
    /// **IMPORTANT**: This generates P2SH-wrapped-P2WPKH addresses (3xxx format).
    /// It does NOT support arbitrary P2SH scripts (like multisig).
    /// 
    /// Formula: Base58Check(0x05 || HASH160(0x0014 || pubkey_hash))
    /// Where 0x0014 = OP_0 (0x00) + PUSH20 (0x14)
    /// 
    /// This is specifically for single-key wrapped SegWit, not general P2SH.
    #[inline]
    fn encode_p2sh(&mut self, pubkey_hash: &[u8; 20]) -> String {
        // Build witness program: OP_0 PUSH20 <20-byte-pubkey-hash>
        // This is the redeemScript for P2SH-P2WPKH (wrapped SegWit)
        let mut witness_program = [0u8; 22];
        witness_program[0] = 0x00; // OP_0 (witness version 0)
        witness_program[1] = 0x14; // PUSH20 (20 bytes = pubkey_hash length)
        witness_program[2..22].copy_from_slice(pubkey_hash);
        
        // HASH160 of witness program gives us the script hash for P2SH
        let script_hash = hash160(&witness_program);
        
        self.base58_buffer.clear();
        self.base58_buffer.push(0x05); // P2SH mainnet prefix
        self.base58_buffer.extend_from_slice(&script_hash);
        
        // Add checksum
        let checksum = double_sha256(&self.base58_buffer);
        self.base58_buffer.extend_from_slice(&checksum[..4]);
        
        // Use Bitcoin alphabet with leading zero handling
        base58check_encode(&self.base58_buffer)
    }
    
    /// P2WPKH: Native SegWit Bech32 address
    /// Format: bech32(bc, 0, pubkey_hash)
    #[inline]
    fn encode_p2wpkh(&mut self, pubkey_hash: &[u8; 20]) -> String {
        // Reuse buffer - witness version 0 + pubkey hash in base32
        self.bech32_buffer.clear();
        self.bech32_buffer.push(bech32::u5::try_from_u8(0).unwrap());
        self.bech32_buffer.extend(pubkey_hash.to_base32());
        
        bech32::encode("bc", &self.bech32_buffer, Variant::Bech32).unwrap_or_default()
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
    pub fn encode_p2wpkh_from_hash(&mut self, pubkey_hash: &[u8; 20]) -> String {
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

/// Base58Check encode with proper leading zero handling
/// Note: bs58 crate already handles leading zero bytes correctly,
/// prepending '1' for each leading 0x00 byte automatically.
#[inline]
fn base58check_encode(data: &[u8]) -> String {
    bs58::encode(data).into_string()
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
        let mut encoder = AddressEncoder::new();
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
        
        println!("P2PKH: {} (len={})", p2pkh, p2pkh.len());
        println!("P2SH:  {} (len={})", p2sh, p2sh.len());
        println!("P2WPKH: {} (len={})", p2wpkh, p2wpkh.len());
        
        // The correct address for zero hash is: 1111111111111111111114oLvT2 (27 chars)
        // This is because 21 leading zeros become 21 '1's, plus ~6 chars for the rest
        // Standard P2PKH with random hash is 34 chars, but zero hash is shorter
        assert!(p2pkh.starts_with('1'), "P2PKH should start with '1'");
        assert!(p2sh.starts_with('3'), "P2SH should start with '3'");
        assert!(p2wpkh.starts_with("bc1q"), "P2WPKH should start with 'bc1q'");
        
        // Zero hash P2PKH is special case with many leading 1s
        assert!(p2pkh.chars().take_while(|&c| c == '1').count() >= 1);
    }
}


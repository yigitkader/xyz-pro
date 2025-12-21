use bech32::{convert_bits, decode};
use bs58;
use fxhash::FxHashMap;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::address::p2sh_script_hash;
use crate::error::Result;
use crate::types::{AddressType, Hash160};

#[derive(Deserialize)]
struct TargetFile {
    addresses: Vec<String>,
}

pub struct TargetDatabase {
    // pubkey_hash -> (address, type)
    targets: FxHashMap<Hash160, (String, AddressType)>,
}

impl TargetDatabase {
    pub fn new(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let file: TargetFile = serde_json::from_str(&content)?;

        let mut targets = FxHashMap::default();
        let mut skipped = 0;

        for addr in file.addresses {
            match Self::decode(&addr) {
                Some((hash, addr_type)) => {
                    targets.insert(hash, (addr, addr_type));
                }
                None => {
                    if skipped < 3 {
                        println!("[!] Skip: {}", addr);
                    }
                    skipped += 1;
                }
            }
        }

        if skipped > 0 {
            println!("[!] Skipped {} unsupported addresses", skipped);
        }

        Ok(Self { targets })
    }

    fn decode(addr: &str) -> Option<(Hash160, AddressType)> {
        // P2PKH (1...)
        if addr.starts_with('1') {
            let decoded = bs58::decode(addr).into_vec().ok()?;
            if decoded.len() != 25 {
                return None;
            }
            // Verify checksum
            let checksum = Sha256::digest(&Sha256::digest(&decoded[..21]));
            if &checksum[..4] != &decoded[21..] {
                return None;
            }
            return Some((Hash160::from_slice(&decoded[1..21]), AddressType::P2PKH));
        }

        // P2SH (3...)
        if addr.starts_with('3') {
            let decoded = bs58::decode(addr).into_vec().ok()?;
            if decoded.len() != 25 || decoded[0] != 0x05 {
                return None;
            }
            let checksum = Sha256::digest(&Sha256::digest(&decoded[..21]));
            if &checksum[..4] != &decoded[21..] {
                return None;
            }
            return Some((Hash160::from_slice(&decoded[1..21]), AddressType::P2SH));
        }

        // P2WPKH (bc1q...)
        if addr.starts_with("bc1q") {
            let (hrp, data, _) = decode(addr).ok()?;
            if hrp != "bc" || data.is_empty() || data[0].to_u8() != 0 {
                return None;
            }
            let program: Vec<u8> = convert_bits(&data[1..], 5, 8, false).ok()?;
            if program.len() != 20 {
                return None;
            }
            return Some((Hash160::from_slice(&program), AddressType::P2WPKH));
        }

        None
    }

    pub fn total(&self) -> usize {
        self.targets.len()
    }

    /// Direct hash lookup - works for any hash type (pubkey_hash or script_hash)
    /// Use this when you already have the exact hash to look up
    #[inline]
    pub fn check_direct(&self, hash: &Hash160) -> Option<(&str, AddressType)> {
        self.targets.get(hash).map(|(addr, atype)| (addr.as_str(), *atype))
    }

    /// Check if pubkey_hash matches any target (P2PKH, P2WPKH, or P2SH)
    /// This also computes P2SH script_hash from pubkey_hash and checks that
    pub fn check(&self, pubkey_hash: &Hash160) -> Option<(&str, AddressType)> {
        // Direct check for P2PKH and P2WPKH
        if let Some(result) = self.check_direct(pubkey_hash) {
            return Some(result);
        }

        // Check P2SH (need to compute script hash from pubkey hash)
        let script_hash = p2sh_script_hash(pubkey_hash.as_bytes());
        let script_hash160 = Hash160::from_slice(&script_hash);
        self.check_direct(&script_hash160)
    }

    /// Get all hashes for Bloom filter
    pub fn get_all_hashes(&self) -> Vec<[u8; 20]> {
        self.targets.keys().map(|h| *h.as_bytes()).collect()
    }
}

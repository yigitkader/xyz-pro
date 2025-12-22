// src/targets/mod.rs
// Target management module

use bech32::{convert_bits, decode};
use bs58;
use fxhash::FxHashMap;
use memmap2::Mmap;
use rayon::prelude::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::address::p2sh_script_hash;
use crate::error::{Result, ScannerError};
use crate::types::{hash160_to_address, AddressType, Hash160};

// ============================================================================
// BINARY FORMAT v2 (Future-proof: supports >4 billion records)
// ============================================================================
// Header: "XYZPRO02" (8 bytes) + count (8 bytes, LE) = 16 bytes
// Records: [hash160 (20 bytes) + type (1 byte)] × count = 21 bytes each
// Total: 16 + (N × 21) bytes
// ============================================================================

const MAGIC: &[u8; 8] = b"XYZPRO02";
const MAGIC_V1: &[u8; 8] = b"XYZPRO01"; // Legacy support
const RECORD_SIZE: usize = 21; // 20 byte hash + 1 byte type
const HEADER_SIZE_V2: usize = 16; // 8 magic + 8 count
const HEADER_SIZE_V1: usize = 12; // 8 magic + 4 count (legacy)

#[derive(Deserialize)]
struct TargetFile {
    addresses: Vec<String>,
}

pub struct TargetDatabase {
    // Memory-efficient: sadece type sakla, String yok!
    targets: FxHashMap<Hash160, AddressType>,
}

impl TargetDatabase {
    /// Load targets - binary varsa onu, yoksa JSON'dan binary oluştur
    pub fn new(json_path: &str) -> Result<Self> {
        let bin_path = json_path.replace(".json", ".bin");

        // Binary dosya varsa ve JSON'dan yeniyse, direkt yükle
        if should_use_binary(json_path, &bin_path) {
            println!("[*] Loading binary targets: {}", bin_path);
            return Self::load_binary(&bin_path);
        }

        // JSON'dan yükle ve binary'ye dönüştür
        println!("[*] Converting JSON to binary format...");
        let db = Self::load_json(json_path)?;

        // Binary kaydet
        if let Err(e) = db.save_binary(&bin_path) {
            eprintln!("[!] Warning: Could not save binary cache: {}", e);
        } else {
            println!("[✓] Binary cache saved: {}", bin_path);
        }

        Ok(db)
    }

    /// JSON'dan yükle (ilk seferde veya binary yoksa)
    fn load_json(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let file: TargetFile = serde_json::from_str(&content)?;

        let total = file.addresses.len();
        println!("[*] Parsing {} addresses...", total);

        // Paralel decode
        let results: Vec<_> = file
            .addresses
            .par_iter()
            .filter_map(|addr| Self::decode(addr))
            .collect();

        // Pre-allocate with exact capacity to avoid resize during inserts
        let mut targets = FxHashMap::with_capacity_and_hasher(
            results.len(),
            Default::default()
        );

        for (hash, addr_type) in results {
            targets.insert(hash, addr_type);
        }

        let skipped = total - targets.len();
        if skipped > 0 {
            println!("[!] Skipped {} unsupported addresses", skipped);
        }

        Ok(Self { targets })
    }

    /// Binary formatından yükle (çok hızlı!)
    /// Supports both v1 (u32 count) and v2 (u64 count) formats
    pub fn load_binary(path: &str) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        // Header kontrolü (minimum v1 header)
        if mmap.len() < HEADER_SIZE_V1 {
            return Err(ScannerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Binary file too small",
            )));
        }

        // Detect version and parse header
        let (count, header_size) = if &mmap[0..8] == MAGIC {
            // v2 format: u64 count
            if mmap.len() < HEADER_SIZE_V2 {
                return Err(ScannerError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Binary v2 file too small for header",
                )));
            }
            let count = u64::from_le_bytes([
                mmap[8], mmap[9], mmap[10], mmap[11],
                mmap[12], mmap[13], mmap[14], mmap[15],
            ]) as usize;
            (count, HEADER_SIZE_V2)
        } else if &mmap[0..8] == MAGIC_V1 {
            // v1 format: u32 count (legacy)
            println!("[*] Loading legacy v1 binary format...");
            let count = u32::from_le_bytes([mmap[8], mmap[9], mmap[10], mmap[11]]) as usize;
            (count, HEADER_SIZE_V1)
        } else {
            return Err(ScannerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid binary magic (expected XYZPRO01 or XYZPRO02)",
            )));
        };

        let expected_size = header_size + count * RECORD_SIZE;

        if mmap.len() < expected_size {
            return Err(ScannerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Binary file truncated: expected {} bytes, got {}",
                    expected_size,
                    mmap.len()
                ),
            )));
        }

        println!("[*] Loading {} records from binary...", count);

        // Paralel yükleme
        let data = &mmap[header_size..];
        let entries: Vec<_> = (0..count)
            .into_par_iter()
            .filter_map(|i| {
                let offset = i * RECORD_SIZE;
                let hash = Hash160::from_slice(&data[offset..offset + 20]);
                let addr_type = AddressType::from_u8(data[offset + 20])?;
                Some((hash, addr_type))
            })
            .collect();

        // Pre-allocate with exact capacity to avoid resize during inserts
        let mut targets = FxHashMap::with_capacity_and_hasher(
            entries.len(),
            Default::default()
        );
        for (hash, addr_type) in entries {
            targets.insert(hash, addr_type);
        }

        Ok(Self { targets })
    }

    /// Binary formatında kaydet (v2 format with u64 count)
    fn save_binary(&self, path: &str) -> Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::with_capacity(1024 * 1024, file); // 1MB buffer

        // Header v2: magic (8) + count (8) = 16 bytes
        writer.write_all(MAGIC)?;
        writer.write_all(&(self.targets.len() as u64).to_le_bytes())?;

        // Records
        for (hash, addr_type) in &self.targets {
            writer.write_all(hash.as_bytes())?;
            writer.write_all(&[addr_type.to_u8()])?;
        }

        writer.flush()?;
        Ok(())
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
    /// Adres String yerine runtime'da oluşturulur
    #[inline]
    pub fn check_direct(&self, hash: &Hash160) -> Option<(String, AddressType)> {
        self.targets.get(hash).map(|&atype| {
            let addr = hash160_to_address(hash, atype);
            (addr, atype)
        })
    }

    /// Check if pubkey_hash matches any target (P2PKH, P2WPKH, or P2SH)
    /// This also computes P2SH script_hash from pubkey_hash and checks that
    /// Public API for external verification
    #[allow(dead_code)]  // Public API, may be used externally
    pub fn check(&self, pubkey_hash: &Hash160) -> Option<(String, AddressType)> {
        // Direct check for P2PKH and P2WPKH
        if let Some(result) = self.check_direct(pubkey_hash) {
            return Some(result);
        }

        // Check P2SH (need to compute script hash from pubkey hash)
        let script_hash = p2sh_script_hash(pubkey_hash.as_bytes());
        let script_hash160 = Hash160::from_slice(&script_hash);
        self.check_direct(&script_hash160)
    }

    /// Sadece AddressType dön (adres String'i oluşturmadan)
    /// Public API for external verification
    #[inline]
    #[allow(dead_code)]  // Public API, may be used externally
    pub fn check_type(&self, hash: &Hash160) -> Option<AddressType> {
        self.targets.get(hash).copied()
    }

    /// Get all hashes for Xor Filter32
    pub fn get_all_hashes(&self) -> Vec<[u8; 20]> {
        self.targets.keys().map(|h| *h.as_bytes()).collect()
    }

    /// Memory stats
    pub fn memory_stats(&self) -> (usize, usize) {
        let entry_size = std::mem::size_of::<Hash160>() + std::mem::size_of::<AddressType>();
        let map_overhead = self.targets.capacity() * entry_size;
        (self.targets.len(), map_overhead)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_roundtrip() {
        // Create temp JSON file
        let temp_dir = std::env::temp_dir();
        let json_path = temp_dir.join("test_targets.json");
        let bin_path = temp_dir.join("test_targets.bin");

        // Clean up any existing files
        let _ = std::fs::remove_file(&json_path);
        let _ = std::fs::remove_file(&bin_path);

        // Create test JSON
        let json_content = r#"{"addresses": [
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        ]}"#;

        std::fs::write(&json_path, json_content).unwrap();

        // Load from JSON (should create binary)
        let db1 = TargetDatabase::new(json_path.to_str().unwrap()).unwrap();
        assert_eq!(db1.total(), 3);

        // Verify binary was created
        assert!(bin_path.exists(), "Binary file should be created");

        // Load from binary
        let db2 = TargetDatabase::load_binary(bin_path.to_str().unwrap()).unwrap();
        assert_eq!(db2.total(), 3);

        // Verify same data
        let hashes1: std::collections::HashSet<_> = db1.get_all_hashes().into_iter().collect();
        let hashes2: std::collections::HashSet<_> = db2.get_all_hashes().into_iter().collect();
        assert_eq!(hashes1, hashes2);

        // Clean up
        let _ = std::fs::remove_file(&json_path);
        let _ = std::fs::remove_file(&bin_path);
    }

    #[test]
    fn test_should_use_binary_logic() {
        let temp_dir = std::env::temp_dir();
        let json_path = temp_dir.join("test_logic.json");
        let bin_path = temp_dir.join("test_logic.bin");

        // Clean up
        let _ = std::fs::remove_file(&json_path);
        let _ = std::fs::remove_file(&bin_path);

        // Case 1: Neither exists - should return false
        assert!(!should_use_binary(
            json_path.to_str().unwrap(),
            bin_path.to_str().unwrap()
        ));

        // Case 2: Only JSON exists - should return false
        std::fs::write(&json_path, "{}").unwrap();
        assert!(!should_use_binary(
            json_path.to_str().unwrap(),
            bin_path.to_str().unwrap()
        ));

        // Case 3: Both exist, bin newer - should return true
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&bin_path, "bin").unwrap();
        assert!(should_use_binary(
            json_path.to_str().unwrap(),
            bin_path.to_str().unwrap()
        ));

        // Clean up
        let _ = std::fs::remove_file(&json_path);
        let _ = std::fs::remove_file(&bin_path);
    }
}

/// Binary dosya kullanılmalı mı?
fn should_use_binary(json_path: &str, bin_path: &str) -> bool {
    let bin_path = Path::new(bin_path);
    let json_path = Path::new(json_path);

    if !bin_path.exists() {
        return false;
    }

    // JSON yoksa binary'yi kullan
    if !json_path.exists() {
        return true;
    }

    // Tarih karşılaştırması
    match (json_path.metadata(), bin_path.metadata()) {
        (Ok(json_meta), Ok(bin_meta)) => {
            match (json_meta.modified(), bin_meta.modified()) {
                (Ok(json_time), Ok(bin_time)) => bin_time >= json_time,
                _ => true, // Tarih alınamıyorsa binary'yi dene
            }
        }
        _ => bin_path.exists(),
    }
}


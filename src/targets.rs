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
// BINARY FORMAT
// ============================================================================
// Header: "XYZPRO01" (8 bytes) + count (4 bytes, LE) = 12 bytes
// Records: [hash160 (20 bytes) + type (1 byte)] × count = 21 bytes each
// Total: 12 + (N × 21) bytes
// ============================================================================

const MAGIC: &[u8; 8] = b"XYZPRO01";
const RECORD_SIZE: usize = 21; // 20 byte hash + 1 byte type

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

        let mut targets = FxHashMap::default();
        targets.reserve(results.len());

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
    fn load_binary(path: &str) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        // Header kontrolü
        if mmap.len() < 12 {
            return Err(ScannerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Binary file too small",
            )));
        }

        if &mmap[0..8] != MAGIC {
            return Err(ScannerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid binary magic",
            )));
        }

        let count = u32::from_le_bytes([mmap[8], mmap[9], mmap[10], mmap[11]]) as usize;
        let expected_size = 12 + count * RECORD_SIZE;

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
        let data = &mmap[12..];
        let entries: Vec<_> = (0..count)
            .into_par_iter()
            .filter_map(|i| {
                let offset = i * RECORD_SIZE;
                let hash = Hash160::from_slice(&data[offset..offset + 20]);
                let addr_type = AddressType::from_u8(data[offset + 20])?;
                Some((hash, addr_type))
            })
            .collect();

        let mut targets = FxHashMap::default();
        targets.reserve(entries.len());
        for (hash, addr_type) in entries {
            targets.insert(hash, addr_type);
        }

        Ok(Self { targets })
    }

    /// Binary formatında kaydet
    fn save_binary(&self, path: &str) -> Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::with_capacity(1024 * 1024, file); // 1MB buffer

        // Header
        writer.write_all(MAGIC)?;
        writer.write_all(&(self.targets.len() as u32).to_le_bytes())?;

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
    #[inline]
    pub fn check_type(&self, hash: &Hash160) -> Option<AddressType> {
        self.targets.get(hash).copied()
    }

    /// Get all hashes for Bloom filter
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

// Target management - MMAP optimized

use bech32::{convert_bits, decode};
use bs58;
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

const MAGIC: &[u8; 8] = b"XYZPRO03";  // Sorted binary format
const RECORD_SIZE: usize = 21;         // 20 byte hash + 1 byte type
const HEADER_SIZE: usize = 16;         // 8 magic + 8 count

#[derive(Deserialize)]
struct TargetFile {
    addresses: Vec<String>,
}

/// Memory-mapped target database
/// RAM usage: ~200MB instead of ~2GB (10x reduction!)
/// Lookup: O(log n) binary search on mmap (~26 comparisons for 49M records)
pub struct TargetDatabase {
    mmap: Option<Mmap>,
    count: usize,
    // Keep file handle alive for mmap
    _file: Option<File>,
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

        // JSON'dan yükle ve sorted binary'ye dönüştür
        println!("[*] Converting JSON to sorted binary format...");
        let entries = Self::parse_json(json_path)?;
        
        // Sort by hash for binary search
        let mut sorted_entries = entries;
        sorted_entries.par_sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        
        // Save sorted binary
        Self::save_sorted_binary(&bin_path, &sorted_entries)?;
        println!("[✓] Sorted binary cache saved: {}", bin_path);
        
        // Now load via mmap
        Self::load_binary(&bin_path)
    }

    /// Parse JSON and return entries (not stored in HashMap)
    fn parse_json(path: &str) -> Result<Vec<(Hash160, AddressType)>> {
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

        let skipped = total - results.len();
        if skipped > 0 {
            println!("[!] Skipped {} unsupported addresses", skipped);
        }

        Ok(results)
    }

    /// Load via mmap - direct binary search
    pub fn load_binary(path: &str) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        if mmap.len() < HEADER_SIZE || &mmap[0..8] != MAGIC {
            return Err(ScannerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid binary format - delete .bin file and retry",
            )));
        }

        let count = u64::from_le_bytes([
            mmap[8], mmap[9], mmap[10], mmap[11],
            mmap[12], mmap[13], mmap[14], mmap[15],
        ]) as usize;

        let expected_size = HEADER_SIZE + count * RECORD_SIZE;
        if mmap.len() < expected_size {
            return Err(ScannerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Binary file truncated",
            )));
        }

        Ok(Self {
            mmap: Some(mmap),
            count,
            _file: Some(File::open(path)?),
        })
    }

    /// Save sorted binary
    fn save_sorted_binary(path: &str, entries: &[(Hash160, AddressType)]) -> Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);

        // Header v3
        writer.write_all(MAGIC)?;
        writer.write_all(&(entries.len() as u64).to_le_bytes())?;

        // Sorted records
        for (hash, addr_type) in entries {
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
        self.count
    }

    /// Binary search on mmap - O(log n) lookup
    #[inline]
    pub fn check_direct(&self, hash: &Hash160) -> Option<(String, AddressType)> {
        let mmap = self.mmap.as_ref()?;
        let data = &mmap[HEADER_SIZE..];
        let target = hash.as_bytes();

        // Binary search
        let mut left = 0usize;
        let mut right = self.count;

        while left < right {
            let mid = left + (right - left) / 2;
            let offset = mid * RECORD_SIZE;
            let entry_hash = &data[offset..offset + 20];

            match entry_hash.cmp(target) {
                std::cmp::Ordering::Less => left = mid + 1,
                std::cmp::Ordering::Greater => right = mid,
                std::cmp::Ordering::Equal => {
                    let addr_type = AddressType::from_u8(data[offset + 20])?;
                    let addr = hash160_to_address(hash, addr_type);
                    return Some((addr, addr_type));
                }
            }
        }

        None
    }

    /// Check with P2SH script hash computation
    #[allow(dead_code)]
    pub fn check(&self, pubkey_hash: &Hash160) -> Option<(String, AddressType)> {
        if let Some(result) = self.check_direct(pubkey_hash) {
            return Some(result);
        }

        let script_hash = p2sh_script_hash(pubkey_hash.as_bytes());
        let script_hash160 = Hash160::from_slice(&script_hash);
        self.check_direct(&script_hash160)
    }

    #[inline]
    #[allow(dead_code)]
    pub fn check_type(&self, hash: &Hash160) -> Option<AddressType> {
        self.check_direct(hash).map(|(_, t)| t)
    }

    /// Get all hashes for Xor Filter32 (one-time load)
    pub fn get_all_hashes(&self) -> Vec<[u8; 20]> {
        let mmap = match &self.mmap {
            Some(m) => m,
            None => return Vec::new(),
        };
        
        let data = &mmap[HEADER_SIZE..];
        
        (0..self.count)
            .into_par_iter()
            .map(|i| {
                let offset = i * RECORD_SIZE;
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&data[offset..offset + 20]);
                hash
            })
            .collect()
    }

    /// Memory stats (virtual, not resident)
    pub fn memory_stats(&self) -> (usize, usize) {
        let virtual_size = self.count * RECORD_SIZE;
        (self.count, virtual_size)
    }
}

/// Binary dosya kullanılmalı mı?
fn should_use_binary(json_path: &str, bin_path: &str) -> bool {
    let bin_path = Path::new(bin_path);
    let json_path = Path::new(json_path);

    if !bin_path.exists() {
        return false;
    }

    if !json_path.exists() {
        return true;
    }

    match (json_path.metadata(), bin_path.metadata()) {
        (Ok(json_meta), Ok(bin_meta)) => {
            match (json_meta.modified(), bin_meta.modified()) {
                (Ok(json_time), Ok(bin_time)) => bin_time >= json_time,
                _ => true,
            }
        }
        _ => bin_path.exists(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_search() {
        // Create temp sorted binary
        let temp_dir = std::env::temp_dir();
        let bin_path = temp_dir.join("test_sorted.bin");
        
        // Create test entries (sorted)
        let mut entries = vec![
            (Hash160::from_slice(&[0u8; 20]), AddressType::P2PKH),
            (Hash160::from_slice(&[1u8; 20]), AddressType::P2SH),
            (Hash160::from_slice(&[2u8; 20]), AddressType::P2WPKH),
        ];
        entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        
        TargetDatabase::save_sorted_binary(bin_path.to_str().unwrap(), &entries).unwrap();
        
        // Load and test binary search
        let db = TargetDatabase::load_binary(bin_path.to_str().unwrap()).unwrap();
        
        assert!(db.check_direct(&Hash160::from_slice(&[0u8; 20])).is_some());
        assert!(db.check_direct(&Hash160::from_slice(&[1u8; 20])).is_some());
        assert!(db.check_direct(&Hash160::from_slice(&[2u8; 20])).is_some());
        assert!(db.check_direct(&Hash160::from_slice(&[3u8; 20])).is_none());
        
        let _ = std::fs::remove_file(&bin_path);
    }
}

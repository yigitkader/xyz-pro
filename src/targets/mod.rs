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

const MAGIC: &[u8; 8] = b"XYZPRO03";
const RECORD_SIZE: usize = 21;
const HEADER_SIZE: usize = 16;

#[derive(Deserialize)]
struct TargetFile {
    addresses: Vec<String>,
}

pub struct TargetDatabase {
    mmap: Option<Mmap>,
    count: usize,
    _file: Option<File>,
}

impl TargetDatabase {
    pub fn new(json_path: &str) -> Result<Self> {
        let bin_path = json_path.replace(".json", ".bin");

        if should_use_binary(json_path, &bin_path) {
            println!("[*] Loading binary targets: {}", bin_path);
            return Self::load_binary(&bin_path);
        }

        println!("[*] Converting JSON to sorted binary format...");
        let mut entries = Self::parse_json(json_path)?;
        entries.par_sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        
        Self::save_sorted_binary(&bin_path, &entries)?;
        println!("[✓] Sorted binary cache saved: {}", bin_path);
        Self::load_binary(&bin_path)
    }

    fn parse_json(path: &str) -> Result<Vec<(Hash160, AddressType)>> {
        let content = fs::read_to_string(path)?;
        let file: TargetFile = serde_json::from_str(&content)?;

        let total = file.addresses.len();
        println!("[*] Parsing {} addresses...", total);

        let results: Vec<_> = file.addresses.par_iter().filter_map(|addr| Self::decode(addr)).collect();

        let skipped = total - results.len();
        if skipped > 0 {
            println!("[!] Skipped {} unsupported addresses", skipped);
        }
        Ok(results)
    }

    pub fn load_binary(path: &str) -> Result<Self> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        if mmap.len() < HEADER_SIZE || &mmap[0..8] != MAGIC {
            return Err(ScannerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid binary format - delete .bin file and retry",
            )));
        }

        let count = u64::from_le_bytes(mmap[8..16].try_into().unwrap()) as usize;

        if mmap.len() < HEADER_SIZE + count * RECORD_SIZE {
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

    fn save_sorted_binary(path: &str, entries: &[(Hash160, AddressType)]) -> Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);

        writer.write_all(MAGIC)?;
        writer.write_all(&(entries.len() as u64).to_le_bytes())?;

        for (hash, addr_type) in entries {
            writer.write_all(hash.as_bytes())?;
            writer.write_all(&[addr_type.to_u8()])?;
        }
        writer.flush()?;
        Ok(())
    }

    fn decode(addr: &str) -> Option<(Hash160, AddressType)> {
        if addr.starts_with('1') {
            return Self::decode_base58(addr, 0x00, AddressType::P2PKH);
        }
        if addr.starts_with('3') {
            return Self::decode_base58(addr, 0x05, AddressType::P2SH);
        }
        if addr.starts_with("bc1q") {
            return Self::decode_bech32(addr);
        }
        None
    }

    fn decode_base58(addr: &str, expected_version: u8, addr_type: AddressType) -> Option<(Hash160, AddressType)> {
        let decoded = bs58::decode(addr).into_vec().ok()?;
        if decoded.len() != 25 || (expected_version != 0x00 && decoded[0] != expected_version) {
            return None;
        }
        let checksum = Sha256::digest(&Sha256::digest(&decoded[..21]));
        if &checksum[..4] != &decoded[21..] {
            return None;
        }
        Some((Hash160::from_slice(&decoded[1..21]), addr_type))
    }

    fn decode_bech32(addr: &str) -> Option<(Hash160, AddressType)> {
        let (hrp, data, _) = decode(addr).ok()?;
        if hrp != "bc" || data.is_empty() || data[0].to_u8() != 0 {
            return None;
        }
        let program: Vec<u8> = convert_bits(&data[1..], 5, 8, false).ok()?;
        if program.len() != 20 {
            return None;
        }
        Some((Hash160::from_slice(&program), AddressType::P2WPKH))
    }

    pub fn total(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn check_direct(&self, hash: &Hash160) -> Option<(String, AddressType)> {
        let mmap = self.mmap.as_ref()?;
        let data = &mmap[HEADER_SIZE..];
        let target = hash.as_bytes();

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
                    return Some((hash160_to_address(hash, addr_type), addr_type));
                }
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn check(&self, pubkey_hash: &Hash160) -> Option<(String, AddressType)> {
        if let Some(result) = self.check_direct(pubkey_hash) {
            return Some(result);
        }
        let script_hash = Hash160::from_slice(&p2sh_script_hash(pubkey_hash.as_bytes()));
        self.check_direct(&script_hash)
    }

    #[inline]
    #[allow(dead_code)]
    pub fn check_type(&self, hash: &Hash160) -> Option<AddressType> {
        self.check_direct(hash).map(|(_, t)| t)
    }

    /// Zero-copy hash access via mmap
    /// Returns slice reference instead of copying 980MB
    #[inline]
    #[allow(dead_code)]
    pub fn hash_at(&self, index: usize) -> Option<&[u8; 20]> {
        if index >= self.count {
            return None;
        }
        let mmap = self.mmap.as_ref()?;
        let offset = HEADER_SIZE + index * RECORD_SIZE;
        let slice = &mmap[offset..offset + 20];
        Some(slice.try_into().ok()?)
    }
    
    /// Iterator over all hashes (zero-copy via mmap)
    pub fn iter_hashes(&self) -> impl Iterator<Item = [u8; 20]> + '_ {
        let mmap = self.mmap.as_ref();
        (0..self.count).filter_map(move |i| {
            let m = mmap?;
            let offset = HEADER_SIZE + i * RECORD_SIZE;
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&m[offset..offset + 20]);
            Some(hash)
        })
    }
    
    /// Collect all hashes (only when absolutely necessary)
    /// WARNING: Allocates ~980MB for 49M targets
    /// Get all hashes as a Vec (for backward compatibility)
    /// Prefer `iter_hashes()` for zero-copy iteration
    #[allow(dead_code)]
    pub fn get_all_hashes(&self) -> Vec<[u8; 20]> {
        self.iter_hashes().collect()
    }

    pub fn memory_stats(&self) -> (usize, usize) {
        (self.count, self.count * RECORD_SIZE)
    }
}

fn should_use_binary(json_path: &str, bin_path: &str) -> bool {
    let bin = Path::new(bin_path);
    let json = Path::new(json_path);

    if !bin.exists() {
        return false;
    }
    if !json.exists() {
        return true;
    }

    match (json.metadata(), bin.metadata()) {
        (Ok(jm), Ok(bm)) => match (jm.modified(), bm.modified()) {
            (Ok(jt), Ok(bt)) => bt >= jt,
            _ => true,
        },
        _ => bin.exists(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_search() {
        let temp_dir = std::env::temp_dir();
        let bin_path = temp_dir.join("test_sorted.bin");
        
        let mut entries = vec![
            (Hash160::from_slice(&[0u8; 20]), AddressType::P2PKH),
            (Hash160::from_slice(&[1u8; 20]), AddressType::P2SH),
            (Hash160::from_slice(&[2u8; 20]), AddressType::P2WPKH),
        ];
        entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        
        TargetDatabase::save_sorted_binary(bin_path.to_str().unwrap(), &entries).unwrap();
        let db = TargetDatabase::load_binary(bin_path.to_str().unwrap()).unwrap();
        
        assert!(db.check_direct(&Hash160::from_slice(&[0u8; 20])).is_some());
        assert!(db.check_direct(&Hash160::from_slice(&[1u8; 20])).is_some());
        assert!(db.check_direct(&Hash160::from_slice(&[2u8; 20])).is_some());
        assert!(db.check_direct(&Hash160::from_slice(&[3u8; 20])).is_none());
        
        let _ = std::fs::remove_file(&bin_path);
    }
}

//! Output writer for JSON and Binary formats
//! 
//! Handles efficient file writing with buffering.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;
use serde::{Deserialize, Serialize};

use super::{KeyEntry, KeyOutput};

/// Output format options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Binary,
    Both,
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Json
    }
}

/// Output writer with buffered I/O
pub struct OutputWriter {
    output_dir: String,
    format: OutputFormat,
    file_counter: u64,
}

impl OutputWriter {
    pub fn new(output_dir: &str, format: OutputFormat) -> std::io::Result<Self> {
        // Ensure output directory exists
        fs::create_dir_all(output_dir)?;
        
        Ok(Self {
            output_dir: output_dir.to_string(),
            format,
            file_counter: 0,
        })
    }
    
    /// Write a batch of keys to file(s)
    pub fn write_batch(&mut self, keys: &[KeyEntry]) -> std::io::Result<String> {
        self.file_counter += 1;
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let base_name = format!("keys_{}_{:06}", timestamp, self.file_counter);
        
        match self.format {
            OutputFormat::Json => {
                let filename = self.write_json(keys, &base_name)?;
                Ok(filename)
            }
            OutputFormat::Binary => {
                let filename = self.write_binary(keys, &base_name)?;
                Ok(filename)
            }
            OutputFormat::Both => {
                self.write_json(keys, &base_name)?;
                let filename = self.write_binary(keys, &base_name)?;
                Ok(filename)
            }
        }
    }
    
    /// Write keys as JSON
    fn write_json(&self, keys: &[KeyEntry], base_name: &str) -> std::io::Result<String> {
        let filename = format!("{}/{}.json", self.output_dir, base_name);
        let file = File::create(&filename)?;
        let mut writer = BufWriter::with_capacity(64 * 1024 * 1024, file); // 64MB buffer
        
        let output = KeyOutput {
            private_keys: keys.to_vec(),
        };
        
        serde_json::to_writer(&mut writer, &output)?;
        writer.flush()?;
        
        Ok(filename)
    }
    
    /// Write keys as compact binary format
    /// Format: [count: u64][entries...]
    /// Entry: [private_key: 32 bytes][pubkey_hash: 20 bytes]
    fn write_binary(&self, keys: &[KeyEntry], base_name: &str) -> std::io::Result<String> {
        let filename = format!("{}/{}.bin", self.output_dir, base_name);
        let file = File::create(&filename)?;
        let mut writer = BufWriter::with_capacity(64 * 1024 * 1024, file); // 64MB buffer
        
        // Write header: magic + count
        writer.write_all(b"BTCK")?; // Magic bytes
        writer.write_all(&(keys.len() as u64).to_le_bytes())?;
        
        // Write each entry
        for key in keys {
            // Private key (32 bytes from hex)
            if let Ok(pk_bytes) = hex::decode(&key.private_key) {
                writer.write_all(&pk_bytes)?;
            }
            
            // Addresses as length-prefixed strings
            write_string(&mut writer, &key.p2pkh)?;
            write_string(&mut writer, &key.p2sh)?;
            write_string(&mut writer, &key.p2wpkh)?;
        }
        
        writer.flush()?;
        Ok(filename)
    }
    
    /// Get current file counter
    pub fn files_written(&self) -> u64 {
        self.file_counter
    }
}

/// Write length-prefixed string
fn write_string<W: Write>(writer: &mut W, s: &str) -> std::io::Result<()> {
    let bytes = s.as_bytes();
    writer.write_all(&(bytes.len() as u16).to_le_bytes())?;
    writer.write_all(bytes)?;
    Ok(())
}

/// Read binary file back (for verification)
#[allow(dead_code)]
pub fn read_binary_file(path: &Path) -> std::io::Result<Vec<KeyEntry>> {
    use std::io::{BufReader, Read};
    
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    
    // Read magic
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != b"BTCK" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid magic bytes",
        ));
    }
    
    // Read count
    let mut count_bytes = [0u8; 8];
    reader.read_exact(&mut count_bytes)?;
    let count = u64::from_le_bytes(count_bytes);
    
    let mut entries = Vec::with_capacity(count as usize);
    
    for _ in 0..count {
        // Read private key
        let mut pk = [0u8; 32];
        reader.read_exact(&mut pk)?;
        
        // Read addresses
        let p2pkh = read_string(&mut reader)?;
        let p2sh = read_string(&mut reader)?;
        let p2wpkh = read_string(&mut reader)?;
        
        entries.push(KeyEntry {
            private_key: hex::encode(pk),
            p2pkh,
            p2sh,
            p2wpkh,
        });
    }
    
    Ok(entries)
}

#[allow(dead_code)]
fn read_string<R: std::io::Read>(reader: &mut R) -> std::io::Result<String> {
    let mut len_bytes = [0u8; 2];
    reader.read_exact(&mut len_bytes)?;
    let len = u16::from_le_bytes(len_bytes) as usize;
    
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    
    String::from_utf8(bytes).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    
    #[test]
    fn test_json_output() {
        let temp_dir = "/tmp/btc_gen_test_json";
        let _ = fs::remove_dir_all(temp_dir);
        
        let mut writer = OutputWriter::new(temp_dir, OutputFormat::Json).unwrap();
        let keys = vec![KeyEntry {
            private_key: "0".repeat(64),
            p2pkh: "1test".to_string(),
            p2sh: "3test".to_string(),
            p2wpkh: "bc1qtest".to_string(),
        }];
        
        let filename = writer.write_batch(&keys).unwrap();
        assert!(Path::new(&filename).exists());
        
        let _ = fs::remove_dir_all(temp_dir);
    }
    
    #[test]
    fn test_binary_roundtrip() {
        let temp_dir = "/tmp/btc_gen_test_bin";
        let _ = fs::remove_dir_all(temp_dir);
        
        let mut writer = OutputWriter::new(temp_dir, OutputFormat::Binary).unwrap();
        let original = vec![KeyEntry {
            private_key: "ab".repeat(32),
            p2pkh: "1TestAddress".to_string(),
            p2sh: "3TestAddress".to_string(),
            p2wpkh: "bc1qtest".to_string(),
        }];
        
        let filename = writer.write_batch(&original).unwrap();
        let loaded = read_binary_file(Path::new(&filename)).unwrap();
        
        assert_eq!(original.len(), loaded.len());
        assert_eq!(original[0].private_key, loaded[0].private_key);
        assert_eq!(original[0].p2pkh, loaded[0].p2pkh);
        
        let _ = fs::remove_dir_all(temp_dir);
    }
}


use sha2::{Digest, Sha256};
use std::hash::{Hash, Hasher};

/// Hash160 = RIPEMD160(SHA256(pubkey))
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C, align(4))]
pub struct Hash160([u8; 20]);

impl Hash160 {
    #[inline(always)]
    pub fn from_slice(slice: &[u8]) -> Self {
        debug_assert_eq!(slice.len(), 20);
        let mut arr = [0u8; 20];
        arr.copy_from_slice(slice);
        Self(arr)
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl Hash for Hash160 {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Use all 20 bytes to minimize hash collisions
        // FxHash and other fast hashers work well with full data
        state.write(&self.0);
    }
}

/// Sadece 3 adres tipi destekleniyor
/// Binary format: 0=P2PKH, 1=P2SH, 2=P2WPKH
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum AddressType {
    P2PKH = 0,   // Legacy (1...)
    P2SH = 1,    // SegWit wrapped (3...)
    P2WPKH = 2,  // Native SegWit (bc1q...)
}

impl AddressType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::P2PKH => "P2PKH",
            Self::P2SH => "P2SH",
            Self::P2WPKH => "P2WPKH",
        }
    }

    #[inline]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::P2PKH),
            1 => Some(Self::P2SH),
            2 => Some(Self::P2WPKH),
            _ => None,
        }
    }

    #[inline]
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Convert Hash160 to address string
pub fn hash160_to_address(hash: &Hash160, addr_type: AddressType) -> String {
    match addr_type {
        AddressType::P2PKH => encode_base58_check(0x00, hash.as_bytes()),
        AddressType::P2SH => encode_base58_check(0x05, hash.as_bytes()),
        AddressType::P2WPKH => encode_bech32(hash.as_bytes()),
    }
}

/// Base58Check encoding (P2PKH ve P2SH için)
fn encode_base58_check(version: u8, hash: &[u8; 20]) -> String {
    let mut data = Vec::with_capacity(25);
    data.push(version);
    data.extend_from_slice(hash);

    let checksum = Sha256::digest(&Sha256::digest(&data));
    data.extend_from_slice(&checksum[..4]);

    bs58::encode(data).into_string()
}

/// Bech32 encoding (P2WPKH için)
fn encode_bech32(hash: &[u8; 20]) -> String {
    use bech32::{u5, Variant};

    // 8-to-5 bit conversion for witness program
    // 20 bytes always converts cleanly to 32 5-bit values
    let converted = bech32::convert_bits(hash, 8, 5, true)
        .expect("20-byte hash should always convert to 5-bit groups");
    
    // witness version 0 + converted data
    let mut witness_data = Vec::with_capacity(33); // 1 version + 32 data
    witness_data.push(u5::try_from_u8(0).expect("0 is valid u5"));
    
    for b in converted {
        witness_data.push(u5::try_from_u8(b).expect("5-bit value should be valid u5"));
    }

    bech32::encode("bc", witness_data, Variant::Bech32)
        .expect("valid witness program should encode")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_reconstruction_p2pkh() {
        // Known test vector: hash160 -> address
        let hash_hex = "89abcdefabbaabbaabbaabbaabbaabbaabbaabba";
        let hash_bytes: [u8; 20] = hex::decode(hash_hex).unwrap().try_into().unwrap();
        let hash = Hash160::from_slice(&hash_bytes);
        
        let addr = hash160_to_address(&hash, AddressType::P2PKH);
        assert!(addr.starts_with('1'), "P2PKH should start with 1: {}", addr);
        
        // Verify roundtrip: decode address, compare hash
        let decoded = bs58::decode(&addr).into_vec().unwrap();
        assert_eq!(&decoded[1..21], &hash_bytes);
    }

    #[test]
    fn test_address_reconstruction_p2sh() {
        let hash_hex = "89abcdefabbaabbaabbaabbaabbaabbaabbaabba";
        let hash_bytes: [u8; 20] = hex::decode(hash_hex).unwrap().try_into().unwrap();
        let hash = Hash160::from_slice(&hash_bytes);
        
        let addr = hash160_to_address(&hash, AddressType::P2SH);
        assert!(addr.starts_with('3'), "P2SH should start with 3: {}", addr);
        
        // Verify roundtrip
        let decoded = bs58::decode(&addr).into_vec().unwrap();
        assert_eq!(decoded[0], 0x05);
        assert_eq!(&decoded[1..21], &hash_bytes);
    }

    #[test]
    fn test_address_reconstruction_p2wpkh() {
        let hash_hex = "89abcdefabbaabbaabbaabbaabbaabbaabbaabba";
        let hash_bytes: [u8; 20] = hex::decode(hash_hex).unwrap().try_into().unwrap();
        let hash = Hash160::from_slice(&hash_bytes);
        
        let addr = hash160_to_address(&hash, AddressType::P2WPKH);
        assert!(addr.starts_with("bc1q"), "P2WPKH should start with bc1q: {}", addr);
    }

    #[test]
    fn test_address_type_binary() {
        assert_eq!(AddressType::P2PKH.to_u8(), 0);
        assert_eq!(AddressType::P2SH.to_u8(), 1);
        assert_eq!(AddressType::P2WPKH.to_u8(), 2);
        
        assert_eq!(AddressType::from_u8(0), Some(AddressType::P2PKH));
        assert_eq!(AddressType::from_u8(1), Some(AddressType::P2SH));
        assert_eq!(AddressType::from_u8(2), Some(AddressType::P2WPKH));
        assert_eq!(AddressType::from_u8(3), None);
    }

    #[test]
    fn test_bech32_roundtrip() {
        // Test with known bech32 address
        let hash_hex = "751e76e8199196d454941c45d1b3a323f1433bd6";
        let hash_bytes: [u8; 20] = hex::decode(hash_hex).unwrap().try_into().unwrap();
        let hash = Hash160::from_slice(&hash_bytes);
        
        let addr = hash160_to_address(&hash, AddressType::P2WPKH);
        assert!(addr.starts_with("bc1q"), "Should be bech32: {}", addr);
        
        // Verify it decodes back correctly
        let (hrp, data, _) = bech32::decode(&addr).unwrap();
        assert_eq!(hrp, "bc");
        let program: Vec<u8> = bech32::convert_bits(&data[1..], 5, 8, false).unwrap();
        assert_eq!(program, hash_bytes);
    }

    #[test]
    fn test_hash160_equality() {
        let h1 = Hash160::from_slice(&[1u8; 20]);
        let h2 = Hash160::from_slice(&[1u8; 20]);
        let h3 = Hash160::from_slice(&[2u8; 20]);
        
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_hash160_as_hashmap_key() {
        use std::collections::HashMap;
        
        let mut map: HashMap<Hash160, u32> = HashMap::new();
        let h1 = Hash160::from_slice(&[1u8; 20]);
        let h2 = Hash160::from_slice(&[2u8; 20]);
        
        map.insert(h1, 100);
        map.insert(h2, 200);
        
        assert_eq!(map.get(&h1), Some(&100));
        assert_eq!(map.get(&h2), Some(&200));
        assert_eq!(map.get(&Hash160::from_slice(&[3u8; 20])), None);
    }

    #[test]
    fn test_known_address_vectors() {
        // Bitcoin genesis block coinbase address
        // 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        let genesis_hash = hex::decode("62e907b15cbf27d5425399ebf6f0fb50ebb88f18").unwrap();
        let hash = Hash160::from_slice(&genesis_hash);
        let addr = hash160_to_address(&hash, AddressType::P2PKH);
        assert_eq!(addr, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }
}

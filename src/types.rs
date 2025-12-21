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

    #[inline(always)]
    fn prefix_u64(&self) -> u64 {
        u64::from_le_bytes([
            self.0[0], self.0[1], self.0[2], self.0[3],
            self.0[4], self.0[5], self.0[6], self.0[7],
        ])
    }
}

impl Hash for Hash160 {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.prefix_u64());
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

// ============================================================================
// ADDRESS RECONSTRUCTION (sadece eşleşme bulunduğunda kullanılır)
// ============================================================================

/// Hash160'dan adres oluştur (String saklama yerine runtime'da üret)
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

    // Convert 8-bit bytes to 5-bit groups
    let mut data = vec![u5::try_from_u8(0).unwrap()]; // witness version 0
    for chunk in hash.chunks(5) {
        let mut acc = 0u64;
        let mut bits = 0;
        for &byte in chunk {
            acc = (acc << 8) | byte as u64;
            bits += 8;
        }
        while bits >= 5 {
            bits -= 5;
            data.push(u5::try_from_u8(((acc >> bits) & 0x1F) as u8).unwrap());
        }
        if bits > 0 {
            data.push(u5::try_from_u8(((acc << (5 - bits)) & 0x1F) as u8).unwrap());
        }
    }

    // Proper 8-to-5 bit conversion for witness program
    let converted = bech32::convert_bits(hash, 8, 5, true).unwrap();
    let mut witness_data = vec![u5::try_from_u8(0).unwrap()];
    for b in converted {
        witness_data.push(u5::try_from_u8(b).unwrap());
    }

    bech32::encode("bc", witness_data, Variant::Bech32).unwrap()
}

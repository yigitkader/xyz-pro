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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddressType {
    P2PKH,   // Legacy (1...)
    P2SH,    // SegWit wrapped (3...)
    P2WPKH,  // Native SegWit (bc1q...)
}

impl AddressType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::P2PKH => "P2PKH",
            Self::P2SH => "P2SH",
            Self::P2WPKH => "P2WPKH",
        }
    }
}

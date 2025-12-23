use sha2::{Digest, Sha256};
use crate::crypto::hash160;

/// P2SH script hash: HASH160(OP_0 PUSH20 <pubkey_hash>)
#[inline]
pub fn p2sh_script_hash(pubkey_hash: &[u8; 20]) -> [u8; 20] {
    let mut script = [0u8; 22];
    script[0] = 0x00;
    script[1] = 0x14;
    script[2..22].copy_from_slice(pubkey_hash);
    hash160(&script)
}

/// Private key to WIF format
pub fn to_wif_compressed(key: &[u8; 32], compressed: bool) -> String {
    let mut data = Vec::with_capacity(if compressed { 38 } else { 37 });
    data.push(0x80);
    data.extend_from_slice(key);
    if compressed { data.push(0x01); }
    
    let checksum = Sha256::digest(Sha256::digest(&data));
    data.extend_from_slice(&checksum[..4]);
    bs58::encode(data).into_string()
}

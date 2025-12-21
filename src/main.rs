use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{CompressedPublicKey, Network, PrivateKey};
use bloomfilter::Bloom;
use once_cell::sync::Lazy;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
struct TargetsFile {
    addresses: Vec<String>,
}

static SECP: Lazy<Secp256k1<secp256k1::All>> = Lazy::new(|| Secp256k1::new());

const TARGETS_FILE: &str = "targets.json";

fn banner() {
    println!(
        r#"
██████╗ ███████╗████████╗
██╔══██╗██╔════╝╚══██╔══╝
██████╔╝███████╗   ██║
██╔══██╗╚════██║   ██║
██████╔╝███████║   ██║
╚═════╝ ╚══════╝   ╚═╝
        B T C
"#
    );

    println!("Bitcoin Address Recovery Tool");
    println!("{}", "=".repeat(70));
    println!("Supported Types: ");
    println!("  1️⃣  P2PKH (Legacy)         - startst with 1... ");
    println!("  2️⃣  P2SH (Nested SegWit)   - startst with 3...");
    println!("  3️⃣  P2WPKH (Native SegWit) - startst with bc1q...");
    println!("{}", "=".repeat(70));
}

fn generate_random_btc_private_key() -> PrivateKey {
    let mut rng = rand::rng();
    let mut key_bytes = [0u8; 32];

    loop {
        rng.fill(&mut key_bytes);
        if let Ok(secret_key) = SecretKey::from_slice(&key_bytes) {
            return PrivateKey::new(secret_key, Network::Bitcoin);
        }
    }
}

fn is_valid_address_type(address: &str) -> bool {
    //P2PKH (Legacy) , P2SH (Nested SegWit – tek imza) , P2WPKH (Native SegWit – Bech32)
    address.starts_with('1') || address.starts_with('3') || address.starts_with("bc1")
}

fn get_address_type(address: &str) -> &str {
    if address.starts_with("1") {
        "P2PKH"
    } else if address.starts_with("3") {
        "P2SH"
    } else if address.starts_with("bc1q") {
        "P2WPKH"
    } else {
        "Unknown"
    }
}

fn generate_addresses(private_key: &PrivateKey) -> Vec<(String, String, String)> {
    let public_key = private_key.public_key(&SECP);
    let compressed_pubkey = CompressedPublicKey(public_key.inner);
    let mut addresses = Vec::new();

    let p2pkh_addr = bitcoin::Address::p2pkh(&compressed_pubkey, Network::Bitcoin);
    addresses.push((
        p2pkh_addr.to_string(),
        "P2PKH".to_string(),
        private_key.to_wif(),
    ));

    let p2wpkh_addr = bitcoin::Address::p2wpkh(&compressed_pubkey, Network::Bitcoin);
    addresses.push((
        p2wpkh_addr.to_string(),
        "P2WPKH".to_string(),
        private_key.to_wif(),
    ));

    let p2wpkh_script = p2wpkh_addr.script_pubkey();
    let p2sh_addr =
        bitcoin::Address::p2sh(&p2wpkh_script, Network::Bitcoin).expect("P2SH creation failed");
    addresses.push((
        p2sh_addr.to_string(),
        "P2SH".to_string(),
        private_key.to_wif(),
    ));

    addresses
}

fn load_targets(file_name: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(file_name)?;
    let targets_file: TargetsFile = serde_json::from_str(&content)?;

    let valid_addresses = targets_file
        .addresses
        .into_iter()
        .filter(|addr| is_valid_address_type(addr))
        .collect::<Vec<String>>();
    Ok(valid_addresses)
}

fn main() {
    banner();

    let valid_targets = match load_targets(TARGETS_FILE) {
        Ok(t) => {
            if t.is_empty() {
                println!("No valid addresses found in the targets file.");
                return;
            } else {
                println!("Found {} valid addresses", t.len());
            }
            t
        }
        Err(e) => {
            println!("Error loading targets file: {}", e);
            return;
        }
    };

    println!("{}", "=".repeat(70));

    println!("Bloom Filter Initialization...");
    let fp_rate = 0.001; // %0.1 false positive rate
    println!("Bloom Filter Rate: {}", fp_rate * 100.0);
    let mut bloom = Bloom::new_for_fp_rate(valid_targets.len(), fp_rate);

    for add in &valid_targets {
        bloom.set(add);
    }

    println!(
        "Bloom Filter Initialized with {} targets",
        valid_targets.len()
    );

    let target_set: HashSet<String> = valid_targets.iter().cloned().collect();
    println!("Target Set Created");
    println!("Bit array size: {} bits", bloom.number_of_bits());
    println!("Hash function size: {}", bloom.number_of_hash_functions());

    println!("{}", "=".repeat(70));

    println!("Staring the key search...");
    let mut checked_count = 0u64;
    let mut bloom_hits = 0u64;
    let mut false_positives = 0u64;
    let check_interval = 10000;

    let start_time = std::time::Instant::now();

    loop {
        let private_key = generate_random_btc_private_key();
        let generated_addresses = generate_addresses(&private_key);

        for (address, addr_type, wif) in generated_addresses {
            if bloom.check(&address) {
                bloom_hits += 1;

                if target_set.contains(&address) {
                    let elapsed = start_time.elapsed();
                    println!("{}", "=".repeat(70));
                    println!("\n🎉🎉🎉 FOUND !!! 🎉🎉🎉");
                    println!("Address: {}", address);
                    println!("Type: {}", addr_type);
                    println!("Private Key (WIF): {}", wif);
                    println!(
                        "Hex:           {}",
                        hex::encode(private_key.inner.secret_bytes())
                    );
                    println!("{}", "=".repeat(70));

                    println!("Checked Addresses: {}", checked_count);
                    println!("Bloom Hits: {}", bloom_hits);
                    println!("False Positives: {}", false_positives);
                    println!("Elapsed Time: {:.2?}", elapsed);
                    println!(
                        "Average Speed: {:.2} keys/second",
                        checked_count as f64 / elapsed.as_secs_f64()
                    );

                    // Save to found.txt
                    let result = format!(
                        "Found!\n\
                        ============================================================\n\
                        Address:         {}\n\
                        Type:           {}\n\
                        Private Key:   {}\n\
                        Hex:           {}\n\
                        ============================================================\n\
                        Statistics:\n\
                        Checked : {} adres\n\
                        Bloom hits:     {}\n\
                        False positive: {}\n\
                        Elapsed time:           {:.2?}\n\
                        Speed:            {:.0} address/second\n",
                        address,
                        addr_type,
                        wif,
                        hex::encode(private_key.inner.secret_bytes()),
                        checked_count,
                        bloom_hits,
                        false_positives,
                        elapsed,
                        checked_count as f64 / elapsed.as_secs_f64()
                    );

                    fs::write("found.txt", result).expect("Dosya yazılamadı");
                    println!("\n💾 Sonuç kaydedildi: found.txt");

                    return;
                } else {
                    //False positive
                    false_positives += 1;
                }
            }
        }

        checked_count += 3; // 3 addresses generated per key

        if checked_count % check_interval == 0 {
            let elapsed = start_time.elapsed();
            let rate = checked_count as f64 / elapsed.as_secs_f64();
            println!(
                "📊 {} address checked | {:.0} address/second | Bloom hits: {} | False+: {} | Elapsed time: {:.1?}",
                checked_count, rate, bloom_hits, false_positives, elapsed
            );
        }
    }
}

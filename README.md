# xyz-pro

src/
├── main.rs          # Ana uygulama (225 satır)
├── gpu.rs           # Metal GPU yönetimi (251 satır)
├── targets.rs       # Hedef veritabanı (120 satır)
├── types.rs         # Hash160, AddressType (55 satır)
├── crypto.rs        # hash160, key validation (41 satır)
├── address.rs       # WIF, P2SH script (27 satır)
├── error.rs         # Hata tipleri (19 satır)
├── sha256_33.metal  # Compressed pubkey SHA256 (157 satır)
├── sha256_65.metal  # Uncompressed pubkey SHA256 (105 satır)
└── ripemd160.metal  # RIPEMD160 (173 satır)

Toplam: 1240 satır



Özellikler:
P2PKH (1...) - Legacy
P2SH (3...) - Nested SegWit
P2WPKH (bc1q...) - Native SegWit
Compressed + Uncompressed pubkey desteği
GPU'da 4 paralel hash pipeline (SHA256×2 + RIPEMD160×2)
Triple-buffered async GPU operasyonları
Bloom filter ile hızlı eşleşme kontrolü


[i] GPU: Apple M1
[i] GPU Memory: 39.71 MB
[⚡] 98,304 keys | 26.6K/s
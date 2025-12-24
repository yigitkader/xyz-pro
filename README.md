# DEFAULT: Scan Mode (Bridge kullanır)
cargo run
# veya
cargo run -- --targets targets.json --start 0x1

# Generator Mode (Diske yaz)
cargo run -- --gen --gpu --format raw

┌─────────────────────────────────────────────────────────────────┐
│                     DEFAULT: SCAN MODE                          │
│                                                                 │
│   cargo run  →  IntegratedPipeline (Bridge)                     │
│                        │                                        │
│         ┌──────────────┼──────────────┐                         │
│         ▼              ▼              ▼                         │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐                   │
│   │Generator │   │ Matcher  │   │  Output  │                   │
│   │  (GPU)   │──▶│(HashSet) │──▶│  (File)  │                   │
│   └──────────┘   └──────────┘   └──────────┘                   │
│                                                                 │
│   Zero Disk I/O  •  GLV 2x  •  O(1) Lookup                     │
└─────────────────────────────────────────────────────────────────┘


Desteklenen Tipler:

Tip	Prefix	Encoding
P2PKH	1...	Base58Check
P2SH	3...	Base58Check
P2WPKH	bc1q...	Bech32 (witness v0)

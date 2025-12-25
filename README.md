# DEFAULT: Scan Mode (Bridge kullanır)
cargo run
# veya
cargo run -- --targets targets.json --start 0x1

# Generator Mode (Diske yaz)
cargo run -- --gen --gpu --format raw

Mevcut Pipeline:
┌─────────────────────────────────────────────────────────────┐
│  GPU (Metal)                                                 │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐        │
│  │ Private Key │ → │ EC Point    │ → │ SHA256 +    │        │
│  │ Generation  │   │ Multiply    │   │ RIPEMD160   │        │
│  │ (GLV 2x)    │   │ (wNAF)      │   │             │        │
│  └─────────────┘   └─────────────┘   └─────────────┘        │
│                           │                                  │
│                           ↓                                  │
│                    [72-byte output]                          │
└───────────────────────────┼─────────────────────────────────┘
                            ↓
┌───────────────────────────┼─────────────────────────────────┐
│  CPU (Rayon Parallel)     ↓                                  │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐        │
│  │ XOR Filter  │ → │ HashSet     │ → │ Match       │        │
│  │ Pre-check   │   │ Lookup      │   │ Output      │        │
│  └─────────────┘   └─────────────┘   └─────────────┘        │
└─────────────────────────────────────────────────────────────┘

Performans: ~509M keys/min (memory constrained)

Desteklenen Tipler:

Tip	Prefix	Encoding
P2PKH	1...	Base58Check
P2SH	3...	Base58Check
P2WPKH	bc1q...	Bech32 (witness v0)

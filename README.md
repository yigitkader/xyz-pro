┌─────────────────────────────────────────────────────────────────────────┐
│                              BRIDGE                                      │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────────┐ │
│  │  KeyGenerator  │  │    Matcher     │  │      MatchOutput           │ │
│  │    (trait)     │  │    (trait)     │  │       (trait)              │ │
│  └───────┬────────┘  └───────┬────────┘  └────────────┬───────────────┘ │
│          │                   │                        │                  │
│  ┌───────┴────────────────────┴────────────────────────┴───────────────┐ │
│  │                    IntegratedPipeline                                │ │
│  │  - Orchestrates generator, matcher, output                           │ │
│  │  - Zero-copy batch transfer                                          │ │
│  │  - Parallel matching with Rayon                                      │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
▲                         ▲                         ▲
│                         │                         │
┌─────────┴──────────┐   ┌─────────┴──────────┐   ┌─────────┴──────────┐
│     GENERATOR      │   │      READER        │   │      OUTPUT        │
│                    │   │                    │   │                    │
│ GpuGeneratorAdapter│   │  ParallelMatcher   │   │  CombinedOutput    │
│  ↓ impl trait      │   │  ↓ impl trait      │   │  ↓ impl trait      │
│                    │   │                    │   │                    │
│ GpuKeyGenerator    │   │  TargetSet         │   │  Console + File    │
│ - Metal shader     │   │  - HashSet O(1)    │   │                    │
│ - GLV 2x           │   │  - All addr types  │   │                    │
└────────────────────┘   └────────────────────┘   └────────────────────┘

src/
├── bridge/
│   ├── mod.rs       # Module exports
│   ├── types.rs     # RawKeyData, KeyBatch, Match
│   ├── traits.rs    # KeyGenerator, Matcher, MatchOutput traits
│   └── pipeline.rs  # IntegratedPipeline orchestrator
│
├── generator/
│   ├── adapter.rs   # GpuGeneratorAdapter (implements KeyGenerator)
│   ├── gpu.rs       # GpuKeyGenerator (Metal, GLV)
│   └── ...
│
├── reader/
│   ├── adapter.rs   # TargetMatcher, ParallelMatcher (implements Matcher)
│   ├── targets.rs   # TargetSet (HashSet)
│   └── ...
│
└── bin/
└── btc_keygen.rs  # Uses bridge to connect modules
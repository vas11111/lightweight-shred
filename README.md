# lightweight-shred

Lightweight Solana shred parsing and FEC recovery — without the baggage.

Vendored from `solana-ledger` to avoid pulling in rocksdb, protobuf-src, and openssl-sys (which add ~2000 transitive deps and 400s+ of C++ build time). This crate keeps only what you need to receive, parse, and reconstruct shreds via Reed-Solomon erasure coding.

## What's included

- `Shred` — parse data and coding shreds (legacy + merkle)
- `ReedSolomonCache` — cached Reed-Solomon encoder/decoder
- `recover()` — FEC recovery of missing data shreds from coding shreds

## What's not included

- Shred creation / shredding
- Packet handling
- Blockstore / RocksDB
- Protobuf / gRPC
- OpenSSL

## Usage

```toml
[dependencies]
lightweight-shred = { git = "https://github.com/vas11111/lightweight-shred" }
```

```rust
use lightweight_shred::{Shred, ReedSolomonCache, recover};
```

# pg-sni-muxer

[![Test](https://github.com/matisiekpl/pg-sni-muxer/actions/workflows/test.yml/badge.svg)](https://github.com/matisiekpl/pg-sni-muxer/actions/workflows/test.yml)
[![Crates.io](https://img.shields.io/crates/v/pg-sni-muxer)](https://crates.io/crates/pg-sni-muxer)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A lightweight PostgreSQL connection multiplexer that routes incoming connections to backend servers based on the **TLS
SNI** (Server Name Indication) extracted from the client's `ClientHello`.

## Usage

Add to your `Cargo.toml`:

```bash
cargo add pg-sni-muxer
```

## Example

```rust
use std::net::SocketAddr;
use std::sync::Arc;

use pg_sni_muxer::PgSniMuxer;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let muxer = Arc::new(PgSniMuxer::new());

    // Register backend mappings
    let db1: SocketAddr = "127.0.0.1:5432".parse()?;
    let db2: SocketAddr = "127.0.0.1:5433".parse()?;

    muxer.set_mapping("db1.example.com", db1).await;
    muxer.set_mapping("db2.example.com", db2).await;

    // Start listening
    let listener = TcpListener::bind("0.0.0.0:6432").await?;
    muxer.listen(listener).await?;

    Ok(())
}
```

Run the included example:

```bash
cargo run --example simple
```
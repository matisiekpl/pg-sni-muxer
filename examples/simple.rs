use std::net::SocketAddr;
use std::sync::Arc;

use pg_sni_muxer::PgSniMuxer;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing so debug logs are visible.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let muxer = Arc::new(PgSniMuxer::new());

    // Register some backend mappings.
    let db1_addr: SocketAddr = "127.0.0.1:5432".parse()?;
    let db2_addr: SocketAddr = "127.0.0.1:5433".parse()?;

    muxer.set_mapping("db1.example.com", db1_addr).await;
    muxer.set_mapping("db2.example.com", db2_addr).await;

    // Print current mappings.
    println!("Current mappings: {:?}", muxer.list_mappings().await);

    // Bind a TCP listener and hand it to the muxer.
    let listener = TcpListener::bind("0.0.0.0:6432").await?;
    println!("Listening on {}", listener.local_addr()?);

    muxer.listen(listener).await?;

    Ok(())
}

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::{RwLock, watch};

use crate::tls::{
    TLS_ALERT_UNRECOGNIZED_NAME, extract_sni_from_tls_records, read_tls_client_hello,
};

/// PostgreSQL SSLRequest code.
const PG_SSL_REQUEST_CODE: u32 = 80877103;

/// A mapping from SNI hostname to a backend socket address.
type MappingTable = HashMap<String, SocketAddr>;

/// PostgreSQL TLS/SNI connection multiplexer.
///
/// Routes incoming connections to backend PostgreSQL servers based on the
/// SNI (Server Name Indication) extracted from the TLS ClientHello message.
///
/// The multiplexer understands the PostgreSQL startup protocol:
/// 1. Client sends an 8-byte SSLRequest.
/// 2. Multiplexer responds with `S` to indicate SSL support.
/// 3. Client sends TLS ClientHello (possibly spanning multiple TLS records).
/// 4. Multiplexer extracts the SNI, resolves the backend, and proxies the
///    full connection (including forwarding the SSLRequest to the backend).
pub struct PgSniMuxer {
    mappings: Arc<RwLock<MappingTable>>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl PgSniMuxer {
    /// Creates a new multiplexer.
    pub fn new() -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            mappings: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Sets the mapping from `hostname` to `backend` address.
    ///
    /// If a mapping for `hostname` already exists it is replaced.
    pub async fn set_mapping(&self, hostname: impl Into<String>, backend: SocketAddr) {
        let hostname = hostname.into();
        let mut mappings = self.mappings.write().await;
        let old = mappings.insert(hostname.clone(), backend);
        tracing::debug!(hostname = %hostname, backend = %backend, old = ?old, "set mapping");
    }

    /// Removes the mapping for `hostname`.
    pub async fn remove_mapping(&self, hostname: &str) {
        let mut mappings = self.mappings.write().await;
        let removed = mappings.remove(hostname);
        if removed.is_some() {
            tracing::debug!(hostname = %hostname, "removed mapping");
        } else {
            tracing::debug!(hostname = %hostname, "no mapping to remove");
        }
    }

    /// Atomically swaps the backend addresses of two hostnames.
    ///
    /// Both hostnames must have existing mappings. Returns `true` if the swap
    /// was performed, `false` if either hostname has no mapping.
    pub async fn swap_mapping(&self, hostname_a: &str, hostname_b: &str) -> bool {
        let mut mappings = self.mappings.write().await;
        let addr_a = mappings.get(hostname_a).copied();
        let addr_b = mappings.get(hostname_b).copied();
        match (addr_a, addr_b) {
            (Some(a), Some(b)) => {
                mappings.insert(hostname_a.to_owned(), b);
                mappings.insert(hostname_b.to_owned(), a);
                tracing::debug!(
                    hostname_a = %hostname_a,
                    hostname_b = %hostname_b,
                    "swapped mappings"
                );
                true
            }
            _ => {
                tracing::debug!(
                    hostname_a = %hostname_a,
                    hostname_b = %hostname_b,
                    "swap failed: one or both hostnames have no mapping"
                );
                false
            }
        }
    }

    /// Signals all tasks spawned by [`listen`](Self::listen) to shut down gracefully.
    pub fn break_connection(&self) {
        tracing::debug!("breaking all connections (sending shutdown signal)");
        let _ = self.shutdown_tx.send(true);
    }

    /// Returns a snapshot of the current mapping table.
    pub async fn list_mappings(&self) -> HashMap<String, SocketAddr> {
        self.mappings.read().await.clone()
    }

    /// Starts accepting connections from the given `listener`.
    ///
    /// This is intentionally generic — callers can bind a [`TcpListener`]
    /// themselves (choosing port, address, or even a pre-existing fd) and hand
    /// it in.
    pub async fn listen(self: Arc<Self>, listener: TcpListener) -> io::Result<()> {
        tracing::debug!(
            addr = %listener.local_addr()?,
            "multiplexer listening"
        );

        let mut shutdown = self.shutdown_rx.clone();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, peer) = result?;
                    tracing::debug!(peer = %peer, "accepted connection");
                    let muxer = Arc::clone(&self);
                    let mut task_shutdown = self.shutdown_rx.clone();
                    tokio::spawn(async move {
                        tokio::select! {
                            res = muxer.handle_connection(stream, peer) => {
                                if let Err(e) = res {
                                    tracing::debug!(peer = %peer, error = %e, "connection error");
                                }
                            }
                            _ = task_shutdown.changed() => {
                                tracing::debug!(peer = %peer, "connection cancelled by shutdown");
                            }
                        }
                    });
                }
                _ = shutdown.changed() => {
                    tracing::debug!("listener shutting down");
                    return Ok(());
                }
            }
        }
    }

    /// Starts listening on the given address (convenience wrapper around [`listen`](Self::listen)).
    pub async fn listen_on(self: Arc<Self>, addr: impl ToSocketAddrs) -> io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        self.listen(listener).await
    }

    /// Handles a single client connection through the full PG SSL + TLS SNI flow.
    async fn handle_connection(&self, mut client: TcpStream, peer: SocketAddr) -> io::Result<()> {
        // Step 1: Read the 8-byte PostgreSQL startup packet.
        let mut first8 = [0u8; 8];
        client.read_exact(&mut first8).await?;

        let packet_len = u32::from_be_bytes([first8[0], first8[1], first8[2], first8[3]]) as usize;
        let code = u32::from_be_bytes([first8[4], first8[5], first8[6], first8[7]]);

        if packet_len != 8 || code != PG_SSL_REQUEST_CODE {
            // Not an SSLRequest — we only handle TLS-based routing.
            tracing::debug!(peer = %peer, code = code, "not an SSLRequest, closing");
            return Ok(());
        }

        tracing::debug!(peer = %peer, "received SSLRequest");

        // Step 2: Tell the client we accept SSL.
        client.write_all(b"S").await?;
        tracing::debug!(peer = %peer, "sent SSL accept ('S')");

        // Step 3: Read TLS ClientHello (may span multiple TLS records).
        let client_hello_bytes = read_tls_client_hello(&mut client).await?;

        let sni = extract_sni_from_tls_records(&client_hello_bytes);

        let sni = match sni {
            Some(s) => s,
            None => {
                tracing::debug!(peer = %peer, "no SNI found in ClientHello");
                let _ = client.write_all(&TLS_ALERT_UNRECOGNIZED_NAME).await;
                return Ok(());
            }
        };

        // Step 4: Look up the backend.
        let backend_addr = {
            let mappings = self.mappings.read().await;
            mappings.get(&sni).copied()
        };

        let backend_addr = match backend_addr {
            Some(addr) => addr,
            None => {
                tracing::debug!(peer = %peer, sni = %sni, "no mapping for SNI");
                let _ = client.write_all(&TLS_ALERT_UNRECOGNIZED_NAME).await;
                return Ok(());
            }
        };

        tracing::debug!(peer = %peer, sni = %sni, backend = %backend_addr, "routing connection");

        // Step 5: Connect to backend, replay the SSLRequest.
        let mut backend = TcpStream::connect(backend_addr).await?;
        backend.write_all(&first8).await?;

        // Read backend's SSL response byte ('S' or 'N').
        let mut ssl_resp = [0u8; 1];
        backend.read_exact(&mut ssl_resp).await?;

        if ssl_resp[0] != b'S' {
            tracing::debug!(
                peer = %peer,
                sni = %sni,
                backend = %backend_addr,
                response = ?ssl_resp[0] as char,
                "backend rejected SSL"
            );
            let _ = client.write_all(&TLS_ALERT_UNRECOGNIZED_NAME).await;
            return Ok(());
        }

        tracing::debug!(peer = %peer, sni = %sni, "backend accepted SSL, forwarding ClientHello");

        // Forward the captured ClientHello bytes to the backend.
        backend.write_all(&client_hello_bytes).await?;

        // Step 6: Bidirectional copy for the rest of the connection.
        let (_, _) = copy_bidirectional(&mut client, &mut backend).await?;

        tracing::debug!(peer = %peer, sni = %sni, "connection closed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::build_client_hello;

    /// Builds the 8-byte PostgreSQL SSLRequest packet.
    fn build_ssl_request() -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&8u32.to_be_bytes());
        buf[4..].copy_from_slice(&PG_SSL_REQUEST_CODE.to_be_bytes());
        buf
    }

    #[tokio::test]
    async fn set_and_list_mappings() {
        let muxer = PgSniMuxer::new();
        let addr1: SocketAddr = "127.0.0.1:5432".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:5433".parse().unwrap();

        muxer.set_mapping("db1.example.com", addr1).await;
        // Replacing silently overwrites.
        muxer.set_mapping("db1.example.com", addr2).await;

        let list = muxer.list_mappings().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list["db1.example.com"], addr2);
    }

    #[tokio::test]
    async fn remove_mapping_works() {
        let muxer = PgSniMuxer::new();
        let addr: SocketAddr = "127.0.0.1:5432".parse().unwrap();

        muxer.set_mapping("db1.example.com", addr).await;
        muxer.remove_mapping("db1.example.com").await;
        // Second remove is a no-op.
        muxer.remove_mapping("db1.example.com").await;
        assert!(muxer.list_mappings().await.is_empty());
    }

    #[tokio::test]
    async fn swap_mapping_works() {
        let muxer = PgSniMuxer::new();
        let addr1: SocketAddr = "127.0.0.1:5432".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:5433".parse().unwrap();

        muxer.set_mapping("db1.example.com", addr1).await;
        muxer.set_mapping("db2.example.com", addr2).await;

        assert!(
            muxer
                .swap_mapping("db1.example.com", "db2.example.com")
                .await
        );

        let list = muxer.list_mappings().await;
        assert_eq!(list["db1.example.com"], addr2);
        assert_eq!(list["db2.example.com"], addr1);

        // Swap fails when a hostname has no mapping.
        assert!(
            !muxer
                .swap_mapping("db1.example.com", "missing.example.com")
                .await
        );
    }

    #[tokio::test]
    async fn break_connection_signals_shutdown() {
        let muxer = Arc::new(PgSniMuxer::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let muxer_clone = Arc::clone(&muxer);
        let handle = tokio::spawn(async move { muxer_clone.listen(listener).await });

        // Give listener a moment to start, then shut it down.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        muxer.break_connection();

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        assert!(result.is_ok(), "listener should have stopped");
    }

    #[tokio::test]
    async fn no_route_message_sent_when_no_mapping() {
        let muxer = Arc::new(PgSniMuxer::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let muxer_clone = Arc::clone(&muxer);
        tokio::spawn(async move {
            let _ = muxer_clone.listen(listener).await;
        });

        // Connect, send SSLRequest, then a ClientHello with an unmapped SNI.
        let mut client = TcpStream::connect(addr).await.unwrap();

        // Send PG SSLRequest.
        client.write_all(&build_ssl_request()).await.unwrap();

        // Read 'S' response.
        let mut ssl_resp = [0u8; 1];
        client.read_exact(&mut ssl_resp).await.unwrap();
        assert_eq!(ssl_resp[0], b'S');

        // Send TLS ClientHello with unmapped SNI.
        let hello = build_client_hello("unknown.example.com");
        client.write_all(&hello).await.unwrap();

        let mut response = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.read_to_end(&mut response),
        )
        .await;

        assert_eq!(response, TLS_ALERT_UNRECOGNIZED_NAME);

        muxer.break_connection();
    }

    #[tokio::test]
    async fn non_ssl_request_gets_closed() {
        let muxer = Arc::new(PgSniMuxer::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let muxer_clone = Arc::clone(&muxer);
        tokio::spawn(async move {
            let _ = muxer_clone.listen(listener).await;
        });

        // Connect and send a non-SSLRequest startup (e.g. protocol version 3.0).
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut startup = [0u8; 8];
        startup[..4].copy_from_slice(&8u32.to_be_bytes());
        startup[4..].copy_from_slice(&196608u32.to_be_bytes()); // version 3.0
        client.write_all(&startup).await.unwrap();

        let mut response = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.read_to_end(&mut response),
        )
        .await;

        // Connection is simply closed without any message.
        assert!(response.is_empty());

        muxer.break_connection();
    }
}

impl Default for PgSniMuxer {
    fn default() -> Self {
        Self::new()
    }
}

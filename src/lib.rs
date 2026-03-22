use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::{watch, RwLock};

/// PostgreSQL SSLRequest code.
const PG_SSL_REQUEST_CODE: u32 = 80877103;

/// Maximum amount of TLS data to capture before giving up.
const MAX_TLS_CAPTURE: usize = 1024 * 1024;

/// TLS fatal alert: unrecognized_name (112).
/// ContentType=21 (alert), Version=0x0303 (TLS 1.2), Length=2, Level=2 (fatal), Description=112.
const TLS_ALERT_UNRECOGNIZED_NAME: [u8; 7] = [21, 3, 3, 0, 2, 2, 112];

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
    pub async fn set_mapping(
        &self,
        hostname: impl Into<String>,
        backend: SocketAddr,
    ) {
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

    /// Signals all tasks spawned by [`listen`] to shut down gracefully.
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

    /// Starts listening on the given address (convenience wrapper around [`listen`]).
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

/// Reads TLS records from the client until a complete ClientHello is assembled.
async fn read_tls_client_hello(client: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    let mut handshake_data = Vec::new();

    loop {
        if raw.len() > MAX_TLS_CAPTURE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS ClientHello too large",
            ));
        }

        // Read TLS record header (5 bytes).
        let mut header = [0u8; 5];
        client.read_exact(&mut header).await?;
        raw.extend_from_slice(&header);

        let content_type = header[0];
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;

        // Read TLS record body.
        let mut body = vec![0u8; record_len];
        client.read_exact(&mut body).await?;
        raw.extend_from_slice(&body);

        // Only process Handshake records (content_type 22 / 0x16).
        if content_type == 0x16 {
            handshake_data.extend_from_slice(&body);

            if has_complete_client_hello(&handshake_data) {
                break;
            }
        } else {
            // Non-handshake record encountered; stop sniffing.
            break;
        }
    }

    Ok(raw)
}

/// Returns `true` if the accumulated handshake data contains a complete ClientHello.
fn has_complete_client_hello(handshake: &[u8]) -> bool {
    if handshake.len() < 4 {
        return false;
    }
    // HandshakeType 1 = ClientHello
    if handshake[0] != 1 {
        return false;
    }
    let len = ((handshake[1] as usize) << 16)
        | ((handshake[2] as usize) << 8)
        | (handshake[3] as usize);
    handshake.len() >= 4 + len
}

/// Extracts the SNI hostname from raw TLS records (which may span multiple records).
fn extract_sni_from_tls_records(data: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    let mut handshake = Vec::new();

    while pos + 5 <= data.len() {
        let content_type = data[pos];
        let record_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
        let record_start = pos + 5;
        let record_end = record_start + record_len;

        if record_end > data.len() {
            return None;
        }

        if content_type == 0x16 {
            handshake.extend_from_slice(&data[record_start..record_end]);
        }

        pos = record_end;
    }

    extract_sni_from_client_hello(&handshake)
}

/// Extracts the SNI from a reassembled ClientHello handshake message.
fn extract_sni_from_client_hello(handshake: &[u8]) -> Option<String> {
    if handshake.len() < 4 {
        return None;
    }
    if handshake[0] != 1 {
        return None;
    }

    let hello_len = ((handshake[1] as usize) << 16)
        | ((handshake[2] as usize) << 8)
        | (handshake[3] as usize);

    if handshake.len() < 4 + hello_len {
        return None;
    }

    let body = &handshake[4..4 + hello_len];
    let mut p = 0usize;

    // legacy_version (2) + random (32)
    if body.len() < p + 34 {
        return None;
    }
    p += 34;

    // session_id
    if body.len() < p + 1 {
        return None;
    }
    let session_id_len = body[p] as usize;
    p += 1 + session_id_len;

    // cipher_suites
    if body.len() < p + 2 {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cipher_suites_len;

    // compression_methods
    if body.len() < p + 1 {
        return None;
    }
    let compression_methods_len = body[p] as usize;
    p += 1 + compression_methods_len;

    // extensions
    if body.len() < p + 2 {
        return None;
    }
    let extensions_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;

    let ext_end = p + extensions_len;
    if ext_end > body.len() {
        return None;
    }

    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[p], body[p + 1]]);
        let ext_len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;

        if p + ext_len > ext_end {
            return None;
        }

        // SNI extension (type 0)
        if ext_type == 0 {
            return parse_sni_extension(&body[p..p + ext_len]);
        }

        p += ext_len;
    }

    None
}

/// Parses the SNI extension value to extract the hostname.
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }

    let mut p = 2usize;
    let end = 2 + list_len;

    while p + 3 <= end {
        let name_type = data[p];
        let name_len = u16::from_be_bytes([data[p + 1], data[p + 2]]) as usize;
        p += 3;

        if p + name_len > end {
            return None;
        }

        if name_type == 0 {
            let name_bytes = &data[p..p + name_len];
            return std::str::from_utf8(name_bytes).ok().map(|s| s.to_string());
        }

        p += name_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal TLS ClientHello record with the given SNI hostname.
    fn build_client_hello(hostname: &str) -> Vec<u8> {
        // SNI extension value
        let name_bytes = hostname.as_bytes();
        let sni_entry_len = 3 + name_bytes.len();
        let sni_list_len = sni_entry_len;

        let mut sni_ext_value = Vec::new();
        sni_ext_value.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        sni_ext_value.push(0x00); // host_name type
        sni_ext_value.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_ext_value.extend_from_slice(name_bytes);

        // Extension header: type(2) + length(2) + value
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // SNI extension type
        extensions.extend_from_slice(&(sni_ext_value.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext_value);

        // ClientHello body
        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        ch_body.extend_from_slice(&[0u8; 32]); // random
        ch_body.push(0); // session_id length = 0
        ch_body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
        ch_body.extend_from_slice(&[0x00, 0xFF]); // one dummy cipher suite
        ch_body.push(1); // compression methods length
        ch_body.push(0); // null compression
        ch_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&extensions);

        // Handshake header: type(1) + length(3)
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let hs_len = ch_body.len();
        handshake.push((hs_len >> 16) as u8);
        handshake.push((hs_len >> 8) as u8);
        handshake.push(hs_len as u8);
        handshake.extend_from_slice(&ch_body);

        // TLS record header: type(1) + version(2) + length(2)
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    /// Builds the 8-byte PostgreSQL SSLRequest packet.
    fn build_ssl_request() -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&8u32.to_be_bytes());
        buf[4..].copy_from_slice(&PG_SSL_REQUEST_CODE.to_be_bytes());
        buf
    }

    #[test]
    fn extract_sni_from_single_record() {
        let data = build_client_hello("db.example.com");
        let result = extract_sni_from_tls_records(&data);
        assert_eq!(result, Some("db.example.com".to_string()));
    }

    #[test]
    fn extract_sni_returns_none_for_empty() {
        assert_eq!(extract_sni_from_tls_records(&[]), None);
    }

    #[test]
    fn extract_sni_returns_none_for_non_handshake() {
        let mut data = build_client_hello("x.com");
        data[0] = 0x17; // change to application data
        assert_eq!(extract_sni_from_tls_records(&data), None);
    }

    #[test]
    fn extract_sni_returns_none_for_non_client_hello() {
        let mut data = build_client_hello("x.com");
        data[5] = 0x02; // change handshake type to ServerHello
        assert_eq!(extract_sni_from_tls_records(&data), None);
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

        assert!(muxer.swap_mapping("db1.example.com", "db2.example.com").await);

        let list = muxer.list_mappings().await;
        assert_eq!(list["db1.example.com"], addr2);
        assert_eq!(list["db2.example.com"], addr1);

        // Swap fails when a hostname has no mapping.
        assert!(!muxer.swap_mapping("db1.example.com", "missing.example.com").await);
    }

    #[tokio::test]
    async fn break_connection_signals_shutdown() {
        let muxer = Arc::new(PgSniMuxer::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let muxer_clone = Arc::clone(&muxer);
        let handle = tokio::spawn(async move {
            muxer_clone.listen(listener).await
        });

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

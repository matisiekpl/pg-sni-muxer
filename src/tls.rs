use std::io;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Maximum amount of TLS data to capture before giving up.
const MAX_TLS_CAPTURE: usize = 1024 * 1024;

/// TLS fatal alert: unrecognized_name (112).
/// ContentType=21 (alert), Version=0x0303 (TLS 1.2), Length=2, Level=2 (fatal), Description=112.
pub(crate) const TLS_ALERT_UNRECOGNIZED_NAME: [u8; 7] = [21, 3, 3, 0, 2, 2, 112];

/// Reads TLS records from the client until a complete ClientHello is assembled.
pub(crate) async fn read_tls_client_hello(client: &mut TcpStream) -> io::Result<Vec<u8>> {
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
pub(crate) fn extract_sni_from_tls_records(data: &[u8]) -> Option<String> {
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

/// Builds a minimal TLS ClientHello record with the given SNI hostname (test helper).
#[cfg(test)]
pub(crate) fn build_client_hello(hostname: &str) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}

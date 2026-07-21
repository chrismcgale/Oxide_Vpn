//! TLS-1.3 protocol mimicry: make the tunnel look like plain HTTPS on the wire.
//!
//! The obfuscation layer ([`oxide_obfs`]) already turns each datagram into a
//! high-entropy blob, but a sophisticated censor can still flag "high-entropy flow with
//! no recognizable protocol." This layer wraps the flow so a passive observer sees a
//! textbook TLS 1.3 session: a `ClientHello` with a real-looking SNI, a `ServerHello`,
//! and then a stream of `application_data` records — indistinguishable from a browser
//! fetching a website. Blocking it means blocking HTTPS.
//!
//! This is *mimicry*, not real TLS: both endpoints are ours and don't validate the
//! handshake — it only has to look right to a DPI box. The actual security is the
//! WireGuard AEAD (and the obfs layer) inside the records. It rides over TCP (real TLS
//! is TCP), which is the accepted trade-off for a censorship-circumvention fallback.
//!
//! This module is pure byte-assembly; the transport that speaks it over a socket lives
//! in `wg-core`.

use rand_core::{OsRng, RngCore};

/// TLS record content types.
pub const REC_HANDSHAKE: u8 = 0x16;
pub const REC_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const REC_APPLICATION_DATA: u8 = 0x17;

const TLS_RECORD_HEADER: usize = 5;
/// Max TLS record payload (2^14). Our datagrams are far smaller, but we split to be safe.
const MAX_RECORD: usize = 16384;

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

/// Prefix `body` with its length as a big-endian `u16`.
fn u16_len(body: &[u8]) -> Vec<u8> {
    let mut v = (body.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(body);
    v
}

/// Prefix `body` with its length as a single byte.
fn u8_len(body: &[u8]) -> Vec<u8> {
    let mut v = vec![body.len() as u8];
    v.extend_from_slice(body);
    v
}

/// Prefix `body` with its length as a 24-bit big-endian integer (TLS handshake length).
fn u24_len(body: &[u8]) -> Vec<u8> {
    let l = body.len() as u32;
    let mut v = vec![(l >> 16) as u8, (l >> 8) as u8, l as u8];
    v.extend_from_slice(body);
    v
}

/// Wrap `payload` in a TLS record with the given content type and legacy version.
fn record(content_type: u8, version: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(TLS_RECORD_HEADER + payload.len());
    v.push(content_type);
    v.extend_from_slice(&version);
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// A TLS extension: `[type: 2][len: 2][data]`.
fn extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
    let mut v = ext_type.to_be_bytes().to_vec();
    v.extend_from_slice(&u16_len(data));
    v
}

/// A realistic set of TLS 1.3 / 1.2 cipher suites.
const CIPHER_SUITES: &[u8] = &[
    0x13, 0x01, // TLS_AES_128_GCM_SHA256
    0x13, 0x02, // TLS_AES_256_GCM_SHA384
    0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
    0xc0, 0x2b, // ECDHE_ECDSA_AES_128_GCM
    0xc0, 0x2f, // ECDHE_RSA_AES_128_GCM
    0xc0, 0x2c, 0xc0, 0x30,
];

fn common_extensions(sni: Option<&str>) -> Vec<u8> {
    let mut exts = Vec::new();

    // server_name (SNI) — the domain a censor sees us "visiting".
    if let Some(host) = sni {
        let server_name = {
            let mut sn = vec![0x00]; // name_type = host_name
            sn.extend_from_slice(&u16_len(host.as_bytes()));
            sn
        };
        exts.extend_from_slice(&extension(0x0000, &u16_len(&server_name)));
    }
    // supported_groups: x25519, secp256r1
    exts.extend_from_slice(&extension(0x000a, &u16_len(&[0x00, 0x1d, 0x00, 0x17])));
    // signature_algorithms
    exts.extend_from_slice(&extension(0x000d, &u16_len(&[0x04, 0x03, 0x08, 0x04, 0x04, 0x01])));
    // supported_versions: TLS 1.3
    exts.extend_from_slice(&extension(0x002b, &u8_len(&[0x03, 0x04])));
    // key_share: x25519 with a random public value
    let key_share = {
        let mut ks = vec![0x00, 0x1d]; // group x25519
        ks.extend_from_slice(&u16_len(&rand_bytes(32)));
        ks
    };
    exts.extend_from_slice(&extension(0x0033, &u16_len(&key_share)));

    exts
}

/// Build a TLS 1.3 `ClientHello` record advertising `sni` (e.g. `"www.cloudflare.com"`).
pub fn client_hello(sni: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
    body.extend_from_slice(&rand_bytes(32)); // random
    body.extend_from_slice(&u8_len(&rand_bytes(32))); // legacy_session_id
    body.extend_from_slice(&u16_len(CIPHER_SUITES));
    body.extend_from_slice(&u8_len(&[0x00])); // compression_methods = null
    body.extend_from_slice(&u16_len(&common_extensions(Some(sni))));

    let handshake = {
        let mut h = vec![0x01]; // ClientHello
        h.extend_from_slice(&u24_len(&body));
        h
    };
    record(REC_HANDSHAKE, [0x03, 0x01], &handshake)
}

/// Build a plausible server response: `ServerHello`, a `ChangeCipherSpec`, and an
/// `application_data` record standing in for the (encrypted) certificate/finished.
pub fn server_hello() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&rand_bytes(32));
    body.extend_from_slice(&u8_len(&rand_bytes(32))); // echo a session id
    body.extend_from_slice(&[0x13, 0x01]); // chosen cipher suite
    body.push(0x00); // compression = null
    let mut exts = Vec::new();
    exts.extend_from_slice(&extension(0x002b, &[0x03, 0x04])); // supported_versions
    let key_share = {
        let mut ks = vec![0x00, 0x1d];
        ks.extend_from_slice(&u16_len(&rand_bytes(32)));
        ks
    };
    exts.extend_from_slice(&extension(0x0033, &key_share));
    body.extend_from_slice(&u16_len(&exts));

    let handshake = {
        let mut h = vec![0x02]; // ServerHello
        h.extend_from_slice(&u24_len(&body));
        h
    };

    let mut out = record(REC_HANDSHAKE, [0x03, 0x03], &handshake);
    out.extend_from_slice(&record(REC_CHANGE_CIPHER_SPEC, [0x03, 0x03], &[0x01]));
    // Encrypted-looking cert/finished as application_data.
    out.extend_from_slice(&record(REC_APPLICATION_DATA, [0x03, 0x03], &rand_bytes(512)));
    out
}

/// Wrap `payload` as one or more TLS `application_data` records.
pub fn frame_app_data(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + TLS_RECORD_HEADER);
    for chunk in payload.chunks(MAX_RECORD).chain(if payload.is_empty() {
        Some(&[][..])
    } else {
        None
    }) {
        out.extend_from_slice(&record(REC_APPLICATION_DATA, [0x03, 0x03], chunk));
    }
    out
}

/// Try to read one TLS record from the front of `buf`.
///
/// Returns `Some((bytes_consumed, content_type, payload))`, or `None` if the buffer
/// doesn't yet hold a complete record (the caller should read more from the socket).
pub fn read_record(buf: &[u8]) -> Option<(usize, u8, Vec<u8>)> {
    if buf.len() < TLS_RECORD_HEADER {
        return None;
    }
    let content_type = buf[0];
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let total = TLS_RECORD_HEADER + len;
    if buf.len() < total {
        return None;
    }
    Some((total, content_type, buf[TLS_RECORD_HEADER..total].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_looks_like_tls_and_carries_sni() {
        let ch = client_hello("www.cloudflare.com");
        // TLS handshake record header.
        assert_eq!(ch[0], REC_HANDSHAKE);
        assert_eq!(&ch[1..3], &[0x03, 0x01]);
        // The record payload begins with the ClientHello handshake type.
        assert_eq!(ch[5], 0x01);
        // The SNI hostname appears verbatim on the wire (as in a real ClientHello).
        assert!(ch.windows(18).any(|w| w == b"www.cloudflare.com"));
        // The declared record length matches the actual payload.
        let len = u16::from_be_bytes([ch[3], ch[4]]) as usize;
        assert_eq!(ch.len(), TLS_RECORD_HEADER + len);
    }

    #[test]
    fn client_hellos_are_unique() {
        assert_ne!(client_hello("example.com"), client_hello("example.com"));
    }

    #[test]
    fn server_hello_has_handshake_then_data() {
        let sh = server_hello();
        assert_eq!(sh[0], REC_HANDSHAKE);
        assert_eq!(sh[5], 0x02); // ServerHello
        // Somewhere later there is a change_cipher_spec and application_data record.
        let (n1, _, _) = read_record(&sh).unwrap();
        let (_n2, ct2, _) = read_record(&sh[n1..]).unwrap();
        assert_eq!(ct2, REC_CHANGE_CIPHER_SPEC);
    }

    #[test]
    fn app_data_frames_look_like_tls_and_roundtrip() {
        let payload = b"an obfuscated wireguard datagram";
        let framed = frame_app_data(payload);
        assert_eq!(framed[0], REC_APPLICATION_DATA);
        assert_eq!(&framed[1..3], &[0x03, 0x03]);
        let (consumed, ct, got) = read_record(&framed).unwrap();
        assert_eq!(consumed, framed.len());
        assert_eq!(ct, REC_APPLICATION_DATA);
        assert_eq!(got, payload);
    }

    #[test]
    fn read_record_handles_partial_and_multiple() {
        let mut stream = frame_app_data(b"first");
        stream.extend_from_slice(&frame_app_data(b"second"));

        // Truncated: not enough for a full record yet.
        assert!(read_record(&stream[..3]).is_none());

        // Two records back to back.
        let (n1, _, p1) = read_record(&stream).unwrap();
        assert_eq!(p1, b"first");
        let (_n2, _, p2) = read_record(&stream[n1..]).unwrap();
        assert_eq!(p2, b"second");
    }
}

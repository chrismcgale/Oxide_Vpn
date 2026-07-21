//! QUIC (HTTP/3) mimicry — make the tunnel look like a QUIC connection.
//!
//! Unlike the TLS mimicry, QUIC is UDP-based, so this needs no TCP and avoids the
//! TCP-over-TCP penalty — and QUIC/HTTP/3 is now a large fraction of web traffic, so the
//! flow blends in. A censor sees: a **long-header Initial** packet (QUIC v1, connection
//! IDs, an embedded TLS ClientHello with SNI, padded to 1200 bytes like a real Initial),
//! followed by **short-header** 1-RTT packets — i.e. a browser opening an HTTP/3 site.
//!
//! Same honesty as the TLS mimicry: this fools a *passive*, fingerprint-based censor
//! (which is what blocks WireGuard today), not a full QUIC protocol emulator. The real
//! security is the WireGuard AEAD (+ obfs) inside.

use rand_core::{OsRng, RngCore};

use crate::client_hello;

/// QUIC version 1 (RFC 9000).
pub const QUIC_V1: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
/// Connection-ID length we use in both directions (real QUIC allows 0–20).
const CID_LEN: usize = 8;
/// Real QUIC Initial packets are padded to at least 1200 bytes (anti-amplification).
const INITIAL_MIN: usize = 1200;
/// The SNI embedded in the mimicked ClientHello.
pub const SNI: &str = "www.cloudflare.com";

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

/// Build a QUIC-Initial-looking packet embedding a TLS ClientHello, then `payload`,
/// padded to 1200 bytes like a real Initial.
pub fn initial_packet(payload: &[u8]) -> Vec<u8> {
    let ch = client_hello(SNI);
    let mut p = Vec::with_capacity(INITIAL_MIN);
    p.push(0xc3); // long header (0x80) + fixed bit (0x40) + Initial type + pn len
    p.extend_from_slice(&QUIC_V1);
    p.push(CID_LEN as u8); // DCID length
    p.extend_from_slice(&rand_bytes(CID_LEN));
    p.push(CID_LEN as u8); // SCID length
    p.extend_from_slice(&rand_bytes(CID_LEN));
    p.push(0x00); // token length (varint 0)
                  // A CRYPTO-frame-looking block carrying the ClientHello.
    p.extend_from_slice(&(ch.len() as u16).to_be_bytes());
    p.extend_from_slice(&ch);
    // Our actual payload, length-prefixed.
    p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    p.extend_from_slice(payload);
    if p.len() < INITIAL_MIN {
        p.resize(INITIAL_MIN, 0); // padding, like a real Initial
    }
    p
}

/// Build a QUIC short-header (1-RTT) packet wrapping `payload`.
pub fn short_packet(payload: &[u8]) -> Vec<u8> {
    let mut flags = [0u8; 1];
    OsRng.fill_bytes(&mut flags);
    let mut p = Vec::with_capacity(1 + CID_LEN + payload.len());
    p.push(0x40 | (flags[0] & 0x03)); // short header: fixed bit set, high bit clear
    p.extend_from_slice(&rand_bytes(CID_LEN)); // destination connection id
    p.extend_from_slice(payload);
    p
}

/// Recover our payload from either a QUIC Initial or short-header packet, or `None` if
/// the datagram isn't one of ours (garbage / probe).
pub fn parse(dg: &[u8]) -> Option<Vec<u8>> {
    let first = *dg.first()?;
    if first & 0x80 != 0 {
        // Long header (Initial).
        if dg.len() < 5 || dg[1..5] != QUIC_V1 {
            return None;
        }
        let mut o = 5;
        let dl = *dg.get(o)? as usize;
        o += 1 + dl;
        let sl = *dg.get(o)? as usize;
        o += 1 + sl;
        let _token_len = *dg.get(o)?; // 1-byte varint 0
        o += 1;
        let cl = u16::from_be_bytes([*dg.get(o)?, *dg.get(o + 1)?]) as usize;
        o += 2 + cl;
        let pl = u16::from_be_bytes([*dg.get(o)?, *dg.get(o + 1)?]) as usize;
        o += 2;
        dg.get(o..o + pl).map(|s| s.to_vec())
    } else if first & 0x40 != 0 {
        // Short header: flags(1) + DCID(CID_LEN), then payload.
        dg.get(1 + CID_LEN..).map(|s| s.to_vec())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_looks_like_quic_and_carries_sni() {
        let pkt = initial_packet(b"an obfuscated wg handshake");
        assert_eq!(pkt[0] & 0x80, 0x80); // long header
        assert_eq!(&pkt[1..5], &QUIC_V1); // version 1
        assert_eq!(pkt.len(), INITIAL_MIN); // padded like a real Initial
        assert!(pkt.windows(SNI.len()).any(|w| w == SNI.as_bytes())); // embedded SNI
    }

    #[test]
    fn short_looks_like_quic_short_header() {
        let pkt = short_packet(b"data");
        assert_eq!(pkt[0] & 0x80, 0x00); // not long header
        assert_eq!(pkt[0] & 0x40, 0x40); // fixed bit set
    }

    #[test]
    fn both_forms_roundtrip() {
        let payload = b"the real (obfuscated) datagram";
        assert_eq!(parse(&initial_packet(payload)).unwrap(), payload);
        assert_eq!(parse(&short_packet(payload)).unwrap(), payload);
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x00, 0x01, 0x02]).is_none()); // neither long nor fixed-bit short
                                                       // Long header with the wrong version.
        assert!(parse(&[0xc0, 0xde, 0xad, 0xbe, 0xef]).is_none());
    }
}

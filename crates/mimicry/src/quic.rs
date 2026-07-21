//! QUIC (HTTP/3) mimicry — make the tunnel look like a QUIC connection.
//!
//! Unlike the TLS mimicry, QUIC is UDP-based, so this needs no TCP and avoids the
//! TCP-over-TCP penalty — and QUIC/HTTP/3 is now a large fraction of web traffic, so the
//! flow blends in. A censor sees: a **long-header Initial** packet (QUIC v1, connection
//! IDs, a token, an embedded TLS ClientHello with SNI, padded to 1200 bytes like a real
//! Initial), followed by **short-header** 1-RTT packets — i.e. a browser opening an
//! HTTP/3 site.
//!
//! **Active-probe resistance.** Passive mimicry (looking like QUIC) defeats a censor that
//! only *fingerprints* traffic. A stronger censor *actively probes*: it replays a captured
//! first packet, or sends its own QUIC-looking Initial, and watches whether the endpoint
//! answers differently from a random UDP port — if so, it has found a circumvention
//! server. To defeat that, the Initial is **authenticated**: its token carries a fresh
//! timestamp + random nonce and a keyed BLAKE2 MAC over the QUIC version, both connection
//! IDs, the timestamp and the nonce. The server ([`verify_initial`]) drops — in total
//! silence, exactly as it would a random datagram — any Initial whose MAC doesn't verify
//! (a **forged** probe, since the prober lacks the key), whose timestamp is outside the
//! window (a **stale** replay), or whose nonce it has already seen (a **replayed** probe,
//! via the caller's replay cache). So forged/stale/replayed probes get no response and the
//! port looks dead. The MAC and window are the transport authenticator; the real payload
//! security is still the WireGuard AEAD (+ obfs) inside.

use blake2::digest::{consts::U16, Mac};
use blake2::Blake2sMac;
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

/// Size of the anti-replay nonce embedded in (and returned from) an authenticated Initial.
pub const NONCE_LEN: usize = 16;
/// Keyed-MAC tag length carried in the token.
const TAG_LEN: usize = 16;
/// Token layout: timestamp(8 BE) ‖ nonce(16) ‖ tag(16). A ~40-byte opaque token is
/// indistinguishable from a real QUIC address-validation token.
const TS_LEN: usize = 8;
const TOKEN_LEN: usize = TS_LEN + NONCE_LEN + TAG_LEN;
/// How far an Initial's timestamp may be from the server's clock, in seconds. Bounds the
/// replay window (and thus the replay cache) while tolerating modest clock skew.
pub const AUTH_WINDOW_SECS: u64 = 120;

/// The anti-replay nonce recovered from a verified Initial. The caller tracks these in a
/// replay cache (bounded by [`AUTH_WINDOW_SECS`]) to reject replays.
pub type Nonce = [u8; NONCE_LEN];

type Mac16 = Blake2sMac<U16>;

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

/// Keyed BLAKE2 MAC binding the Initial to its version, both connection IDs, timestamp and
/// nonce, so a prober can neither forge one (no key) nor lift the token onto a different
/// packet (the CIDs are covered).
fn initial_tag(
    key: &[u8; 32],
    dcid: &[u8],
    scid: &[u8],
    ts: u64,
    nonce: &[u8; NONCE_LEN],
) -> [u8; TAG_LEN] {
    let mut mac = Mac16::new_from_slice(key).expect("blake2s accepts a 32-byte key");
    mac.update(&QUIC_V1);
    mac.update(dcid);
    mac.update(scid);
    mac.update(&ts.to_be_bytes());
    mac.update(nonce);
    mac.finalize().into_bytes().into()
}

/// Build an authenticated QUIC-Initial-looking packet embedding a TLS ClientHello, then
/// `payload`, padded to 1200 bytes like a real Initial. `now_secs` is the current Unix
/// time; it and a fresh random nonce are bound into the token's keyed MAC so the server
/// can reject forged, stale, or replayed Initials.
pub fn initial_packet(payload: &[u8], key: &[u8; 32], now_secs: u64) -> Vec<u8> {
    let ch = client_hello(SNI);
    let dcid = rand_bytes(CID_LEN);
    let scid = rand_bytes(CID_LEN);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let tag = initial_tag(key, &dcid, &scid, now_secs, &nonce);

    let mut p = Vec::with_capacity(INITIAL_MIN);
    p.push(0xc3); // long header (0x80) + fixed bit (0x40) + Initial type + pn len
    p.extend_from_slice(&QUIC_V1);
    p.push(CID_LEN as u8); // DCID length
    p.extend_from_slice(&dcid);
    p.push(CID_LEN as u8); // SCID length
    p.extend_from_slice(&scid);
    // Token (varint length; TOKEN_LEN < 64 so it's a single byte): ts ‖ nonce ‖ MAC.
    p.push(TOKEN_LEN as u8);
    p.extend_from_slice(&now_secs.to_be_bytes());
    p.extend_from_slice(&nonce);
    p.extend_from_slice(&tag);
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

/// Recover the payload from a QUIC **short-header** (1-RTT) packet, or `None` if it isn't
/// one. Short packets carry no authenticator — first contact must be an authenticated
/// [`initial_packet`] (see [`verify_initial`]); short packets only flow once a peer is
/// established, and their payloads are still gated by the WireGuard AEAD inside.
pub fn parse_short(dg: &[u8]) -> Option<Vec<u8>> {
    let first = *dg.first()?;
    if first & 0x80 == 0 && first & 0x40 != 0 {
        dg.get(1 + CID_LEN..).map(|s| s.to_vec())
    } else {
        None
    }
}

/// Verify an authenticated QUIC **Initial** and recover `(nonce, payload)`, or `None` if it
/// isn't a valid, fresh, well-keyed Initial. Returns `None` — so the caller stays silent,
/// like a dead port — when the datagram isn't a long-header Initial, is malformed, has a
/// timestamp outside `±AUTH_WINDOW_SECS` of `now_secs` (stale/premature replay), or fails
/// the keyed MAC (a forged probe without the key). Replay of an *in-window* Initial is the
/// caller's job: track the returned `nonce` and drop a repeat.
pub fn verify_initial(dg: &[u8], key: &[u8; 32], now_secs: u64) -> Option<(Nonce, Vec<u8>)> {
    let first = *dg.first()?;
    if first & 0x80 == 0 {
        return None; // not a long header
    }
    if dg.len() < 5 || dg[1..5] != QUIC_V1 {
        return None;
    }
    let mut o = 5;
    let dl = *dg.get(o)? as usize;
    o += 1;
    let dcid = dg.get(o..o + dl)?;
    o += dl;
    let sl = *dg.get(o)? as usize;
    o += 1;
    let scid = dg.get(o..o + sl)?;
    o += sl;
    let token_len = *dg.get(o)? as usize;
    o += 1;
    if token_len != TOKEN_LEN {
        return None; // not one of ours
    }
    let token = dg.get(o..o + TOKEN_LEN)?;
    o += TOKEN_LEN;

    let ts = u64::from_be_bytes(token[..TS_LEN].try_into().ok()?);
    if now_secs.abs_diff(ts) > AUTH_WINDOW_SECS {
        return None; // stale or premature: outside the freshness window
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&token[TS_LEN..TS_LEN + NONCE_LEN]);
    let tag = &token[TS_LEN + NONCE_LEN..];

    // Constant-time MAC check. A prober without the key can't produce a matching tag, so a
    // forged Initial fails here and gets no response.
    let mut mac = Mac16::new_from_slice(key).expect("blake2s accepts a 32-byte key");
    mac.update(&QUIC_V1);
    mac.update(dcid);
    mac.update(scid);
    mac.update(&ts.to_be_bytes());
    mac.update(&nonce);
    mac.verify_slice(tag).ok()?;

    // Same body layout as the builder: CRYPTO block (ClientHello) then the length-prefixed
    // payload.
    let cl = u16::from_be_bytes([*dg.get(o)?, *dg.get(o + 1)?]) as usize;
    o += 2 + cl;
    let pl = u16::from_be_bytes([*dg.get(o)?, *dg.get(o + 1)?]) as usize;
    o += 2;
    let payload = dg.get(o..o + pl)?.to_vec();
    Some((nonce, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];
    const NOW: u64 = 1_700_000_000;

    #[test]
    fn initial_looks_like_quic_and_carries_sni() {
        let pkt = initial_packet(b"an obfuscated wg handshake", &KEY, NOW);
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
    fn authenticated_initial_roundtrips() {
        let payload = b"the real (obfuscated) datagram";
        let pkt = initial_packet(payload, &KEY, NOW);
        let (_nonce, got) = verify_initial(&pkt, &KEY, NOW).expect("valid initial");
        assert_eq!(got, payload);
        // A short packet round-trips through parse_short.
        assert_eq!(parse_short(&short_packet(payload)).unwrap(), payload);
    }

    #[test]
    fn forged_probe_without_key_is_rejected() {
        // Prober holds the wrong key: the MAC can't match, so the server stays silent.
        let pkt = initial_packet(b"payload", &KEY, NOW);
        assert!(verify_initial(&pkt, &[9u8; 32], NOW).is_none());
    }

    #[test]
    fn tampered_initial_is_rejected() {
        let mut pkt = initial_packet(b"payload", &KEY, NOW);
        // Flip a byte inside one of the connection IDs — the MAC covers the CIDs.
        pkt[6] ^= 0x01;
        assert!(verify_initial(&pkt, &KEY, NOW).is_none());
    }

    #[test]
    fn stale_or_premature_initial_is_rejected() {
        let pkt = initial_packet(b"payload", &KEY, NOW);
        // Verified far in the future (a replay long after capture) → outside the window.
        assert!(verify_initial(&pkt, &KEY, NOW + AUTH_WINDOW_SECS + 1).is_none());
        // Or far in the past (clock skew beyond tolerance).
        assert!(verify_initial(&pkt, &KEY, NOW - AUTH_WINDOW_SECS - 1).is_none());
        // Within the window it still verifies.
        assert!(verify_initial(&pkt, &KEY, NOW + AUTH_WINDOW_SECS).is_some());
    }

    #[test]
    fn nonce_is_stable_for_replay_tracking() {
        let pkt = initial_packet(b"payload", &KEY, NOW);
        let (n1, _) = verify_initial(&pkt, &KEY, NOW).unwrap();
        let (n2, _) = verify_initial(&pkt, &KEY, NOW).unwrap();
        // Verifying the same datagram twice yields the same nonce — that's what lets a
        // replay cache recognise and drop the second copy.
        assert_eq!(n1, n2);
        // Two fresh Initials use different nonces.
        let other = initial_packet(b"payload", &KEY, NOW);
        let (n3, _) = verify_initial(&other, &KEY, NOW).unwrap();
        assert_ne!(n1, n3);
    }

    #[test]
    fn garbage_and_short_are_not_initials() {
        assert!(verify_initial(&[], &KEY, NOW).is_none());
        assert!(verify_initial(&[0x00, 0x01, 0x02], &KEY, NOW).is_none());
        // A long header with the wrong version.
        assert!(verify_initial(&[0xc0, 0xde, 0xad, 0xbe, 0xef], &KEY, NOW).is_none());
        // A short packet is not an Initial, and an Initial is not a short packet.
        assert!(verify_initial(&short_packet(b"x"), &KEY, NOW).is_none());
        assert!(parse_short(&initial_packet(b"x", &KEY, NOW)).is_none());
    }
}

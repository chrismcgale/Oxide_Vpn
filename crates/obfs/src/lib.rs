//! Traffic obfuscation for censorship resistance ("stealth mode").
//!
//! WireGuard is easy for DPI to fingerprint and block: its handshake messages have
//! fixed sizes (148 / 92 bytes) and recognizable type/MAC byte patterns. This layer
//! wraps each UDP datagram so it becomes an indistinguishable high-entropy blob with no
//! fixed header and a randomized size — defeating fingerprint-based blocking.
//!
//! Frame:
//! ```text
//! [ nonce: 12 ][ ChaCha20(key, nonce) XOR ( [len: 2 BE][payload][random padding] ) ]
//! ```
//! The nonce is random per packet, so identical payloads produce different ciphertext
//! and there is no static prefix to match. Random padding breaks the fixed handshake
//! sizes. This is *obfuscation*, not authentication — the real security is the
//! WireGuard AEAD underneath, which rejects any tampering; the obfuscation layer only
//! needs to defeat passive DPI. (Full protocol *mimicry*, e.g. WG-in-TLS/QUIC, is a
//! future tier.)
//!
//! Note: obfuscation adds `12 + 2 + padding` bytes of overhead, so it reduces the
//! effective path MTU. Lower the tunnel MTU (e.g. to 1380) when using stealth.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand_core::{OsRng, RngCore};

const NONCE_LEN: usize = 12;
const LEN_HDR: usize = 2;
/// Max random padding added per packet. Kept small so an obfuscated max-size WireGuard
/// datagram still fits under a 1500-byte path.
const MAX_PAD: usize = 32;

/// Wrap `plaintext` into an obfuscated datagram.
pub fn obfuscate(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let pad = (OsRng.next_u32() as usize) % (MAX_PAD + 1);

    // body = [len: 2][plaintext][pad zeros]; the zeros become keystream after XOR.
    let mut body = Vec::with_capacity(LEN_HDR + plaintext.len() + pad);
    body.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
    body.extend_from_slice(plaintext);
    body.resize(LEN_HDR + plaintext.len() + pad, 0);

    ChaCha20::new(key.into(), &nonce.into()).apply_keystream(&mut body);

    let mut out = Vec::with_capacity(NONCE_LEN + body.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    out
}

/// Recover the plaintext from an obfuscated datagram, or `None` if it doesn't decode
/// (garbage / probe traffic — the caller should silently drop it, giving DPI no signal).
pub fn deobfuscate(key: &[u8; 32], datagram: &[u8]) -> Option<Vec<u8>> {
    if datagram.len() < NONCE_LEN + LEN_HDR {
        return None;
    }
    let (nonce, body) = datagram.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;

    let mut buf = body.to_vec();
    ChaCha20::new(key.into(), &nonce.into()).apply_keystream(&mut buf);

    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if LEN_HDR + len > buf.len() {
        return None;
    }
    Some(buf[LEN_HDR..LEN_HDR + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [9u8; 32];
        let msg = b"a wireguard handshake or data packet";
        let framed = obfuscate(&key, msg);
        assert_eq!(deobfuscate(&key, &framed).unwrap(), msg);
    }

    #[test]
    fn ciphertext_is_randomized_and_unlike_plaintext() {
        let key = [1u8; 32];
        let msg = b"same payload";
        let a = obfuscate(&key, msg);
        let b = obfuscate(&key, msg);
        // Random nonce + padding -> different framing each time, no static prefix.
        assert_ne!(a, b);
        // The plaintext must not appear verbatim in the obfuscated output.
        assert!(!a.windows(msg.len()).any(|w| w == msg));
    }

    #[test]
    fn wrong_key_or_garbage_is_rejected() {
        let key = [2u8; 32];
        let framed = obfuscate(&key, b"secret");
        // Wrong key: the length header decodes to garbage and is (almost surely) rejected
        // or yields the wrong bytes — either way it never returns the real plaintext.
        let wrong = deobfuscate(&[3u8; 32], &framed);
        assert!(wrong.as_deref() != Some(&b"secret"[..]));
        // Random bytes: rejected.
        assert!(deobfuscate(&key, &[0u8; 8]).is_none());
    }

    #[test]
    fn empty_payload_roundtrips() {
        let key = [7u8; 32];
        let framed = obfuscate(&key, b"");
        assert_eq!(deobfuscate(&key, &framed).unwrap(), b"");
    }
}

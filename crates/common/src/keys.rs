//! WireGuard key material.
//!
//! Keys are Curve25519 32-byte values encoded as standard base64 on the wire and
//! in config files, exactly matching `wg`'s format so we interoperate with stock
//! WireGuard tooling. Secret material is wrapped in [`SecretKey`], which zeroizes
//! on drop and never implements `Debug`/`Display` so it can't be logged by accident.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand_core::OsRng;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

fn decode_key(s: &str) -> Result<[u8; 32]> {
    let bytes = B64
        .decode(s.trim())
        .map_err(|e| Error::Key(format!("base64: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Key(format!("expected 32 bytes, got {}", bytes.len())))?;
    Ok(arr)
}

fn encode_key(bytes: &[u8; 32]) -> String {
    B64.encode(bytes)
}

/// A public key or other non-secret 32-byte value (base64 in config).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_base64(&self) -> String {
        encode_key(&self.0)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Public keys are safe to print; show base64 for readable logs.
        write!(f, "PublicKey({})", self.to_base64())
    }
}

impl std::str::FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(PublicKey(decode_key(s)?))
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        decode_key(&s).map(PublicKey).map_err(de::Error::custom)
    }
}

/// A secret 32-byte value (private key or preshared key). Zeroized on drop.
///
/// Deliberately has no `Debug`/`Display`/`Serialize` that reveals bytes beyond the
/// base64 needed to round-trip config. It never appears in `tracing` output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SecretKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_base64(&self) -> String {
        encode_key(&self.0)
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never reveal secret material in logs.
        f.write_str("SecretKey(<redacted>)")
    }
}

impl std::str::FromStr for SecretKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(SecretKey(decode_key(s)?))
    }
}

impl Serialize for SecretKey {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        decode_key(&s).map(SecretKey).map_err(de::Error::custom)
    }
}

/// Generate a fresh Curve25519 private key using the OS CSPRNG. Matches `wg genkey`.
pub fn generate_secret() -> SecretKey {
    let secret = StaticSecret::random_from_rng(OsRng);
    SecretKey(secret.to_bytes())
}

/// Derive the public key for a private key. Matches `wg pubkey`.
pub fn public_from_secret(sk: &SecretKey) -> PublicKey {
    let secret = StaticSecret::from(sk.0);
    PublicKey(XPublicKey::from(&secret).to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn derived_public_matches_x25519() {
        let sk = generate_secret();
        let pk = public_from_secret(&sk);
        // Deriving twice is stable and the public key is non-zero.
        assert_eq!(pk, public_from_secret(&sk));
        assert_ne!(pk.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn roundtrip_base64() {
        let sk = SecretKey::from_bytes([7u8; 32]);
        let b64 = sk.to_base64();
        let parsed = SecretKey::from_str(&b64).unwrap();
        assert_eq!(parsed.as_bytes(), &[7u8; 32]);
    }

    #[test]
    fn rejects_wrong_length() {
        // base64 of 31 bytes should be rejected.
        let short = B64.encode([0u8; 31]);
        assert!(PublicKey::from_str(&short).is_err());
    }
}

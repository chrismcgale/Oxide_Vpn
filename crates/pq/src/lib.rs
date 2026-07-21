//! Post-quantum key agreement (ML-KEM / Kyber) for a hybrid WireGuard handshake.
//!
//! WireGuard's key exchange is x25519, which a large quantum computer could break. This
//! crate adds a *second*, quantum-resistant secret and feeds it into WireGuard's
//! **preshared-key** slot. It is strictly **additive/hybrid**: the session is protected
//! by x25519 AND the ML-KEM secret, so this can only strengthen security — even if the
//! (not-yet-audited) ML-KEM implementation were flawed, the classical WireGuard security
//! still holds.
//!
//! Flow (mapped onto our control plane):
//!   * A server has an ML-KEM keypair; it publishes its public (encapsulation) key.
//!   * A client `encapsulate`s to that public key, getting a ciphertext + a 32-byte
//!     shared secret. It uses the secret as the WireGuard PSK and sends the ciphertext
//!     to the server (via the control plane, at registration).
//!   * The server `decapsulate`s the ciphertext with its private key, recovering the
//!     same 32-byte secret, and sets it as that peer's PSK.
//!
//! ML-KEM-768 (NIST security category 3). The private key is stored/transported as its
//! 64-byte seed; public keys and ciphertexts are ~1184 / ~1088 bytes.

use ml_kem::{
    Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, Kem, Key, KeyExport, MlKem768,
    Seed,
};

/// Byte length of the private-key seed.
pub const SEED_LEN: usize = 64;
/// Byte length of the derived shared secret (fits the WireGuard PSK slot exactly).
pub const SHARED_LEN: usize = 32;

type Ek = EncapsulationKey<MlKem768>;
type Dk = DecapsulationKey<MlKem768>;

/// Generate a fresh ML-KEM keypair. Returns `(private_seed, public_key_bytes)`.
pub fn generate() -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = MlKem768::generate_keypair();
    let seed = dk.to_seed().expect("ml-kem key is seed-derivable");
    (seed.as_slice().to_vec(), ek.to_bytes().as_slice().to_vec())
}

/// Recover the public (encapsulation) key bytes from a private seed.
pub fn public_from_seed(seed: &[u8]) -> Option<Vec<u8>> {
    let dk = dk_from_seed(seed)?;
    Some(dk.encapsulation_key().to_bytes().as_slice().to_vec())
}

/// Encapsulate to `public_key`, returning `(ciphertext, shared_secret)`.
pub fn encapsulate(public_key: &[u8]) -> Option<(Vec<u8>, [u8; SHARED_LEN])> {
    let key = Key::<Ek>::try_from(public_key).ok()?;
    let ek = Ek::new(&key).ok()?;
    let (ct, ss) = ek.encapsulate();
    let shared: [u8; SHARED_LEN] = ss.as_slice().try_into().ok()?;
    Some((ct.as_slice().to_vec(), shared))
}

/// Decapsulate `ciphertext` with the private `seed`, recovering the shared secret.
pub fn decapsulate(seed: &[u8], ciphertext: &[u8]) -> Option<[u8; SHARED_LEN]> {
    let dk = dk_from_seed(seed)?;
    let ss = dk.decapsulate_slice(ciphertext).ok()?;
    ss.as_slice().try_into().ok()
}

fn dk_from_seed(seed: &[u8]) -> Option<Dk> {
    let seed = Seed::try_from(seed).ok()?;
    Some(Dk::from_seed(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_decapsulate_agree() {
        let (seed, public_key) = generate();
        assert_eq!(seed.len(), SEED_LEN);

        let (ct, client_secret) = encapsulate(&public_key).unwrap();
        let server_secret = decapsulate(&seed, &ct).unwrap();
        assert_eq!(client_secret, server_secret);
    }

    #[test]
    fn public_key_is_stable_from_seed() {
        let (seed, public_key) = generate();
        assert_eq!(public_from_seed(&seed).unwrap(), public_key);
    }

    #[test]
    fn wrong_seed_yields_different_secret() {
        let (_seed_a, public_key) = generate();
        let (seed_b, _pk_b) = generate();
        let (ct, client_secret) = encapsulate(&public_key).unwrap();
        // Decapsulating with the wrong private key must not reproduce the secret.
        let wrong = decapsulate(&seed_b, &ct).unwrap();
        assert_ne!(client_secret, wrong);
    }
}

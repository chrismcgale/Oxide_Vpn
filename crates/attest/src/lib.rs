//! Verifiable build identity: a release-key-**signed manifest** binding a running server to
//! the exact binary it is running.
//!
//! Enforced no-logs ([`oxide_seccomp`]) proves the server *can't* write to disk; this proves
//! *which build* is doing that. The operator signs a [`BuildManifest`] (the binary's SHA-256,
//! its git commit, version, build time) with an offline **release key**; the server publishes
//! the [`SignedManifest`]; a client that pins the release public key verifies the signature at
//! connect and can refuse an unknown or tampered build. Combined with reproducible builds
//! (rebuild the pinned git commit → identical SHA-256) this turns "trust our no-logs claim"
//! into "verify the binary is the audited one."
//!
//! Signatures are Ed25519 over a fixed **canonical** encoding of the manifest (not the JSON,
//! so formatting can't change what was signed). The binary hash is computed at runtime from
//! `/proc/self/exe`, a read-only open that the no-logs seccomp filter permits.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Length of an Ed25519 seed / public key.
pub const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("signature verification failed")]
    BadSignature,
    #[error("release public key mismatch (manifest not signed by the pinned key)")]
    KeyMismatch,
    #[error("malformed field: {0}")]
    Malformed(&'static str),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// What a build *is*: the fields that identify the exact binary a server runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildManifest {
    /// Crate version (`CARGO_PKG_VERSION`).
    pub version: String,
    /// Git commit the binary was built from (baked in at build time).
    pub git_commit: String,
    /// Build timestamp (informational; use reproducible builds for byte-identity).
    pub build_time: String,
    /// Lowercase hex SHA-256 of the binary itself (`/proc/self/exe` at runtime).
    pub binary_sha256: String,
}

impl BuildManifest {
    /// The exact bytes that get signed. A fixed, versioned, field-ordered encoding — never
    /// the JSON — so re-serialization or key reordering can't change the signed message.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "oxide-build-manifest-v1\nversion={}\ngit_commit={}\nbuild_time={}\nbinary_sha256={}",
            self.version, self.git_commit, self.build_time, self.binary_sha256
        )
        .into_bytes()
    }
}

/// A [`BuildManifest`] plus its Ed25519 signature and the signer's public key (base64). The
/// public key is carried for convenience only — verification is always against a **pinned**
/// key, never the one embedded here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifest {
    pub manifest: BuildManifest,
    /// Base64 Ed25519 signature over [`BuildManifest::canonical_bytes`].
    pub signature: String,
    /// Base64 Ed25519 public key of the signer (informational).
    pub public_key: String,
}

impl SignedManifest {
    pub fn to_json(&self) -> String {
        // Infallible for this shape; fall back to an empty object on the impossible error.
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

/// Generate a fresh release keypair: `(signing_seed, public_key)`, both 32 bytes. Keep the
/// seed offline; pin the public key in clients.
pub fn generate_release_key() -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut seed = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    (seed, pk)
}

/// The public key for a signing seed (base64), e.g. to print alongside a generated key.
pub fn public_key_b64(signing_seed: &[u8; KEY_LEN]) -> String {
    let sk = SigningKey::from_bytes(signing_seed);
    B64.encode(sk.verifying_key().to_bytes())
}

/// Sign a manifest with the release signing seed.
pub fn sign_manifest(manifest: BuildManifest, signing_seed: &[u8; KEY_LEN]) -> SignedManifest {
    let sk = SigningKey::from_bytes(signing_seed);
    let sig = sk.sign(&manifest.canonical_bytes());
    SignedManifest {
        signature: B64.encode(sig.to_bytes()),
        public_key: B64.encode(sk.verifying_key().to_bytes()),
        manifest,
    }
}

/// Verify a signed manifest against a **pinned** release public key. Returns the manifest on
/// success, or an error if the key doesn't match, the signature is invalid, or a field is
/// malformed. A caller then checks `manifest.binary_sha256` against the build it expects.
pub fn verify_manifest<'a>(
    signed: &'a SignedManifest,
    pinned_public_key: &[u8; KEY_LEN],
) -> Result<&'a BuildManifest> {
    // The embedded public key must be the one we pinned — reject a manifest signed by anyone
    // else outright (before even checking the signature).
    let embedded = B64
        .decode(&signed.public_key)
        .ok()
        .and_then(|b| <[u8; KEY_LEN]>::try_from(b).ok())
        .ok_or(Error::Malformed("public_key"))?;
    if &embedded != pinned_public_key {
        return Err(Error::KeyMismatch);
    }

    let vk = VerifyingKey::from_bytes(pinned_public_key).map_err(|_| Error::Malformed("key"))?;
    let sig_bytes: [u8; 64] = B64
        .decode(&signed.signature)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .ok_or(Error::Malformed("signature"))?;
    let sig = Signature::from_bytes(&sig_bytes);

    vk.verify(&signed.manifest.canonical_bytes(), &sig)
        .map_err(|_| Error::BadSignature)?;
    Ok(&signed.manifest)
}

/// SHA-256 (lowercase hex) of the currently running binary, read from `/proc/self/exe`.
pub fn self_binary_sha256() -> Result<String> {
    let bytes = std::fs::read("/proc/self/exe")?;
    Ok(sha256_hex(&bytes))
}

/// Lowercase-hex SHA-256 of arbitrary bytes (used for the binary hash and by the
/// transparency log).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------------------
// Transparency log (1D-3)
// ---------------------------------------------------------------------------------------

/// One entry in the append-only build log: a deployed binary hash + its git commit, chained
/// to the previous entry by `prev_hash` so the log is tamper-evident (changing any past
/// entry changes every later hash and the signed head).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub seq: u64,
    pub binary_sha256: String,
    pub git_commit: String,
    /// Hash of the previous entry (empty for the genesis entry).
    pub prev_hash: String,
}

impl LogEntry {
    fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "oxide-tlog-entry-v1\nseq={}\nbinary_sha256={}\ngit_commit={}\nprev_hash={}",
            self.seq, self.binary_sha256, self.git_commit, self.prev_hash
        )
        .into_bytes()
    }
    /// This entry's hash — commits to the whole prefix via `prev_hash`.
    pub fn hash(&self) -> String {
        sha256_hex(&self.canonical_bytes())
    }
}

/// An append-only, hash-chained log of deployed builds. The operator publishes it and signs
/// its [`SignedHead`]; a client checks that the build its server reported (via the signed
/// manifest) appears in a log whose head is signed by the pinned log key — i.e. the server
/// runs a build that was publicly logged, not a one-off swapped in for them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransparencyLog {
    entries: Vec<LogEntry>,
}

/// The signed head of a transparency log: commits to the entire log via `head_hash` (the
/// last entry's chain hash) and `count`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHead {
    pub head_hash: String,
    pub count: u64,
    pub signature: String,
    pub public_key: String,
}

fn head_canonical(head_hash: &str, count: u64) -> Vec<u8> {
    format!("oxide-tlog-head-v1\nhead_hash={head_hash}\ncount={count}").into_bytes()
}

impl TransparencyLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconstruct a log from published entries (e.g. downloaded by a client). Validate it
    /// with [`TransparencyLog::verify_chain`] before trusting it.
    pub fn from_entries(entries: Vec<LogEntry>) -> Self {
        TransparencyLog { entries }
    }

    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// Append a build to the log, chaining it to the current head.
    pub fn append(&mut self, binary_sha256: impl Into<String>, git_commit: impl Into<String>) {
        let entry = LogEntry {
            seq: self.entries.len() as u64,
            binary_sha256: binary_sha256.into(),
            git_commit: git_commit.into(),
            prev_hash: self.head_hash(),
        };
        self.entries.push(entry);
    }

    /// The chain hash of the whole log (the last entry's hash), or empty for an empty log.
    pub fn head_hash(&self) -> String {
        self.entries.last().map(LogEntry::hash).unwrap_or_default()
    }

    /// Verify the log is a well-formed chain: sequential `seq`, and each `prev_hash` links to
    /// the actual previous entry. Detects any insertion, deletion, or edit of history.
    pub fn verify_chain(&self) -> bool {
        let mut prev = String::new();
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != i as u64 || e.prev_hash != prev {
                return false;
            }
            prev = e.hash();
        }
        true
    }

    /// The sequence number at which `binary_sha256` appears, if it does.
    pub fn contains(&self, binary_sha256: &str) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.binary_sha256 == binary_sha256)
            .map(|e| e.seq)
    }

    /// Sign the log's head with the operator's signing seed.
    pub fn sign_head(&self, signing_seed: &[u8; KEY_LEN]) -> SignedHead {
        let head_hash = self.head_hash();
        let count = self.entries.len() as u64;
        let sk = SigningKey::from_bytes(signing_seed);
        let sig = sk.sign(&head_canonical(&head_hash, count));
        SignedHead {
            head_hash,
            count,
            signature: B64.encode(sig.to_bytes()),
            public_key: B64.encode(sk.verifying_key().to_bytes()),
        }
    }
}

/// Verify a published transparency log against a **pinned** operator public key: the chain is
/// well-formed, the signed head matches the entries, and the head signature is valid. Returns
/// the validated log so the caller can then check membership of its server's binary hash.
pub fn verify_log(
    entries: Vec<LogEntry>,
    head: &SignedHead,
    pinned_public_key: &[u8; KEY_LEN],
) -> Result<TransparencyLog> {
    let embedded = B64
        .decode(&head.public_key)
        .ok()
        .and_then(|b| <[u8; KEY_LEN]>::try_from(b).ok())
        .ok_or(Error::Malformed("head public_key"))?;
    if &embedded != pinned_public_key {
        return Err(Error::KeyMismatch);
    }

    let log = TransparencyLog::from_entries(entries);
    if !log.verify_chain()
        || log.head_hash() != head.head_hash
        || log.entries().len() as u64 != head.count
    {
        return Err(Error::BadSignature);
    }

    let vk = VerifyingKey::from_bytes(pinned_public_key).map_err(|_| Error::Malformed("key"))?;
    let sig_bytes: [u8; 64] = B64
        .decode(&head.signature)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .ok_or(Error::Malformed("signature"))?;
    vk.verify(
        &head_canonical(&head.head_hash, head.count),
        &Signature::from_bytes(&sig_bytes),
    )
    .map_err(|_| Error::BadSignature)?;
    Ok(log)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BuildManifest {
        BuildManifest {
            version: "0.1.0".into(),
            git_commit: "abc1234".into(),
            build_time: "2026-07-22T00:00:00Z".into(),
            binary_sha256: sha256_hex(b"a fake binary"),
        }
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (seed, pk) = generate_release_key();
        let signed = sign_manifest(sample(), &seed);
        let m = verify_manifest(&signed, &pk).expect("valid signature");
        assert_eq!(m.git_commit, "abc1234");
    }

    #[test]
    fn tampered_manifest_is_rejected() {
        let (seed, pk) = generate_release_key();
        let mut signed = sign_manifest(sample(), &seed);
        // Flip the binary hash — the signature no longer covers it.
        signed.manifest.binary_sha256 = sha256_hex(b"a DIFFERENT binary");
        assert!(matches!(
            verify_manifest(&signed, &pk),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn wrong_pinned_key_is_rejected() {
        let (seed, _pk) = generate_release_key();
        let (_other_seed, other_pk) = generate_release_key();
        let signed = sign_manifest(sample(), &seed);
        // A client pinning a different release key must refuse it (before signature check).
        assert!(matches!(
            verify_manifest(&signed, &other_pk),
            Err(Error::KeyMismatch)
        ));
    }

    #[test]
    fn attacker_resigns_with_own_key_is_rejected() {
        // An attacker who swaps in a tampered manifest AND re-signs with their own key still
        // fails, because the client verifies against the *pinned* release key.
        let (_good_seed, good_pk) = generate_release_key();
        let (evil_seed, _evil_pk) = generate_release_key();
        let mut m = sample();
        m.binary_sha256 = sha256_hex(b"malicious build");
        let evil = sign_manifest(m, &evil_seed);
        assert!(matches!(
            verify_manifest(&evil, &good_pk),
            Err(Error::KeyMismatch)
        ));
    }

    #[test]
    fn json_roundtrips() {
        let (seed, pk) = generate_release_key();
        let signed = sign_manifest(sample(), &seed);
        let json = signed.to_json();
        let back = SignedManifest::from_json(&json).unwrap();
        assert!(verify_manifest(&back, &pk).is_ok());
    }

    #[test]
    fn self_hash_is_hex_sha256() {
        let h = self_binary_sha256().expect("read own binary");
        assert_eq!(h.len(), 64);
        assert!(h.bytes().all(|c| c.is_ascii_hexdigit()));
    }

    fn build_log() -> ([u8; KEY_LEN], [u8; KEY_LEN], TransparencyLog) {
        let (seed, pk) = generate_release_key();
        let mut log = TransparencyLog::new();
        log.append(sha256_hex(b"build-1"), "aaa1111");
        log.append(sha256_hex(b"build-2"), "bbb2222");
        log.append(sha256_hex(b"build-3"), "ccc3333");
        (seed, pk, log)
    }

    #[test]
    fn log_chain_and_signed_head_verify() {
        let (seed, pk, log) = build_log();
        assert!(log.verify_chain());
        let head = log.sign_head(&seed);
        let verified = verify_log(log.entries().to_vec(), &head, &pk).expect("valid log");
        // A client can now prove its server's build is in the logged, audited set.
        assert!(verified.contains(&sha256_hex(b"build-2")).is_some());
        assert!(verified.contains(&sha256_hex(b"never-logged")).is_none());
    }

    #[test]
    fn edited_history_breaks_the_chain() {
        let (seed, pk, log) = build_log();
        let head = log.sign_head(&seed); // head over the honest log
                                         // Tamper with a past entry's commit; every later hash and the head no longer match.
        let mut entries = log.entries().to_vec();
        entries[1].git_commit = "forged!".into();
        let tampered = TransparencyLog::from_entries(entries.clone());
        assert!(!tampered.verify_chain());
        // And verifying the tampered entries against the honest signed head fails.
        assert!(matches!(
            verify_log(entries, &head, &pk),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn head_signed_by_wrong_key_is_rejected() {
        let (seed, _pk, log) = build_log();
        let (_other, other_pk) = generate_release_key();
        let head = log.sign_head(&seed);
        assert!(matches!(
            verify_log(log.entries().to_vec(), &head, &other_pk),
            Err(Error::KeyMismatch)
        ));
    }
}

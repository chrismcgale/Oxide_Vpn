//! Runtime-mutable peer table, keyed by public key.
//!
//! The control plane (M2) adds and removes peers on a live server as devices register
//! and expire, so peers can't be a fixed `Vec` built once at startup. Peers are keyed
//! by their public key — a stable identity that survives other peers being removed
//! (unlike a positional index). The engine holds this behind an `RwLock`: reads (every
//! packet) take the lock only long enough to clone the relevant `Arc<Peer>`; writes
//! (rare reconciles) take it exclusively.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use boringtun::noise::Tunn;
use boringtun::x25519::{PublicKey as XPublicKey, StaticSecret};

use crate::peer::Peer;
use crate::router::AllowedIps;
use crate::PeerParams;

/// Stable per-peer identity: the raw 32-byte public key.
pub type PeerId = [u8; 32];

pub struct PeerTable {
    static_private: StaticSecret,
    /// boringtun session index, unique per peer for its lifetime.
    next_index: u32,
    peers: HashMap<PeerId, Arc<Peer>>,
    router: AllowedIps<PeerId>,
}

impl PeerTable {
    pub fn new(static_private: StaticSecret) -> Self {
        PeerTable {
            static_private,
            next_index: 0,
            peers: HashMap::new(),
            router: AllowedIps::new(),
        }
    }

    /// Add a peer. No-op if one with the same public key already exists (so a
    /// reconcile leaves live sessions untouched).
    pub fn add(&mut self, p: PeerParams) {
        let id = p.public_key.0;
        if self.peers.contains_key(&id) {
            return;
        }
        let peer_public = XPublicKey::from(id);
        let tunn = Tunn::new(
            self.static_private.clone(),
            peer_public,
            p.preshared_key,
            p.persistent_keepalive,
            self.next_index,
            None,
        );
        self.next_index = self.next_index.wrapping_add(1);
        for net in &p.allowed_ips {
            self.router.insert(*net, id);
        }
        self.peers.insert(
            id,
            Arc::new(Peer::new(tunn, p.endpoint, p.allowed_ips, p.public_key)),
        );
    }

    /// Remove a peer and its routes. Its `Tunn` (and session keys) drop here.
    pub fn remove(&mut self, id: &PeerId) {
        if self.peers.remove(id).is_some() {
            self.router.retain_not(*id);
        }
    }

    /// Peer owning `dst` by longest-prefix match (outbound routing).
    pub fn route(&self, dst: IpAddr) -> Option<Arc<Peer>> {
        self.router
            .lookup(dst)
            .and_then(|id| self.peers.get(&id).cloned())
    }

    /// True if `addr` is a permitted source for the peer identified by `id`.
    pub fn source_ok(&self, addr: IpAddr, id: &PeerId) -> bool {
        self.router.is_allowed_for(addr, *id)
    }

    pub fn get(&self, id: &PeerId) -> Option<Arc<Peer>> {
        self.peers.get(id).cloned()
    }

    /// Snapshot of `(id, peer)` for iteration (timer loop, inbound demux fallback).
    pub fn snapshot(&self) -> Vec<(PeerId, Arc<Peer>)> {
        self.peers.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    pub fn ids(&self) -> Vec<PeerId> {
        self.peers.keys().copied().collect()
    }
}

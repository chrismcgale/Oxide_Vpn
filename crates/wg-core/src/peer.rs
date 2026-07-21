//! A single WireGuard peer: its boringtun state machine plus the endpoint we send to.
//!
//! The `Tunn` is not `Sync`, and boringtun mutates it on every encapsulate/decapsulate/
//! timer call, so it lives behind a `std::sync::Mutex`. We only ever hold that lock to
//! run one boringtun call into a stack buffer and copy the result out — never across an
//! `.await` — so a blocking mutex is correct and cheap here.

use std::net::SocketAddr;
use std::sync::Mutex;

use boringtun::noise::Tunn;
use ipnet::IpNet;

use crate::PublicKey;

pub struct Peer {
    /// boringtun session state for this peer.
    pub tunn: Mutex<Tunn>,

    /// Where to send this peer's encrypted datagrams. For a client, this is the
    /// configured server endpoint. For a server, it starts `None` and is learned
    /// (and updated, for roaming) from the source address of received datagrams.
    pub endpoint: Mutex<Option<SocketAddr>>,

    /// CIDRs this peer may use as packet sources / that we route to it.
    pub allowed_ips: Vec<IpNet>,

    /// Static public key (safe to log; used for diagnostics).
    pub public_key: PublicKey,
}

impl Peer {
    pub fn new(
        tunn: Tunn,
        endpoint: Option<SocketAddr>,
        allowed_ips: Vec<IpNet>,
        public_key: PublicKey,
    ) -> Self {
        Self {
            tunn: Mutex::new(tunn),
            endpoint: Mutex::new(endpoint),
            allowed_ips,
            public_key,
        }
    }

    pub fn endpoint(&self) -> Option<SocketAddr> {
        *self.endpoint.lock().unwrap()
    }

    /// Update the endpoint if it changed (roaming); returns true if it moved.
    pub fn set_endpoint(&self, addr: SocketAddr) -> bool {
        let mut ep = self.endpoint.lock().unwrap();
        if *ep != Some(addr) {
            *ep = Some(addr);
            true
        } else {
            false
        }
    }
}

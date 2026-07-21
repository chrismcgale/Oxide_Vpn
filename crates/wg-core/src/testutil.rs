//! Test-support helpers (behind the `test-util` feature).
//!
//! An in-memory [`MockTun`] stands in for a real `/dev/net/tun`, so engines can be
//! driven end-to-end over loopback UDP with no root and no device. Shared by this
//! crate's integration tests and higher-level crates that exercise the full M2 flow.

use std::future::pending;
use std::io;

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;

use oxide_common::TunQueue;

/// In-memory TUN: `recv` yields injected packets (as if the OS sent them out);
/// `send` captures packets the engine wrote (decapsulated inbound traffic).
pub struct MockTun {
    inject: Mutex<UnboundedReceiver<Vec<u8>>>,
    capture: UnboundedSender<Vec<u8>>,
}

impl MockTun {
    /// Returns the device plus `(inject_sender, capture_receiver)` for the test to
    /// push outbound packets and read what surfaced on the tunnel.
    pub fn pair() -> (Self, UnboundedSender<Vec<u8>>, UnboundedReceiver<Vec<u8>>) {
        let (inject_tx, inject_rx) = unbounded_channel();
        let (capture_tx, capture_rx) = unbounded_channel();
        (
            MockTun {
                inject: Mutex::new(inject_rx),
                capture: capture_tx,
            },
            inject_tx,
            capture_rx,
        )
    }
}

impl TunQueue for MockTun {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rx = self.inject.lock().await;
        match rx.recv().await {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => pending().await,
        }
    }

    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let _ = self.capture.send(buf.to_vec());
        Ok(buf.len())
    }
}

/// Build a minimal IPv4 packet so `Tunn::dst_address` can route it and the inbound
/// source check can read the source address.
pub fn ipv4_packet(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total_len = (20 + payload.len()) as u16;
    let mut p = vec![0u8; 20 + payload.len()];
    p[0] = 0x45; // version 4, IHL 5
    p[2..4].copy_from_slice(&total_len.to_be_bytes());
    p[8] = 64; // TTL
    p[9] = 17; // protocol UDP (not validated here)
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..].copy_from_slice(payload);
    p
}

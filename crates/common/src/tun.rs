//! Abstract TUN queue.
//!
//! `wg-core` drives the data plane against this trait so it stays OS-agnostic and
//! unit-testable without a real device; `net-linux` provides the concrete Linux
//! implementation over `/dev/net/tun`. Both `recv` and `send` take `&self` so a
//! single device can be shared (via `Arc`) between the inbound and outbound tasks —
//! a TUN fd is full-duplex.
//!
//! Buffers carry bare IP packets (the device is opened `IFF_NO_PI`, so there is no
//! 4-byte packet-info prefix).

use std::future::Future;
use std::io;

pub trait TunQueue: Send + Sync + 'static {
    /// Read one IP packet from the tunnel interface into `buf`, returning its length.
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;

    /// Write one IP packet to the tunnel interface.
    fn send(&self, buf: &[u8]) -> impl Future<Output = io::Result<usize>> + Send;
}

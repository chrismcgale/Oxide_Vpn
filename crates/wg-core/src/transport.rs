//! The datagram transport the engine sends/receives WireGuard packets over.
//!
//! Abstracts the UDP socket so the engine's logic is identical whether traffic is sent
//! in the clear or through the obfuscation layer ("stealth mode"). Keeping this an enum
//! (rather than a generic) avoids threading another type parameter through the engine.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

use oxide_obfs::{deobfuscate, obfuscate};

use crate::mimic::MimicTransport;

/// Scratch buffer for an obfuscated datagram (WireGuard max + obfs overhead).
const OBFS_BUF: usize = 2048;

pub enum Transport {
    /// Plain UDP — standard WireGuard on the wire.
    Plain(UdpSocket),
    /// Obfuscated UDP: each datagram is wrapped so DPI can't fingerprint it.
    Obfuscated { socket: UdpSocket, key: [u8; 32] },
    /// TLS-mimicry over TCP: the flow looks like an HTTPS session ("stealth tier 2").
    Mimic(MimicTransport),
}

impl Transport {
    pub fn plain(socket: UdpSocket) -> Self {
        Transport::Plain(socket)
    }

    pub fn obfuscated(socket: UdpSocket, key: [u8; 32]) -> Self {
        Transport::Obfuscated { socket, key }
    }

    pub fn mimic(transport: MimicTransport) -> Self {
        Transport::Mimic(transport)
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        match self {
            Transport::Plain(s) => s.send_to(buf, addr).await,
            Transport::Obfuscated { socket, key } => {
                let framed = obfuscate(key, buf);
                socket.send_to(&framed, addr).await?;
                Ok(buf.len())
            }
            Transport::Mimic(m) => m.send_to(buf, addr).await,
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            Transport::Plain(s) => s.recv_from(buf).await,
            Transport::Obfuscated { socket, key } => {
                let mut raw = [0u8; OBFS_BUF];
                loop {
                    let (n, addr) = socket.recv_from(&mut raw).await?;
                    // Undecodable datagrams (scans/probes) are silently dropped: giving
                    // no response is itself part of resisting active detection.
                    if let Some(plain) = deobfuscate(key, &raw[..n]) {
                        let m = plain.len().min(buf.len());
                        buf[..m].copy_from_slice(&plain[..m]);
                        return Ok((m, addr));
                    }
                }
            }
            Transport::Mimic(m) => m.recv_from(buf).await,
        }
    }
}

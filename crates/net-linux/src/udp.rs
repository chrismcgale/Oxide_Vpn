//! UDP socket helpers for the WireGuard underlay transport.
//!
//! The tunnel's UDP socket is bound here (not in `wg-core`, which stays OS-agnostic and just
//! takes a ready socket) so a server/client can serve **both IPv4 and IPv6 clients on one
//! socket**: bind `[::]` with `IPV6_V6ONLY` cleared, and the kernel accepts v4 peers as
//! IPv4-mapped addresses. Hosts with IPv6 disabled fall back to a plain `0.0.0.0` bind.

use std::io;
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};
use tracing::debug;

/// Bind a **dual-stack** UDP socket on `[::]:port` (both IPv4 and IPv6), returning a
/// nonblocking `std::net::UdpSocket` ready for `tokio::net::UdpSocket::from_std`.
///
/// `IPV6_V6ONLY` is cleared so one socket serves v4 (as IPv4-mapped) and v6 peers — this is
/// what lets clients dial a server over IPv6 or IPv4 without the server binding two sockets.
/// If the host has IPv6 disabled (the `[::]` bind fails), falls back to `0.0.0.0:port` so an
/// IPv4-only box keeps working. `port` 0 requests an ephemeral port (client side).
pub fn bind_dual_stack(port: u16) -> io::Result<UdpSocket> {
    match bind_v6_dual(port) {
        Ok(sock) => Ok(sock),
        Err(e) => {
            debug!(
                ?e,
                "dual-stack [::] bind failed; falling back to IPv4 0.0.0.0"
            );
            let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            sock.set_nonblocking(true)?;
            sock.bind(&SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port)).into())?;
            Ok(sock.into())
        }
    }
}

fn bind_v6_dual(port: u16) -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    // Clear IPV6_V6ONLY so the socket also accepts IPv4 (mapped) peers.
    sock.set_only_v6(false)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    Ok(sock.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // One dual-stack socket must receive datagrams from BOTH an IPv6 and an IPv4 client —
    // the whole point of IPV6_V6ONLY=false. No root needed (loopback).
    #[test]
    fn dual_stack_socket_receives_v4_and_v6() {
        let server = bind_dual_stack(0).expect("bind dual-stack");
        server.set_nonblocking(false).unwrap();
        let port = server.local_addr().unwrap().port();

        // IPv6 client -> [::1]:port
        let c6 = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        c6.send_to(b"v6", (Ipv6Addr::LOCALHOST, port)).unwrap();
        let mut buf = [0u8; 8];
        let (n, from) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"v6");
        assert!(from.is_ipv6());

        // IPv4 client -> 127.0.0.1:port (delivered as an IPv4-mapped v6 address)
        let c4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        c4.send_to(b"v4", (Ipv4Addr::LOCALHOST, port)).unwrap();
        let (n, _from) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"v4");
    }
}

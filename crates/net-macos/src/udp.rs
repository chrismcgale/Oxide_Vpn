//! Dual-stack UDP bind — portable via `socket2` (identical behaviour to the Linux backend).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};

/// Bind a dual-stack UDP socket on `[::]:port` with `IPV6_V6ONLY` cleared (so one socket serves
/// v4 and v6), falling back to `0.0.0.0:port` if IPv6 is unavailable. Returns a nonblocking
/// `std::net::UdpSocket` ready for `tokio::net::UdpSocket::from_std`.
pub fn bind_dual_stack(port: u16) -> io::Result<UdpSocket> {
    match bind_v6_dual(port) {
        Ok(s) => Ok(s),
        Err(_) => {
            let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            sock.set_nonblocking(true)?;
            sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
            Ok(sock.into())
        }
    }
}

fn bind_v6_dual(port: u16) -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_only_v6(false)?;
    sock.set_nonblocking(true)?;
    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
    sock.bind(&SocketAddr::V6(addr).into())?;
    Ok(sock.into())
}

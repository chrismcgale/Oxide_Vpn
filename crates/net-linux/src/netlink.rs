//! Interface addressing and routing via **rtnetlink** (real netlink sockets).
//!
//! This replaces the earlier `ip`-command shell-outs for all mutations (link up/mtu,
//! address add, route add/del) — no dependency on the `iproute2` binary, and operations
//! go straight to the kernel. The route/address builders are family-agnostic, so IPv6
//! works the same as IPv4.
//!
//! One read — finding the current default gateway/interface — is still done with
//! `ip route show default`, because reconstructing it from raw netlink route-dump
//! attributes is disproportionately fiddly for a low-risk read. Everything that
//! *changes* kernel state goes through netlink.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::TryStreamExt;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rtnetlink::packet_route::route::{RouteMessage, RouteScope};
use rtnetlink::{new_connection, Handle, LinkUnspec, RouteMessageBuilder};

use crate::cmd::output;

/// Map an rtnetlink error to an `io::Error`, **preserving the kernel errno** for netlink
/// error messages so callers can match on `ErrorKind` — e.g. tolerate `AlreadyExists`
/// (EEXIST) when re-adding a route the kernel already installed, or `NotFound` (ENOENT) on
/// idempotent teardown. Without this every failure collapses to `ErrorKind::Other`.
fn to_io(e: rtnetlink::Error) -> io::Error {
    match e {
        rtnetlink::Error::NetlinkError(ref msg) => msg.to_io(),
        other => io::Error::other(other.to_string()),
    }
}

/// A handle to the kernel's routing/addressing via netlink. Cheap to clone.
#[derive(Clone)]
pub struct Netlink {
    handle: Handle,
}

impl Netlink {
    /// Open a netlink connection and spawn its background task.
    pub fn connect() -> io::Result<Self> {
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        Ok(Netlink { handle })
    }

    /// Resolve an interface name to its index.
    pub async fn link_index(&self, name: &str) -> io::Result<u32> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        match links.try_next().await.map_err(to_io)? {
            Some(link) => Ok(link.header.index),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("interface {name} not found"),
            )),
        }
    }

    /// Bring an interface up and set its MTU.
    pub async fn set_up_mtu(&self, index: u32, mtu: u32) -> io::Result<()> {
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().mtu(mtu).build())
            .execute()
            .await
            .map_err(to_io)
    }

    /// Assign a tunnel address (with prefix) to the interface.
    pub async fn add_address(&self, index: u32, addr: IpNet) -> io::Result<()> {
        self.handle
            .address()
            .add(index, addr.addr(), addr.prefix_len())
            .execute()
            .await
            .map_err(to_io)
    }

    /// Add an on-link route (dst out this interface, no gateway).
    pub async fn add_route_dev(&self, dst: IpNet, index: u32) -> io::Result<()> {
        self.handle
            .route()
            .add(dev_route(dst, index))
            .execute()
            .await
            .map_err(to_io)
    }

    /// Remove an on-link route (teardown).
    pub async fn del_route_dev(&self, dst: IpNet, index: u32) -> io::Result<()> {
        self.handle
            .route()
            .del(dev_route(dst, index))
            .execute()
            .await
            .map_err(to_io)
    }

    /// Add a `/32` or `/128` host route to `host` via `gateway` out `index`. Pins the
    /// VPN server's endpoint through the original gateway before the default route is
    /// swung into the tunnel (so the tunnel's own UDP doesn't recurse into itself).
    pub async fn add_host_route_via(
        &self,
        host: IpAddr,
        gateway: IpAddr,
        index: u32,
    ) -> io::Result<()> {
        self.handle
            .route()
            .add(host_route_via(host, gateway, index)?)
            .execute()
            .await
            .map_err(to_io)
    }

    /// Remove a host route (teardown).
    pub async fn del_host_route_via(
        &self,
        host: IpAddr,
        gateway: IpAddr,
        index: u32,
    ) -> io::Result<()> {
        self.handle
            .route()
            .del(host_route_via(host, gateway, index)?)
            .execute()
            .await
            .map_err(to_io)
    }

    /// Add a route for an arbitrary-prefix `dst` CIDR via `gateway` out `index`. Used by
    /// split-tunnel **exclude** to pin a CIDR to the original default gateway so it bypasses
    /// the tunnel (a more specific exclude outranks the tunnel default by longest prefix).
    pub async fn add_route_via(&self, dst: IpNet, gateway: IpAddr, index: u32) -> io::Result<()> {
        self.handle
            .route()
            .add(net_route_via(dst, gateway, index)?)
            .execute()
            .await
            .map_err(to_io)
    }

    /// Remove a routed-via-gateway CIDR (teardown).
    pub async fn del_route_via(&self, dst: IpNet, gateway: IpAddr, index: u32) -> io::Result<()> {
        self.handle
            .route()
            .del(net_route_via(dst, gateway, index)?)
            .execute()
            .await
            .map_err(to_io)
    }

    /// Capture all IPv4 traffic into the tunnel with the two-halves trick
    /// (`0.0.0.0/1` + `128.0.0.0/1`), which outranks the existing default by
    /// longest-prefix match without deleting it.
    pub async fn set_default_v4_via_dev(&self, index: u32) -> io::Result<()> {
        self.add_route_dev("0.0.0.0/1".parse().unwrap(), index)
            .await?;
        self.add_route_dev("128.0.0.0/1".parse().unwrap(), index)
            .await
    }

    /// IPv6 equivalent: `::/1` + `8000::/1`.
    pub async fn set_default_v6_via_dev(&self, index: u32) -> io::Result<()> {
        self.add_route_dev("::/1".parse().unwrap(), index).await?;
        self.add_route_dev("8000::/1".parse().unwrap(), index).await
    }

    /// Remove the split-default routes we installed (belt-and-suspenders; they also
    /// vanish when the tun interface is dropped).
    pub async fn clear_default_via_dev(&self, index: u32, v6: bool) {
        for cidr in ["0.0.0.0/1", "128.0.0.0/1"] {
            let _ = self.del_route_dev(cidr.parse().unwrap(), index).await;
        }
        if v6 {
            for cidr in ["::/1", "8000::/1"] {
                let _ = self.del_route_dev(cidr.parse().unwrap(), index).await;
            }
        }
    }
}

/// The current default route as `(gateway, egress interface name)`, parsed from
/// `ip route show default`. (The one read we don't do over netlink — see module docs.)
pub fn default_route() -> io::Result<Option<(IpAddr, String)>> {
    let text = output("ip", &["route", "show", "default"])?;
    for line in text.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let via = toks
            .iter()
            .position(|t| *t == "via")
            .and_then(|i| toks.get(i + 1));
        let dev = toks
            .iter()
            .position(|t| *t == "dev")
            .and_then(|i| toks.get(i + 1));
        if let (Some(gw), Some(dev)) = (via, dev) {
            if let Ok(ip) = gw.parse::<IpAddr>() {
                return Ok(Some((ip, dev.to_string())));
            }
        }
    }
    Ok(None)
}

fn dev_route(dst: IpNet, oif: u32) -> RouteMessage {
    match dst {
        IpNet::V4(n) => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(n.addr(), n.prefix_len())
            .output_interface(oif)
            .scope(RouteScope::Link)
            .build(),
        IpNet::V6(n) => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(n.addr(), n.prefix_len())
            .output_interface(oif)
            .scope(RouteScope::Link)
            .build(),
    }
}

fn host_route_via(host: IpAddr, gateway: IpAddr, oif: u32) -> io::Result<RouteMessage> {
    let host_net = match host {
        IpAddr::V4(h) => IpNet::V4(Ipv4Net::new(h, 32).expect("prefix 32 is valid")),
        IpAddr::V6(h) => IpNet::V6(Ipv6Net::new(h, 128).expect("prefix 128 is valid")),
    };
    net_route_via(host_net, gateway, oif)
}

fn net_route_via(dst: IpNet, gateway: IpAddr, oif: u32) -> io::Result<RouteMessage> {
    match (dst, gateway) {
        (IpNet::V4(d), IpAddr::V4(g)) => Ok(RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(d.addr(), d.prefix_len())
            .gateway(g)
            .output_interface(oif)
            .build()),
        (IpNet::V6(d), IpAddr::V6(g)) => Ok(RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(d.addr(), d.prefix_len())
            .gateway(g)
            .output_interface(oif)
            .build()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination and gateway address families differ",
        )),
    }
}

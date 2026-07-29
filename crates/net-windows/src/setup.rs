//! Bring up the tunnel interface on Windows: create the Wintun adapter, then address it + set MTU.
//!
//! Scaffold: both the adapter creation ([`crate::tun::TunDevice::create`]) and the addressing
//! ([`crate::netlink::Netlink`]) are stubbed (`TODO(windows)`), so this currently returns an
//! `Unsupported` error — it exists to keep the client contract identical across platforms.

use std::io;

use oxide_common::InterfaceConfig;

use crate::netlink::Netlink;
use crate::tun::TunDevice;

/// Create the Wintun adapter and configure its address(es) + MTU. Returns the device and its
/// interface index. Mirrors the Linux backend's signature.
pub async fn bring_up_interface(
    nl: &Netlink,
    name: &str,
    iface: &InterfaceConfig,
) -> io::Result<(TunDevice, u32)> {
    let dev = TunDevice::create(name)?;
    let index = nl.link_index(dev.name()).await?;
    nl.add_address(index, iface.address).await?;
    if let Some(addr6) = iface.address6 {
        nl.add_address(index, addr6).await?;
    }
    nl.set_up_mtu(index, iface.mtu()).await?;
    Ok((dev, index))
}

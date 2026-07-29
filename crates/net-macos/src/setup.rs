//! Bring up the tunnel interface on macOS: create the utun device, then address it + set MTU.
//!
//! The utun open is real; the addressing goes through [`crate::netlink::Netlink`], whose mutating
//! methods are still stubbed (`TODO(macos)`), so on a real Mac `bring_up_interface` currently
//! returns the device but errors at `add_address` until the BSD route/ioctl path is finished.

use std::io;

use oxide_common::InterfaceConfig;

use crate::netlink::Netlink;
use crate::tun::TunDevice;

/// Create the utun device and configure its address(es) + MTU. Returns the device and its
/// kernel-assigned interface index. Mirrors the Linux backend's signature.
pub async fn bring_up_interface(
    nl: &Netlink,
    name: &str,
    iface: &InterfaceConfig,
) -> io::Result<(TunDevice, u32)> {
    let dev = TunDevice::create(name)?;
    // macOS named the device (utunN); resolve the index from its real name, not `name`.
    let index = nl.link_index(dev.name()).await?;
    nl.add_address(index, iface.address).await?;
    if let Some(addr6) = iface.address6 {
        nl.add_address(index, addr6).await?;
    }
    nl.set_up_mtu(index, iface.mtu()).await?;
    Ok((dev, index))
}

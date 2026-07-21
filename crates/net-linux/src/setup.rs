//! Interface bring-up shared by the server and client daemons: create the TUN device,
//! assign its tunnel address(es), set MTU, and bring it up — all over netlink.

use std::io;

use oxide_common::InterfaceConfig;

use crate::netlink::Netlink;
use crate::tun::TunDevice;

/// Create the tunnel interface `name`, apply address(es)/MTU from `iface`, bring it up.
/// Returns the device plus its link index (for subsequent route operations).
pub async fn bring_up_interface(
    nl: &Netlink,
    name: &str,
    iface: &InterfaceConfig,
) -> io::Result<(TunDevice, u32)> {
    let dev = TunDevice::create(name)?;
    let index = nl.link_index(name).await?;
    nl.add_address(index, iface.address).await?;
    if let Some(addr6) = iface.address6 {
        nl.add_address(index, addr6).await?;
    }
    nl.set_up_mtu(index, iface.mtu()).await?;
    Ok((dev, index))
}

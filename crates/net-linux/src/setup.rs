//! Interface bring-up shared by the server and client daemons: create the TUN
//! device, set MTU, assign the tunnel address, and bring it up.

use std::io;

use oxide_common::InterfaceConfig;

use crate::netlink;
use crate::tun::TunDevice;

/// Create the tunnel interface `name` and apply address/MTU from `iface`.
pub fn bring_up_interface(name: &str, iface: &InterfaceConfig) -> io::Result<TunDevice> {
    let dev = TunDevice::create(name)?;
    netlink::set_mtu(name, iface.mtu())?;
    netlink::add_address(name, iface.address)?;
    netlink::set_up(name)?;
    Ok(dev)
}

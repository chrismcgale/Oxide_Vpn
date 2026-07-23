//! Interface bring-up shared by the server and client daemons: create the TUN device,
//! assign its tunnel address(es), set MTU, and bring it up — all over netlink.

use std::io;
use std::time::Duration;

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
    let dev = create_tun_retrying(name).await?;
    let index = nl.link_index(name).await?;
    nl.add_address(index, iface.address).await?;
    if let Some(addr6) = iface.address6 {
        nl.add_address(index, addr6).await?;
    }
    nl.set_up_mtu(index, iface.mtu()).await?;
    Ok((dev, index))
}

/// Create the TUN device, retrying briefly on `EBUSY`. On a fast reconnect the previous
/// interface of the same name may still be releasing (its fd closes asynchronously once the
/// old engine's tasks are aborted), so a short retry avoids failing the reconnect. A TUN
/// device auto-removes when its last fd closes, so no explicit delete is needed.
async fn create_tun_retrying(name: &str) -> io::Result<TunDevice> {
    let mut last_err = None;
    for _ in 0..20 {
        match TunDevice::create(name) {
            Ok(dev) => return Ok(dev),
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("tun create failed (EBUSY)")))
}

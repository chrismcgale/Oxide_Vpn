//! macOS **utun** TUN device.
//!
//! Opened via the `PF_SYSTEM` / `SYSPROTO_CONTROL` kernel control interface (the `com.apple.net
//! .utun_control` provider). Unlike Linux `IFF_NO_PI`, a utun packet is always prefixed on the
//! wire by a **4-byte address-family header** (`AF_INET` / `AF_INET6`, big-endian); we strip it on
//! `recv` and prepend it on `send` so `wg-core` sees raw IP packets exactly as it does on Linux.
//!
//! macOS assigns the interface name (`utunN`) — it can't be an arbitrary name like `oxide0` — so
//! `create` ignores the requested name and reports the kernel-assigned one via [`TunDevice::name`].
//! **TODO(macos):** the client (`client-core`) currently uses a fixed `IFNAME` for the DNS/kill
//! -switch/route calls; on macOS it must use `tun.name()` instead. Flagged for on-device work.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use oxide_common::TunQueue;
use tokio::io::unix::AsyncFd;

/// The utun kernel-control provider name.
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
/// `getsockopt`/`setsockopt` option to read back the assigned `utunN` name.
const UTUN_OPT_IFNAME: libc::c_int = 2;
/// `sockaddr_ctl.ss_sysaddr` value for a kernel control socket.
const AF_SYS_CONTROL: u16 = 2;
/// The 4-byte protocol-family header utun prepends to every packet.
const AF_HEADER_LEN: usize = 4;

pub struct TunDevice {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl TunDevice {
    /// Create a utun interface. The macOS kernel assigns the name (`utunN`); the requested
    /// `_name` is ignored (see the module note). Returns the device with its real name.
    pub fn create(_name: &str) -> io::Result<Self> {
        // SAFETY: standard utun open sequence; every raw fd is checked and owned on success.
        unsafe { Self::open_utun() }
    }

    unsafe fn open_utun() -> io::Result<Self> {
        let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = OwnedFd::from_raw_fd(fd);

        // Resolve the utun control id by name.
        let mut info: libc::ctl_info = std::mem::zeroed();
        for (dst, src) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME.iter()) {
            *dst = *src as libc::c_char;
        }
        if libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) < 0 {
            return Err(io::Error::last_os_error());
        }

        // Connect to the control, unit 0 => let the kernel pick the next free utun.
        let addr = libc::sockaddr_ctl {
            sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: 0,
            sc_reserved: [0; 5],
        };
        if libc::connect(
            fd,
            &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }

        let name = read_ifname(fd)?;
        set_nonblocking(fd)?;
        Ok(TunDevice {
            fd: AsyncFd::new(owned)?,
            name,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Read back the kernel-assigned `utunN` name via `getsockopt`.
unsafe fn read_ifname(fd: RawFd) -> io::Result<String> {
    let mut buf = [0u8; libc::IFNAMSIZ];
    let mut len = buf.len() as libc::socklen_t;
    if libc::getsockopt(
        fd,
        libc::SYSPROTO_CONTROL,
        UTUN_OPT_IFNAME,
        buf.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    ) < 0
    {
        return Err(io::Error::last_os_error());
    }
    // `len` includes the trailing NUL.
    let end = (len as usize).saturating_sub(1).min(buf.len());
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}

unsafe fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = libc::fcntl(fd, libc::F_GETFL);
    if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Big-endian 4-byte utun header for an outbound packet, chosen by IP version.
fn af_header(packet: &[u8]) -> [u8; AF_HEADER_LEN] {
    let af = match packet.first().map(|b| b >> 4) {
        Some(6) => libc::AF_INET6,
        _ => libc::AF_INET,
    };
    (af as u32).to_be_bytes()
}

impl TunQueue for TunDevice {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Read into a staging buffer that includes utun's 4-byte AF header, then hand the caller
        // just the IP packet (header stripped) so wg-core sees the same bytes as on Linux.
        let mut staging = [0u8; 65_536 + AF_HEADER_LEN];
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let n = unsafe {
                    libc::read(fd, staging.as_mut_ptr() as *mut libc::c_void, staging.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    let payload = &staging[AF_HEADER_LEN.min(n)..n];
                    let m = payload.len().min(buf.len());
                    buf[..m].copy_from_slice(&payload[..m]);
                    return Ok(m);
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }

    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        // Prepend utun's 4-byte AF header. `header` (Send) is chosen up front; the `iovec` array
        // (raw pointers, !Send) is built *inside* the readiness closure so nothing !Send is held
        // across the await — `TunQueue::send` requires a `Send` future.
        let header = af_header(buf);
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let iov = [
                    libc::iovec {
                        iov_base: header.as_ptr() as *mut libc::c_void,
                        iov_len: header.len(),
                    },
                    libc::iovec {
                        iov_base: buf.as_ptr() as *mut libc::c_void,
                        iov_len: buf.len(),
                    },
                ];
                let n = unsafe { libc::writev(fd, iov.as_ptr(), iov.len() as libc::c_int) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    // Report only the IP bytes written (exclude the AF header).
                    Ok((n as usize).saturating_sub(AF_HEADER_LEN))
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

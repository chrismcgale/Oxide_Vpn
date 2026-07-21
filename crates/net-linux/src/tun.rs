//! Linux TUN device via `/dev/net/tun`.
//!
//! We open the clone device, issue `TUNSETIFF` to create/attach a named layer-3
//! (`IFF_TUN`) interface with no packet-info prefix (`IFF_NO_PI`), then drive the fd
//! asynchronously through tokio's `AsyncFd`. The interface is non-persistent: it
//! vanishes when the fd is dropped, which suits the RAM-only / leave-no-trace posture.
//!
//! This is the one piece that must be an in-process file descriptor; addressing,
//! routing, and NAT are done with `ip`/`nft` in the sibling modules.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use tokio::io::unix::AsyncFd;

use oxide_common::TunQueue;

// From <linux/if_tun.h> / <net/if.h>.
const IFNAMSIZ: usize = 16;
const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
// TUNSETIFF = _IOW('T', 202, int) on Linux (constant across common arches).
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// Kernel `struct ifreq` (40 bytes on LP64). We only touch the name and flags.
#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    flags: i16,
    _pad: [u8; 22],
}

pub struct TunDevice {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl TunDevice {
    /// Create (or attach to) a TUN interface named `name` (e.g. `oxide0`).
    pub fn create(name: &str) -> io::Result<Self> {
        if name.len() >= IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tun interface name too long",
            ));
        }

        // SAFETY: standard open() of the clone device.
        let raw: RawFd = unsafe {
            libc::open(
                c"/dev/net/tun".as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a fresh, owned, valid fd.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut req = IfReq {
            name: [0u8; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };
        req.name[..name.len()].copy_from_slice(name.as_bytes());

        // SAFETY: valid fd and a correctly-sized ifreq pointer.
        let rc = unsafe { libc::ioctl(owned.as_raw_fd(), TUNSETIFF, &mut req as *mut IfReq) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(TunDevice {
            fd: AsyncFd::new(owned)?,
            name: name.to_string(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl TunQueue for TunDevice {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // SAFETY: fd is valid; buf is a valid writable slice.
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // SAFETY: fd is valid; buf is a valid readable slice.
                let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

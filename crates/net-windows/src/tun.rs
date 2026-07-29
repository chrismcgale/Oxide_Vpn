//! Windows TUN device via **Wintun**.
//!
//! **Scaffold.** Windows has no `/dev/net/tun`; the standard userspace TUN is Wintun (the DLL
//! WireGuard ships): load `wintun.dll`, create/open an adapter, start a session, and read/write
//! packets through its ring buffers. A read blocks on an event, so the async [`oxide_common::
//! TunQueue`] would drive a dedicated blocking thread bridged to tokio (or IOCP). Use the
//! `wintun` crate. Until that's implemented + verified on Windows, `create` and the I/O methods
//! return `ErrorKind::Unsupported` so the client links/cross-compiles but can't run. `TODO(windows)`.

use std::io;

use oxide_common::TunQueue;

fn unsupported(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("Windows TUN {what}: not yet implemented (TODO: Wintun via the `wintun` crate)"),
    )
}

pub struct TunDevice {
    name: String,
}

impl TunDevice {
    /// Create/open a Wintun adapter named `name`. Not yet implemented (see the module note).
    pub fn create(_name: &str) -> io::Result<Self> {
        Err(unsupported("create adapter"))
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl TunQueue for TunDevice {
    async fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(unsupported("read"))
    }

    async fn send(&self, _buf: &[u8]) -> io::Result<usize> {
        Err(unsupported("write"))
    }
}

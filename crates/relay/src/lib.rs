//! UDP relay for multihop entry servers.
//!
//! In Oxide (like Mullvad), multihop is not onion encryption — the client runs a single
//! WireGuard tunnel to the **exit** server's key but sends the ciphertext to the
//! **entry** server, which blindly forwards it to the exit. The entry sees the client's
//! address but only WireGuard ciphertext it can't decrypt; the exit sees the destination
//! but the traffic appears to originate from the entry. No single server sees both ends.
//!
//! This relay is that forwarder. It listens on a port dedicated to one exit and, for
//! each distinct client source address, opens a private upstream socket to the exit
//! (a UDP-NAT flow). Replies from the exit are sent back to the client **through the
//! listen socket**, so from the client's point of view the peer endpoint is always
//! `entry:listen_port` — exactly what its WireGuard session expects.
//!
//! Pure tokio UDP: no root, no privileges, unit-testable over loopback.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, warn};

const BUF: usize = 2048;
/// Drop a client flow after this much inactivity.
const IDLE_TIMEOUT: Duration = Duration::from_secs(180);
/// How often to sweep idle flows.
const REAP_INTERVAL: Duration = Duration::from_secs(30);

struct Flow {
    upstream: Arc<UdpSocket>,
    pump: tokio::task::AbortHandle,
    last_seen: Instant,
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

/// A relay forwarding one entry port to one exit endpoint.
pub struct Relay {
    listen: Arc<UdpSocket>,
    exit: SocketAddr,
}

impl Relay {
    /// Bind the listen socket. Use `local_addr` afterward to learn the port when binding
    /// to `:0`.
    pub async fn bind(listen_addr: impl ToSocketAddrs, exit: SocketAddr) -> io::Result<Self> {
        let listen = UdpSocket::bind(listen_addr).await?;
        Ok(Relay {
            listen: Arc::new(listen),
            exit,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listen.local_addr()
    }

    /// Run the relay forever, forwarding client<->exit datagrams.
    pub async fn run(self) -> io::Result<()> {
        let flows: Arc<Mutex<HashMap<SocketAddr, Flow>>> = Arc::new(Mutex::new(HashMap::new()));
        spawn_reaper(flows.clone());

        let mut buf = [0u8; BUF];
        loop {
            let (n, client) = self.listen.recv_from(&mut buf).await?;

            let upstream = {
                let mut map = flows.lock().await;
                match map.get_mut(&client) {
                    Some(flow) => {
                        flow.last_seen = Instant::now();
                        flow.upstream.clone()
                    }
                    None => match self.new_flow(client, &mut map).await {
                        Some(up) => up,
                        None => continue,
                    },
                }
            };

            if let Err(e) = upstream.send(&buf[..n]).await {
                warn!(%client, ?e, "relay: forward to exit failed");
            }
        }
    }

    /// Create a new client flow: a private upstream socket connected to the exit, plus a
    /// pump task copying exit replies back to the client via the listen socket.
    async fn new_flow(
        &self,
        client: SocketAddr,
        map: &mut HashMap<SocketAddr, Flow>,
    ) -> Option<Arc<UdpSocket>> {
        let upstream = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                warn!(?e, "relay: upstream bind failed");
                return None;
            }
        };
        if let Err(e) = upstream.connect(self.exit).await {
            warn!(exit = %self.exit, ?e, "relay: upstream connect failed");
            return None;
        }
        let upstream = Arc::new(upstream);

        let listen = self.listen.clone();
        let up = upstream.clone();
        let pump = tokio::spawn(async move {
            let mut b = [0u8; BUF];
            // Reply to the client through the LISTEN socket, so the client sees it
            // coming from entry:listen_port (its WG endpoint).
            while let Ok(m) = up.recv(&mut b).await {
                let _ = listen.send_to(&b[..m], client).await;
            }
        });

        map.insert(
            client,
            Flow {
                upstream: upstream.clone(),
                pump: pump.abort_handle(),
                last_seen: Instant::now(),
            },
        );
        debug!(%client, exit = %self.exit, "relay: new flow");
        Some(upstream)
    }
}

fn spawn_reaper(flows: Arc<Mutex<HashMap<SocketAddr, Flow>>>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REAP_INTERVAL);
        loop {
            tick.tick().await;
            let mut map = flows.lock().await;
            // Dropping a Flow aborts its pump task.
            map.retain(|_, flow| flow.last_seen.elapsed() < IDLE_TIMEOUT);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Client -> relay -> exit and back; the client must see replies from the relay.
    #[tokio::test]
    async fn relay_forwards_both_ways() {
        // Exit: a UDP echo server.
        let exit = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let exit_addr = exit.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; BUF];
            loop {
                let (n, src) = exit.recv_from(&mut b).await.unwrap();
                let _ = exit.send_to(&b[..n], src).await;
            }
        });

        let relay = Relay::bind("127.0.0.1:0", exit_addr).await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        tokio::spawn(relay.run());

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(b"ping-through-relay", relay_addr)
            .await
            .unwrap();

        let mut b = [0u8; BUF];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut b))
            .await
            .expect("relay round-trip timed out")
            .unwrap();
        assert_eq!(&b[..n], b"ping-through-relay");
        // Crucial: the reply appears to come from the relay, not the exit.
        assert_eq!(from, relay_addr);
    }

    #[tokio::test]
    async fn two_clients_are_isolated() {
        // Exit echoes back the source port it saw, so we can tell flows apart.
        let exit = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let exit_addr = exit.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; BUF];
            loop {
                let (_n, src) = exit.recv_from(&mut b).await.unwrap();
                let msg = format!("seen:{}", src.port());
                let _ = exit.send_to(msg.as_bytes(), src).await;
            }
        });

        let relay = Relay::bind("127.0.0.1:0", exit_addr).await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        tokio::spawn(relay.run());

        let c1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let c2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        c1.send_to(b"a", relay_addr).await.unwrap();
        c2.send_to(b"b", relay_addr).await.unwrap();

        let mut b = [0u8; BUF];
        let (n1, f1) = tokio::time::timeout(Duration::from_secs(2), c1.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        let seen1 = String::from_utf8_lossy(&b[..n1]).into_owned();
        let (n2, f2) = tokio::time::timeout(Duration::from_secs(2), c2.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        let seen2 = String::from_utf8_lossy(&b[..n2]).into_owned();

        // Both replies come from the relay, and each client's flow used a distinct
        // upstream source port (so the exit could tell them apart).
        assert_eq!(f1, relay_addr);
        assert_eq!(f2, relay_addr);
        assert_ne!(seen1, seen2);
    }
}

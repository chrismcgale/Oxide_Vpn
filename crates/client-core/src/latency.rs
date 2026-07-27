//! No-root latency estimation to a VPN server ("TCP ping").
//!
//! We can't ICMP-ping without privileges, and a WireGuard endpoint is UDP (no reply to a bare
//! probe), so we time a **TCP connect** to the endpoint host:port instead. A server that answers
//! *or* refuses the connection does so after roughly one network round-trip, so both outcomes
//! yield a usable RTT; only a timeout (host unreachable / silently dropped) counts as "no
//! measurement". It's an estimate for ranking servers, not a precise path RTT.

use std::time::Duration;

use tokio::net::TcpStream;

/// Default probe timeout — beyond this a server is treated as unreachable for ranking.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1500);

/// Time a TCP connect to `endpoint` (`host:port`). Returns the round-trip estimate, or `None`
/// if the probe timed out or the host couldn't be resolved. A refused connection still counts:
/// the refusal itself came back over the network, so its timing is a valid RTT.
pub async fn tcp_ping(endpoint: &str, timeout: Duration) -> Option<Duration> {
    let start = tokio::time::Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(endpoint)).await {
        // Connected within the window.
        Ok(Ok(_stream)) => Some(start.elapsed()),
        // The connect resolved to an error. A refusal means the host answered (reachable);
        // a resolution failure means we never got on the network (not a latency signal).
        Ok(Err(e)) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset => {
                Some(start.elapsed())
            }
            _ => None,
        },
        // Timed out: unreachable for our purposes.
        Err(_elapsed) => None,
    }
}

/// Format a latency measurement for a compact status column.
pub fn format_latency(rtt: Option<Duration>) -> String {
    match rtt {
        Some(d) => format!("{}ms", d.as_millis()),
        None => "—".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ping_measures_a_reachable_listener() {
        // A bound-but-unaccepted listener still completes the TCP handshake, so connect succeeds.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let rtt = tcp_ping(&addr.to_string(), DEFAULT_TIMEOUT).await;
        assert!(rtt.is_some(), "loopback listener should be reachable");
    }

    #[tokio::test]
    async fn ping_counts_a_refused_port_as_reachable() {
        // Bind then drop to get a port nobody is listening on: the OS replies RST (refused),
        // which is a real round-trip, so we still record a measurement.
        let addr = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let rtt = tcp_ping(&addr.to_string(), DEFAULT_TIMEOUT).await;
        assert!(rtt.is_some(), "a refused loopback port is still reachable");
    }

    #[test]
    fn format_latency_renders() {
        assert_eq!(format_latency(Some(Duration::from_millis(42))), "42ms");
        assert_eq!(format_latency(None), "—");
    }
}

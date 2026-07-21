//! TLS-mimicry transport: carry the tunnel inside a flow that looks like HTTPS.
//!
//! Presents the same datagram `send_to`/`recv_from` interface the engine expects, but
//! over TCP with a mimicked TLS 1.3 handshake ([`oxide_mimicry`]) and each datagram
//! wrapped as a TLS `application_data` record. Payloads are obfuscated ([`oxide_obfs`])
//! first, so the record contents are high-entropy like real TLS. To a censor the flow is
//! a TCP:443 connection with a TLS ClientHello (SNI included), a ServerHello, and a
//! stream of application_data — i.e. someone browsing a website.
//!
//! Client side: one TCP stream to the server. Server side: an accept loop that
//! demultiplexes many client connections back into the engine's per-peer model, keyed by
//! the client's TCP source address.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::debug;

use oxide_mimicry::{
    client_hello, frame_app_data, read_record, server_hello, REC_APPLICATION_DATA,
};
use oxide_obfs::{deobfuscate, obfuscate};

/// The hostname we pretend to be visiting. A high-reputation domain a censor is unlikely
/// to block wholesale.
const SNI: &str = "www.cloudflare.com";

const READ_CHUNK: usize = 4096;

pub struct MimicTransport {
    inner: Inner,
}

enum Inner {
    Client(ClientSide),
    Server(ServerSide),
}

struct ClientSide {
    write: Mutex<OwnedWriteHalf>,
    reader: Mutex<Reader>,
    key: [u8; 32],
    peer: SocketAddr,
}

struct Reader {
    half: OwnedReadHalf,
    acc: Vec<u8>,
}

type OutMap = Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>;

struct ServerSide {
    inbound: Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
    outbound: OutMap,
    local_addr: SocketAddr,
    key: [u8; 32],
}

impl MimicTransport {
    /// Connect to `server` and send the mimicked ClientHello.
    pub async fn connect(server: SocketAddr, key: [u8; 32]) -> io::Result<Self> {
        let stream = TcpStream::connect(server).await?;
        let _ = stream.set_nodelay(true);
        let (read, mut write) = stream.into_split();
        write.write_all(&client_hello(SNI)).await?;
        Ok(MimicTransport {
            inner: Inner::Client(ClientSide {
                write: Mutex::new(write),
                reader: Mutex::new(Reader {
                    half: read,
                    acc: Vec::new(),
                }),
                key,
                peer: server,
            }),
        })
    }

    /// Listen on `addr`, accepting mimicked TLS connections from clients.
    pub async fn bind(addr: SocketAddr, key: [u8; 32]) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let outbound: OutMap = Arc::new(Mutex::new(HashMap::new()));

        let out_accept = outbound.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let _ = stream.set_nodelay(true);
                let (read, write) = stream.into_split();
                let (out_tx, out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                out_accept.lock().await.insert(peer, out_tx.clone());
                // Respond with a mimicked ServerHello.
                let _ = out_tx.send(server_hello());
                tokio::spawn(writer_task(write, out_rx));
                tokio::spawn(reader_task(
                    read,
                    peer,
                    key,
                    in_tx.clone(),
                    out_accept.clone(),
                ));
                debug!(%peer, "mimic: accepted TLS-looking connection");
            }
        });

        Ok(MimicTransport {
            inner: Inner::Server(ServerSide {
                inbound: Mutex::new(in_rx),
                outbound,
                local_addr,
                key,
            }),
        })
    }

    /// The bound address (server side only).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        match &self.inner {
            Inner::Server(s) => Some(s.local_addr),
            Inner::Client(_) => None,
        }
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        match &self.inner {
            Inner::Client(c) => {
                let framed = frame_app_data(&obfuscate(&c.key, buf));
                c.write.lock().await.write_all(&framed).await?;
                Ok(buf.len())
            }
            Inner::Server(s) => {
                let framed = frame_app_data(&obfuscate(&s.key, buf));
                if let Some(tx) = s.outbound.lock().await.get(&addr) {
                    let _ = tx.send(framed);
                }
                Ok(buf.len())
            }
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match &self.inner {
            Inner::Client(c) => {
                let mut r = c.reader.lock().await;
                loop {
                    if let Some((consumed, ct, payload)) = read_record(&r.acc) {
                        r.acc.drain(..consumed);
                        // Only application_data carries our datagrams; skip the server's
                        // handshake / change_cipher_spec / fake-cert records.
                        if ct == REC_APPLICATION_DATA {
                            if let Some(data) = deobfuscate(&c.key, &payload) {
                                let n = data.len().min(buf.len());
                                buf[..n].copy_from_slice(&data[..n]);
                                return Ok((n, c.peer));
                            }
                        }
                        continue;
                    }
                    let mut tmp = [0u8; READ_CHUNK];
                    let n = r.half.read(&mut tmp).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "mimic stream closed",
                        ));
                    }
                    r.acc.extend_from_slice(&tmp[..n]);
                }
            }
            Inner::Server(s) => match s.inbound.lock().await.recv().await {
                Some((data, addr)) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok((n, addr))
                }
                None => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "mimic inbound closed",
                )),
            },
        }
    }
}

/// Drain framed byte blobs to the socket.
async fn writer_task(mut write: OwnedWriteHalf, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(bytes) = rx.recv().await {
        if write.write_all(&bytes).await.is_err() {
            break;
        }
    }
}

/// Read TLS records from one client, decode application_data into datagrams, and forward
/// them (tagged with the client's address) to the shared inbound channel.
async fn reader_task(
    mut read: OwnedReadHalf,
    peer: SocketAddr,
    key: [u8; 32],
    in_tx: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
    outbound: OutMap,
) {
    let mut acc: Vec<u8> = Vec::new();
    let mut tmp = [0u8; READ_CHUNK];
    loop {
        while let Some((consumed, ct, payload)) = read_record(&acc) {
            acc.drain(..consumed);
            if ct == REC_APPLICATION_DATA {
                if let Some(data) = deobfuscate(&key, &payload) {
                    if in_tx.send((data, peer)).is_err() {
                        return;
                    }
                }
            }
            // else: skip the client's ClientHello / other handshake records.
        }
        match read.read(&mut tmp).await {
            Ok(0) | Err(_) => {
                outbound.lock().await.remove(&peer);
                return;
            }
            Ok(n) => acc.extend_from_slice(&tmp[..n]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A passive observer of the client's first bytes must see a TLS ClientHello.
    #[tokio::test]
    async fn client_first_bytes_look_like_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sniff = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 128];
            let n = stream.read(&mut buf).await.unwrap();
            buf[..n].to_vec()
        });

        let _client = MimicTransport::connect(addr, [1u8; 32]).await.unwrap();
        let first = sniff.await.unwrap();

        // TLS handshake record + ClientHello + the SNI on the wire.
        assert_eq!(first[0], 0x16);
        assert_eq!(&first[1..3], &[0x03, 0x01]);
        assert_eq!(first[5], 0x01);
        assert!(first.windows(SNI.len()).any(|w| w == SNI.as_bytes()));
    }
}

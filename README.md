# Oxide VPN

A WireGuard-based VPN platform written in Rust, built on
[boringtun](https://github.com/cloudflare/boringtun) and modeled on the architecture
of NordLynx / Mullvad. Linux-first.

The data plane speaks standard WireGuard (Noise_IKpsk2, ChaCha20-Poly1305, UDP) and
interoperates with stock `wg` tooling. Everything above the tunnel — the control plane,
privacy features, clients, and ops — is what Oxide builds on top.

## Status

**Milestone 1 complete:** a real single tunnel. Server and client daemons establish a
genuine WireGuard handshake, create TUN devices, route traffic across the encrypted
tunnel, and (optionally) provide full-tunnel internet egress via NAT.

**Milestone 2 complete:** the control plane. Anonymous account numbers (Mullvad-style,
no email/PII), a device-registration API that allocates tunnel IPs, and a server that
pulls its peer list from the control plane and reconciles it into the live engine.

**Milestone 3 complete:** multi-server selection and load balancing. Servers advertise
location and capacity and heartbeat their live load; the control plane picks the
least-loaded healthy server (optionally filtered by country/city), and the client can
auto-select instead of naming a server.

**Milestone 4 complete:** privacy / leak prevention. An opt-in kill switch blocks all
non-tunnel traffic (so nothing leaks if the tunnel drops), DNS leak protection points
the resolver at the tunnel DNS while connected, and the data plane is audited to keep
nothing on disk and log no client PII.

**Verifiable no-logs:** the no-logs claim is *enforced and provable*, not just asserted. An
optional seccomp filter (`[hardening] no_disk_writes`) makes the server process physically
**unable to create or write files** — so it can't log to disk even if compromised. And an
Ed25519 **signed build manifest** (the binary's SHA-256 + git commit, verified against a
pinned release key) plus a hash-chained **transparency log** of deployed builds let a client
confirm its server runs the exact audited build — verify the binary, don't trust the promise.

**Multihop complete:** the client runs one WireGuard session keyed to an *exit* server
but sends it through an *entry* server that relays the (still-encrypted) traffic — so no
single server sees both your IP and your destination. Done the WireGuard-native way (the
entry is a UDP relay), not onion encryption, so the tunnel stays single-encryption.

**Mesh hybrid ("Tailscale, but actually private"):** your own devices form a private
WireGuard peer-to-peer overlay, coordinated by the control plane. Each device joins the
account's mesh (`oxide-client mesh`), gets a stable mesh IP, and reaches your other
devices directly — no traffic through a server. Because the mesh carries only its own
subnet, it composes with a full-tunnel `connect` for anonymous egress: a private device
overlay *and* an anonymous exit at once, which no incumbent offers.

**Stealth mode:** an optional obfuscation layer wraps every WireGuard datagram in a
ChaCha20 keystream (random nonce + size-bucket padding) so deep-packet inspection can't
fingerprint or block it. On top of that, protocol mimicry makes the flow look like
ordinary web traffic — **TLS-over-TCP** (looks like HTTPS) or **QUIC-over-UDP** (looks
like HTTP/3, UDP-native and preferred) — for use where WireGuard is censored. Under active
probing the QUIC server goes further: an unauthenticated probe isn't dropped (a dead port
is itself a signal) but **decoy-forwarded** to a real TLS/QUIC backend, so the port answers
exactly like the ordinary web server it pretends to be. Pick the transport per interface
(`transport = "plain" | "obfs" | "quic" | "mimic"`).

**Traffic-analysis defense (DAITA):** on top of size-bucket padding, an optional shaper
turns the client's egress into a constant-rate stream of fixed-size **cells** — one per
fixed slot, with **cover** cells filling idle slots — so a passive/ML observer (or even
our own multihop entry) sees only steady, contentless volume, no bursts or gaps. It's an
honest padding+rate defense with a constant bandwidth cost (`cell_size × 8 / slot`), not a
learned framework; cover rides inside the obfs frame and is dropped before WireGuard.

**Post-quantum (core):** an ML-KEM (Kyber) exchange derives a shared secret used as the
WireGuard preshared key, so the tunnel is protected by x25519 *and* a quantum-resistant
KEM — additive, so it can only strengthen security.

Roadmap: desktop/mobile clients, and fleet ops (Postgres, provisioning, DoS hardening).

## Quick start

```bash
# Build
cargo build

# Generate a keypair (interoperable with `wg genkey`/`wg pubkey`)
cargo run -p oxide-serverd -- genkey

# End-to-end test on one host (two network namespaces; needs root)
sudo bash scripts/netns-test.sh
```

Config templates live in `configs/`. Operational details are in the project runbook at
`.claude/skills/oxide-vpn/SKILL.md`.

## Workspace layout

| Crate | Role |
|-------|------|
| `crates/common` | Key types, TOML config, error, `TunQueue`, account numbers, API DTOs |
| `crates/wg-core` | The boringtun-based tunnel engine, runtime-mutable peers (OS-agnostic) |
| `crates/net-linux` | Linux TUN device, routing, NAT, sysctls |
| `crates/control-plane` | Accounts/devices/servers API, selection, multihop, mesh (axum + SQLite) |
| `crates/control-client` | HTTP client for the control-plane API |
| `crates/relay` | UDP relay for multihop entry servers |
| `crates/obfs` | Stealth-mode obfuscation codec (anti-DPI) |
| `crates/daita` | Traffic-analysis defense: constant-rate cell shaper + cover traffic |
| `crates/seccomp` | Enforced no-logs: seccomp filter making the process unable to write to disk |
| `crates/attest` | Verifiable build identity: signed build manifest + transparency log |
| `crates/mimicry` | Protocol mimicry: TLS-over-TCP (HTTPS) + QUIC-over-UDP (HTTP/3) |
| `crates/pq` | Post-quantum (ML-KEM) key agreement for a hybrid PSK |
| `crates/oxide-serverd` | Server daemon (static peers or control-plane-managed) |
| `crates/client-core` | Shared client tunnel logic (resolve + run) |
| `crates/oxide-client` | Client CLI (static config or control-plane connect) |
| `crates/oxide-agentd` | Privileged agent: owns the tunnel, Unix-socket control API |
| `crates/oxide-tui` | Unprivileged terminal UI (ratatui) |

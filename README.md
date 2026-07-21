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

Roadmap (M4–M6): privacy features (kill switch, DNS leak protection, no-logs/RAM-only,
multihop), desktop clients, and fleet ops (Postgres, provisioning, DoS hardening).

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
| `crates/control-plane` | Accounts/devices/servers API (axum + SQLite) |
| `crates/control-client` | HTTP client for the control-plane API |
| `crates/oxide-serverd` | Server daemon (static peers or control-plane-managed) |
| `crates/oxide-client` | Client daemon (static config or control-plane connect) |

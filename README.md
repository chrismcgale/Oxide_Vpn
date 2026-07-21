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
tunnel, and (optionally) provide full-tunnel internet egress via NAT. Static config;
no control plane yet.

Roadmap (M2–M6): control plane (auth, server list, ephemeral keys), multi-server
selection, privacy features (kill switch, DNS leak protection, no-logs/RAM-only,
multihop), desktop clients, and fleet ops.

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
| `crates/common` | Key types, TOML config, error, the `TunQueue` trait |
| `crates/wg-core` | The boringtun-based tunnel engine (OS-agnostic) |
| `crates/net-linux` | Linux TUN device, routing, NAT, sysctls |
| `crates/oxide-serverd` | Server daemon |
| `crates/oxide-client` | Client daemon |

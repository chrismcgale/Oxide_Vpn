---
name: oxide-vpn
description: Operational runbook for the Oxide VPN — a WireGuard-based (boringtun) VPN platform in Rust. Run, debug, architecture pointer, gotchas, changelog.
---

# Oxide VPN runbook

A WireGuard data plane (via **boringtun**) with an Oxide-built control/privacy/ops
layer on top. Modeled on Mullvad / NordLynx. Linux-first. See the plan at
`/home/archriso/.claude/plans/wobbly-splashing-puddle.md` for the full M1–M6 roadmap.

Toolchain note: Rust is installed via **rustup** in `~/.cargo` (not a system package).
Run `. "$HOME/.cargo/env"` first in a fresh shell, or use `~/.cargo/bin/cargo`.

## Run

```bash
cargo build                       # whole workspace
cargo test --workspace            # unit tests (keys, config, router)
cargo clippy --workspace

# Key management (interoperable with `wg genkey`/`wg pubkey`):
cargo run -p oxide-serverd -- genkey                 # print a private key
echo "<privkey>" | cargo run -p oxide-serverd -- pubkey

# Run (needs root / CAP_NET_ADMIN):
sudo target/debug/oxide-serverd up --config server.toml
sudo target/debug/oxide-client  up --config client.toml
```

Config templates: `configs/server.toml.example`, `configs/client.toml.example`.
Put real configs somewhere gitignored (`*.local.toml` or `run/`).

## Verify (end-to-end)

No-root core test — two `Engine`s over loopback UDP with a mock TUN drive the real
boringtun handshake + encapsulation + routing end to end:

```bash
cargo test -p oxide-wg-core --test tunnel   # tests/tunnel.rs
```

Fastest full (privileged) test — two network namespaces on one host, real handshake +
ping across the tunnel:

```bash
sudo bash scripts/netns-test.sh      # prints PASS/PASS ✗ and both daemon logs
```

Manual two-host verification (Milestone 1 definition of done):
- **A handshake:** `ip addr show oxide0`; `tcpdump -ni <wan> udp port 51820` shows WG init/response.
- **B tunnel ping:** ping the peer's tunnel IP; `tcpdump -i oxide0 icmp` shows plaintext ICMP while `<wan>` shows only encrypted UDP.
- **C full tunnel:** from the client, `curl ifconfig.co` returns the **server's** IP; `nft list ruleset` shows the `oxide` masquerade table; `ip route get 1.1.1.1` resolves via `oxide0`.
- **D interop:** our key derivation matches stock `wg pubkey` (verified in CI-style check). A stock `wg` peer should handshake with our daemon.

## Debug / common errors

- **`Operation not permitted` bringing up tun** — not root / missing `CAP_NET_ADMIN`. Run under `sudo`.
- **Handshake never completes** — check the timer task is ticking (boringtun needs `update_timers` on a cadence — see `wg-core/src/engine.rs::timer_loop`). Confirm UDP reaches `:51820` (firewall). Confirm keys: client's `[[peer]].public_key` must be the server's public key and vice-versa.
- **Ping works but curl/large transfers hang** — MTU. Interface MTU must be 1420; if a path is smaller, lower it. Classic PMTU black hole; MSS clamping is an M5 item.
- **Full tunnel connects then the connection dies** — the encrypted UDP is routing into the tunnel. The client pins a `/32` host route to the server endpoint via the original gateway *before* swinging the default (`netlink::add_host_route_via`). Verify with `ip route get <server-ip>`.
- **NAT egress silently drops replies** — strict `rp_filter`. We set it to loose (2); confirm `sysctl net.ipv4.conf.all.rp_filter`.
- **`nft` table left behind after a crash** — `sudo nft delete table inet oxide`.

## Architecture (brief)

Cargo workspace, `crates/`:
- **`common`** — key newtypes (zeroizing, base64, `wg`-compatible), TOML config, error, the `TunQueue` trait. No tokio/OS deps.
- **`wg-core`** — the engine: wraps boringtun `Tunn`; three tokio tasks (outbound TUN→UDP, inbound UDP→TUN, 250ms timers) sharing `Arc<Shared>`; allowed-IPs router. OS-agnostic (talks to TUN via `TunQueue`).
- **`net-linux`** — privileged Linux bits: TUN `ioctl` + `AsyncFd`; `ip`/`nft`/`sysctl` wrappers. (Shell-outs now; netlink/nftables libs are M5.)
- **`oxide-serverd` / `oxide-client`** — thin daemons: config → engine → net-linux; Ctrl-C tears down host state.

Data flow and boringtun contracts are documented at the top of `crates/wg-core/src/engine.rs`.

## Gotchas

- **boringtun contract 1:** `update_timers` MUST be called on a ticker or handshakes never retry.
- **boringtun contract 2:** after `decapsulate` returns `WriteToNetwork`, keep calling `decapsulate(None, &[], buf)` until `Done`, sending each datagram.
- **Never hold the `Tunn` mutex across `.await`** — it's a blocking `std::sync::Mutex`; lock, run one boringtun call into a stack buffer, copy out, unlock, then await I/O.
- **Peer demux is by source-address cache with an all-peers fallback** (M1). A proper receiver-index table is an M2 refinement; matters once one server has many clients.
- **No-logs posture:** the data plane keeps nothing on disk; never `tracing`-log secret key material (the `SecretKey` type refuses to print its bytes). Any persistence belongs in the control plane (M2+), never here.

## Changelog / Decisions (newest first)

- **2026-07-21 — M1 built.** Ripped out the old TCP-echo `src/` and rebuilt as a WireGuard-based workspace (boringtun 0.7). New crates: common, wg-core, net-linux, oxide-serverd, oxide-client. Real handshake, TUN devices, allowed-IPs routing, full-tunnel NAT. Key derivation verified byte-identical to `wg pubkey`.
  - Decision: **build on boringtun, not hand-rolled crypto** — matches what NordLynx/Mullvad actually ship; our value is the control/privacy/ops layer.
  - Decision: **shell out to `ip`/`nft` for M1** (like wg-quick); migrate to netlink/nftables libraries in M5. Only the TUN `ioctl` is in-process.
  - Decision: `common` owns the `TunQueue` trait so `wg-core` stays OS-agnostic and unit-testable without root.

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

# Data plane (needs root / CAP_NET_ADMIN):
sudo target/debug/oxide-serverd up --config server.toml
sudo target/debug/oxide-client  up --config client.toml

# Control plane (M2/M3 — no root; plain web service + SQLite):
target/debug/oxide-control-plane --db oxide.db add-server \
    --id us-1 --public-key <server-pubkey> --endpoint 1.2.3.4:51820 --cidr 10.8.0.0/24 \
    --country US --city "New York" --capacity 500      # M3: location + capacity
target/debug/oxide-control-plane --db oxide.db serve --listen 127.0.0.1:8080
# Client via control plane (register device, get assigned IP, connect):
target/debug/oxide-client account --control-plane http://cp:8080          # new account number
# Explicit server, or auto-select the least-loaded (optionally by location):
sudo target/debug/oxide-client connect --control-plane http://cp:8080 --account <n> --server us-1
sudo target/debug/oxide-client connect --control-plane http://cp:8080 --account <n> --country US
```

Config templates: `configs/server.toml.example`, `configs/client.toml.example`.
Put real configs somewhere gitignored (`*.local.toml` or `run/`).

## Verify (end-to-end)

No-root tests — the whole stack is exercised in userspace (mock TUN + loopback UDP +
in-process control plane):

```bash
cargo test --workspace                                  # everything (19 tests)
cargo test -p oxide-wg-core --test tunnel               # real handshake over loopback
cargo test -p oxide-control-plane --test api            # account/device/IP/peer API + server selection
cargo test -p oxide-serverd --test control_plane_flow   # CP -> reconcile -> tunnel (capstone)
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
- **`common`** — key newtypes (zeroizing, base64, `wg`-compatible), TOML config, error, the `TunQueue` trait, anonymous account numbers, and the control-plane API DTOs. No tokio/OS deps.
- **`wg-core`** — the engine: wraps boringtun `Tunn`; three tokio tasks (outbound TUN→UDP, inbound UDP→TUN, 250ms timers) sharing `Arc<Shared>`; allowed-IPs router; **runtime-mutable peer table** (`EngineHandle::{add_peer,remove_peer,reconcile}`). OS-agnostic (talks to TUN via `TunQueue`). `test-util` feature exposes a mock TUN.
- **`net-linux`** — privileged Linux bits: TUN `ioctl` + `AsyncFd`; `ip`/`nft`/`sysctl` wrappers. (Shell-outs now; netlink/nftables libs are M5.)
- **`control-plane`** — axum + sqlx(SQLite) service: accounts (anonymous numbers), devices (pubkey + assigned tunnel IP), servers (with location + capacity), IP allocation, **load-based server selection** (`GET /v1/servers/best`) fed by **server heartbeats**. Never depends on `wg-core`. `add_server` CLI + `serve`.
- **`control-client`** — thin reqwest client for the control-plane API, shared by both daemons.
- **`oxide-serverd` / `oxide-client`** — thin daemons: config → engine → net-linux; Ctrl-C tears down host state. Server optionally polls the control plane and reconciles peers live; client can `connect` via the control plane (register device → assigned IP → tunnel).

Control-plane <-> server sync: the server **polls** `GET /v1/internal/servers/{id}/peers` (token-authed) and reconciles into the live engine. The data plane keeps peer state in RAM only; the DB lives solely in the control plane.

Data flow and boringtun contracts are documented at the top of `crates/wg-core/src/engine.rs`.

## Gotchas

- **boringtun contract 1:** `update_timers` MUST be called on a ticker or handshakes never retry.
- **boringtun contract 2:** after `decapsulate` returns `WriteToNetwork`, keep calling `decapsulate(None, &[], buf)` until `Done`, sending each datagram.
- **Never hold the `Tunn` mutex across `.await`** — it's a blocking `std::sync::Mutex`; lock, run one boringtun call into a stack buffer, copy out, unlock, then await I/O.
- **Peer demux is by source-address cache with an all-peers fallback** (M1). A proper receiver-index table is an M2 refinement; matters once one server has many clients.
- **No-logs posture:** the data plane keeps nothing on disk; never `tracing`-log secret key material (the `SecretKey` type refuses to print its bytes). Any persistence belongs in the control plane (M2+), never here.

## Changelog / Decisions (newest first)

- **2026-07-21 — M3 multi-server selection built.** Servers carry location (country/city) and a soft `capacity`; they heartbeat live load (`active_peers`, derived from boringtun handshake recency via `EngineHandle::stats`) to the control plane. New `GET /v1/servers/best?country=&city=` picks the least-loaded healthy server (load factor = active/capacity); `oxide-client connect` auto-selects when `--server` is omitted (with `--country`/`--city` filters). `oxide-serverd`'s poll loop now also heartbeats. Verified without root (selection test + HTTP smoke test showing the pick flip as load shifts). 20 tests, clippy clean.
  - Decision: **load = live heartbeated active-peer count**, not registered device count — registrations aren't connections. A server that has never heartbeated is treated as healthy (may not run the loop); staleness (>90s) applies once it starts.
  - Note: `wg-core` stayed API-additive (just `stats()`), as the roadmap intended.

- **2026-07-21 — M2 control plane v0 built.** New crates `control-plane` (axum + sqlx/SQLite) and `control-client`. Anonymous account numbers (Mullvad-style, no PII), device registration with per-server tunnel-IP allocation, and a token-authed peer-list endpoint. `wg-core` peer table is now runtime-mutable (`EngineHandle::reconcile`); `oxide-serverd` polls the control plane and reconciles live; `oxide-client connect` registers a device and connects. Verified end-to-end without root: control-plane API test, runtime-reconcile test, and a capstone `control_plane_flow` test that drives a real tunnel from a control-plane-provisioned device. 19 tests, clippy clean.
  - Decision: **anonymous account numbers** — the number is the whole credential; no email/PII, minimal stored identity (on-brand for the Mullvad privacy goal).
  - Decision: **SQLite for v0, Postgres for a fleet.** SQLite is single-writer/single-node; fine and zero-infra now, but a multi-node API tier (M6) needs a networked DB. All access is via sqlx runtime queries so the swap is mechanical.
  - Decision: **server polls the control plane** (rather than CP pushing) — keeps the data plane a pull-based, stateless-on-disk consumer that holds peers in RAM only.
  - Decision: **`control-plane` never depends on `wg-core`** (enforced by layering); shared wire types live in `common::api`.

- **2026-07-21 — M1 built.** Ripped out the old TCP-echo `src/` and rebuilt as a WireGuard-based workspace (boringtun 0.7). New crates: common, wg-core, net-linux, oxide-serverd, oxide-client. Real handshake, TUN devices, allowed-IPs routing, full-tunnel NAT. Key derivation verified byte-identical to `wg pubkey`.
  - Decision: **build on boringtun, not hand-rolled crypto** — matches what NordLynx/Mullvad actually ship; our value is the control/privacy/ops layer.
  - Decision: **shell out to `ip`/`nft` for M1** (like wg-quick); migrate to netlink/nftables libraries in M5. Only the TUN `ioctl` is in-process.
  - Decision: `common` owns the `TunQueue` trait so `wg-core` stays OS-agnostic and unit-testable without root.

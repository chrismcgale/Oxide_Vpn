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
# Multihop: tunnel to the exit through an entry relay (entry auto-picked if omitted):
sudo target/debug/oxide-client connect --control-plane http://cp:8080 --account <n> --exit se-1 --entry de-1
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
cargo test -p oxide-serverd --test multihop_flow        # client -> entry relay -> exit (multihop capstone)
cargo test -p oxide-relay                               # UDP relay forwarding + flow isolation
cargo test -p oxide-obfs                                # obfuscation codec
cargo test -p oxide-wg-core --test tunnel tunnel_works_over_obfuscated_transport  # stealth capstone
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
- **Ping works but curl/large transfers hang** — MTU / PMTU black hole. The NAT ruleset now MSS-clamps forwarded TCP to the route MTU (`nat.rs`), which fixes the common case. If it persists, lower the tunnel MTU (and lower it further under stealth).
- **Full tunnel connects then the connection dies** — the encrypted UDP is routing into the tunnel. The client pins a `/32` host route to the server endpoint via the original gateway *before* swinging the default (`netlink::add_host_route_via`). Verify with `ip route get <server-ip>`.
- **NAT egress silently drops replies** — strict `rp_filter`. We set it to loose (2); confirm `sysctl net.ipv4.conf.all.rp_filter`.
- **`nft` table left behind after a crash** — `sudo nft delete table inet oxide` (NAT) or `sudo nft delete table inet oxide-ks` (kill switch).
- **Kill switch locked me out / SSH froze** — the kill switch drops all non-tunnel output. On a remote box this can cut your session. Remove it with `sudo nft delete table inet oxide-ks`. It only permits loopback, the tunnel, and UDP to the server endpoint.
- **DNS didn't change / reverted** — `systemd-resolved` or NetworkManager may own `/etc/resolv.conf` and rewrite it; our direct swap is best-effort until a resolved-aware backend exists.

## Architecture (brief)

Cargo workspace, `crates/`:
- **`common`** — key newtypes (zeroizing, base64, `wg`-compatible), TOML config, error, the `TunQueue` trait, anonymous account numbers, and the control-plane API DTOs. No tokio/OS deps.
- **`wg-core`** — the engine: wraps boringtun `Tunn`; three tokio tasks (outbound TUN→UDP, inbound UDP→TUN, 250ms timers) sharing `Arc<Shared>`; allowed-IPs router; **runtime-mutable peer table** (`EngineHandle::{add_peer,remove_peer,reconcile}`). OS-agnostic (talks to TUN via `TunQueue`). `test-util` feature exposes a mock TUN.
- **`net-linux`** — privileged Linux bits: TUN `ioctl` + `AsyncFd`; **link/addr/route via real netlink** (`netlink.rs`, rtnetlink — `Netlink` handle, async, family-agnostic so IPv6 works); `nft` (NAT + kill switch) and `sysctl` still shell out; **DNS leak protection** (`dns.rs`). `bring_up_interface` is async and returns the link index.
- **`control-plane`** — axum + sqlx(SQLite) service: accounts (anonymous numbers), devices (pubkey + assigned tunnel IP), servers (with location + capacity), IP allocation, **load-based server selection** (`GET /v1/servers/best`) fed by **server heartbeats**. Never depends on `wg-core`. `add_server` CLI + `serve`.
- **`control-client`** — thin reqwest client for the control-plane API, shared by both daemons.
- **`relay`** — a pure-tokio UDP relay used by **multihop** entry servers: forwards a client's WireGuard ciphertext to the exit server (per-client upstream flows), so no single server sees both the client's IP and its destination. No root; unit-tested over loopback.
- **`pq`** — **post-quantum** key agreement (ML-KEM-768 via `ml-kem`). `generate`/`encapsulate`/`decapsulate` produce a 32-byte shared secret used as the WireGuard **PSK**, layered on top of x25519 — strictly additive/hybrid (can only strengthen; a flaw in the unaudited ML-KEM can't weaken the classical security). Pure; unit-tested. Capstone: a real tunnel secured by the PQ-derived PSK.
- **`obfs`** — **stealth mode** codec: wraps each datagram as `[nonce][ChaCha20(key,nonce) XOR ([len][payload][pad])]` so DPI can't fingerprint WireGuard (no fixed header). Padding rounds the datagram up to size **buckets** (256/512/…/1472) so handshakes/keepalives/small data collapse into indistinguishable sizes — traffic-analysis resistance (size dimension). Pure; unit-tested. Used by `wg-core`'s `Transport::Obfuscated`. (Timing-based cover traffic and protocol *mimicry* — WG-in-TLS/QUIC — are the next tiers.)
- **`oxide-serverd` / `oxide-client`** — thin daemons: config → engine → net-linux; Ctrl-C tears down host state. Server optionally polls the control plane and reconciles peers live; client can `connect` via the control plane (register device → assigned IP → tunnel).

Control-plane <-> server sync: the server **polls** `GET /v1/internal/servers/{id}/peers` (token-authed) and reconciles into the live engine. The data plane keeps peer state in RAM only; the DB lives solely in the control plane.

Data flow and boringtun contracts are documented at the top of `crates/wg-core/src/engine.rs`.

## Gotchas

- **boringtun contract 1:** `update_timers` MUST be called on a ticker or handshakes never retry.
- **boringtun contract 2:** after `decapsulate` returns `WriteToNetwork`, keep calling `decapsulate(None, &[], buf)` until `Done`, sending each datagram.
- **Never hold the `Tunn` mutex across `.await`** — it's a blocking `std::sync::Mutex`; lock, run one boringtun call into a stack buffer, copy out, unlock, then await I/O.
- **Peer demux is by source-address cache with an all-peers fallback** (M1). A proper receiver-index table is an M2 refinement; matters once one server has many clients.
- **No-logs posture:** the data plane keeps nothing on disk; never `tracing`-log secret key material (the `SecretKey` type refuses to print its bytes). Any persistence belongs in the control plane (M2+), never here.

## Privacy posture (no-logs / leak prevention)

- **Kill switch** (`--kill-switch`): an nft `output` chain (policy drop) permitting only loopback, the tunnel interface, and the encrypted UDP to the server. Nothing leaks in the clear if the tunnel drops. Removed on disconnect.
- **DNS leak protection**: while connected, `/etc/resolv.conf` is repointed at the tunnel DNS (handed out by the control plane per-server, or set in client config) and restored on disconnect. Caveat: `systemd-resolved`/NetworkManager may reclaim the file — a resolved-aware backend is future work.
- **No-logs / RAM-only (audited 2026-07-21):** the data plane (`wg-core`, `oxide-serverd`, `net-linux`) performs **no disk writes** — peers live in RAM only. The engine logs no client PII at the default level (pubkeys/endpoints are `debug`-only). The control-plane DB stores only routing essentials (account numbers, device pubkeys, IP assignments) — no traffic/activity logs. Client-side disk writes are limited to the device key (0600) and the resolv.conf swap, both intentional and local.

## Changelog / Decisions (newest first)

- **2026-07-21 — Post-quantum handshake (signature feature, core).** New `pq` crate wrapping ML-KEM-768. The KEM shared secret becomes the WireGuard PSK, so the tunnel is protected by x25519 **and** ML-KEM — quantum-resistant, and strictly additive (hybrid). Verified: KEM round-trip tests + a capstone running a real WireGuard tunnel keyed by the PQ-derived PSK. 40 tests, clippy + fmt clean.
  - Decision: **hybrid via the PSK slot**, not replacing x25519 — matches Mullvad's approach and means the not-yet-audited ML-KEM impl can only add security, never subtract. ML-KEM-768 = NIST category 3. Private key stored/transported as its 64-byte seed.
  - Follow-up: distribute the PQ public key + carry the ciphertext through the control plane (ServerInfo.pq_public_key, register ciphertext, server decapsulates per-peer) so `connect` negotiates PQ automatically. The crate + PSK plumbing are done; only the distribution wiring remains.

- **2026-07-21 — Hardening: SIGTERM + MSS clamping.** Daemons now shut down cleanly on `SIGTERM` (systemd/docker), not just Ctrl-C (`net-linux::shutdown_signal`). The NAT forward chain MSS-clamps forwarded TCP to the route MTU (`tcp flags syn ... maxseg size set rt mtu`), fixing the PMTU black-hole "ping works, curl hangs" bug — and it adapts to the lower MTU used under stealth. 36 tests, clippy + fmt clean.

- **2026-07-21 — Stealth mode (signature feature).** New `obfs` crate (ChaCha20 obfuscation codec) + `wg-core` `Transport` enum (`Plain` | `Obfuscated`). The engine now sends/receives over `Transport` instead of a raw `UdpSocket`; with an `obfuscation_key` set (config field, shared client/server), every datagram is wrapped so there's no WireGuard fingerprint on the wire and undecodable probes are silently dropped. `Engine::build`/`build_server` take a `Transport`. Verified without root: codec tests + a capstone that runs a real WireGuard tunnel entirely over the obfuscated transport. 34 tests, clippy + fmt clean.
  - Decision: **obfs4/Shadowsocks-style keystream obfuscation** (defeats fingerprint-based blocking, which is how WG gets blocked), not protocol mimicry yet. Full TLS/QUIC mimicry is the next stealth tier. It's obfuscation, not AEAD — the real security is the WireGuard layer underneath.
  - Decision: `Transport` as an enum (not a generic) to avoid threading another type parameter through the engine.
  - Note: obfuscation adds ~14+padding bytes/packet — lower the tunnel MTU (~1380) when using it. Obfs key is a 32-byte base64 (generate with `oxide-serverd genkey`).
  - **Control-plane distribution (done):** `oxide-control-plane add-server --obfuscation-key <b64>` stores it; registration returns it; `oxide-client connect` uses it automatically. Multihop works transparently — the key is the *exit's* (tunnel terminates there), and the entry relays the obfuscated bytes untouched, so no relay change was needed.

- **2026-07-21 — Hardening pass 2: netlink + IPv6.** `net-linux` link/addr/route now go through **rtnetlink** (real netlink) instead of `ip` shell-outs — a `Netlink` handle (async, cloneable). `bring_up_interface` is async, returns the link index, and assigns both `address` and the new `address6`. **IPv6 inside the tunnel** works: dual-stack tunnel addresses and `::/0` full-tunnel routing (`::/1` + `8000::/1`). The netns test now pings both IPv4 and IPv6 across the tunnel (CI verifies). 29 tests, clippy + fmt clean.
  - Decision: migrate **mutations** to netlink; keep the single default-route *read* as `ip route show` (reconstructing it from raw netlink dumps is disproportionately fiddly for a low-risk read). nftables (NAT/kill switch) still shells out to `nft` — nft-via-netlink is a separate follow-up.
  - Scope: WG **transport** is still IPv4 (WG-over-IPv6 + control-plane v6 IP allocation are follow-ups); IPv6 *inside* the tunnel is done.

- **2026-07-21 — Hardening pass 1.** (1) **DoS defense:** a shared boringtun `RateLimiter` is now fed to every server peer's `Tunn` (via `Engine::build_server`, 100 handshakes/s) with a 1s `reset_count` tick — cookie challenges engage under handshake floods. (2) **Auth rate-limiting:** per-IP fixed-window limiter (60 req/60s) as axum middleware, plus a 64 KB body cap and 15s request timeout; served with connect-info so the limiter sees client IPs. Protects the account-number bearer auth from brute force. (3) **CI:** `.github/workflows/ci.yml` runs fmt + clippy `-D warnings` + test, `cargo-deny` (advisories/bans/sources), and a **privileged `netns` job** that runs `scripts/netns-test.sh` as root — this is how the live-kernel TUN/nft path gets verified without local sudo (runs on push). `deny.toml` added. 28 tests, clippy clean, fmt clean.
  - Next hardening chunk: migrate `net-linux` off `ip`/`nft` shell-outs to real netlink/nftables; IPv6; MSS clamping.

- **2026-07-21 — Multihop built.** New `relay` crate (tokio UDP proxy). The client runs a single WireGuard session keyed to the **exit** but sends ciphertext to the **entry**, which relays it — so no single server sees both ends, and the client engine/`wg-core` needed **zero changes**. Control plane: `relays` table + per-entry port allocation, `POST /v1/devices/multihop` (registers device on exit, ensures relay route, returns exit-key + entry-relay-endpoint), `GET /v1/internal/servers/:id/relays`. `oxide-serverd` runs a relay per route (fetched on poll); `oxide-client connect --exit/--entry`. Verified without root: relay forwarding + flow isolation, control-plane multihop registration, and a capstone `multihop_flow` test driving a real tunnel client→relay→exit. 27 tests, clippy clean.
  - Decision: **WireGuard-native multihop (entry relays ciphertext), not onion encryption.** Matches Mullvad; keeps the data plane single-encryption and untouched. The entry is a dumb UDP forwarder that can't read the traffic (it's encrypted to the exit).
  - Decision: entry auto-picks the least-loaded server ≠ exit when `--entry` is omitted.

- **2026-07-21 — M4 privacy (leak prevention) built.** Kill switch + DNS leak protection in `net-linux` (pure ruleset/resolv.conf builders, unit-tested; applied via nft/resolv.conf, needs root). Control plane hands out a per-server DNS in device registration. `oxide-client` gains `--kill-switch` and applies/tears down DNS + kill switch around the tunnel in the right order. No-logs posture audited (data plane keeps nothing on disk, no info-level PII). 24 tests, clippy clean. Multihop deferred to its own milestone (nested tunnels + entry/exit pairing is substantial).
  - Decision: kill switch is **opt-in** (`--kill-switch`) in v0 to avoid surprising lockouts from a CLI; a real client would default it on with a toggle.
  - Decision: manage `/etc/resolv.conf` directly for v0 (simple, auditable); resolved/NetworkManager backends later.

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

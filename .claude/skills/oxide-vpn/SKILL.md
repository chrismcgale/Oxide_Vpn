---
name: oxide-vpn
description: Operational runbook for the Oxide VPN — a WireGuard-based (boringtun) VPN platform in Rust. Run, debug, architecture pointer, gotchas, changelog.
---

# Oxide VPN runbook

A WireGuard data plane (via **boringtun**) with an Oxide-built control/privacy/ops
layer on top. Modeled on Mullvad / NordLynx. Linux-first.

**Forward plan:** the M1–M4 rearchitecture is done. The active execution plan — current
state, working conventions, and ~6 months of ordered work (Wave 1 moonshots: DAITA →
undetectable server → onion multihop → verifiable no-logs; then scale, clients, research)
— lives in the repo at **`PLAN.md`**. Read that to know what to build next; read this file
to build/run/debug. (Historical M1–M6 plan: `~/.claude/plans/wobbly-splashing-puddle.md`.)

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

# TUI client (agent runs as root; TUI runs as your user):
sudo target/debug/oxide-agentd &                  # privileged agent on /run/oxide/agent.sock
target/debug/oxide-tui --control-plane http://cp:8080 --account <n>   # ↑/↓ select · Enter connect · d disconnect · q quit
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
- **`control-plane`** — axum + sqlx service on **SQLite or Postgres** (chosen by the connection string): accounts (anonymous numbers), devices (pubkey + assigned tunnel IP), servers (with location + capacity), IP allocation, **load-based server selection** (`GET /v1/servers/best`) fed by **server heartbeats**. Never depends on `wg-core`. `add_server` CLI + `serve`. Backend abstraction lives in `db.rs` (`Db`/`DbRow`/`Val` dialect layer — SQL written once, `?`→`$n` for PG); switching is a connection-string change.
- **`control-client`** — thin reqwest client for the control-plane API, shared by both daemons.
- **`relay`** — a pure-tokio UDP relay used by **multihop** entry servers: forwards a client's WireGuard ciphertext to the exit server (per-client upstream flows), so no single server sees both the client's IP and its destination. No root; unit-tested over loopback.
- **`pq`** — **post-quantum** key agreement (ML-KEM-768 via `ml-kem`). `generate`/`encapsulate`/`decapsulate` produce a 32-byte shared secret used as the WireGuard **PSK**, layered on top of x25519 — strictly additive/hybrid (can only strengthen; a flaw in the unaudited ML-KEM can't weaken the classical security). Pure; unit-tested. Capstone: a real tunnel secured by the PQ-derived PSK.
- **`mimicry`** — **stealth tier 2 (protocol mimicry)**. Two modes, both making the flow look like normal web traffic (blocking it = blocking HTTPS/HTTP3):
  - **TLS-over-TCP** (`mimicry` root + `wg-core::MimicTransport`, `Transport::Mimic`): a real-looking TLS 1.3 handshake (ClientHello w/ SNI, ServerHello) then datagrams as TLS `application_data` records over TCP (server accept + demux by TCP source addr).
  - **QUIC-over-UDP** (`mimicry::quic` + `Transport::QuicMimic`): UDP-native (no TCP-over-TCP), looks like HTTP/3 — first packet a QUIC Initial (v1, connection IDs, embedded ClientHello, padded to 1200), rest short-header. Reuses the datagram model.
  Payloads are obfuscated first, so record/packet contents are high-entropy like real TLS/QUIC. It's mimicry, not a full protocol emulator (fools passive fingerprinting, which is what blocks WireGuard); security is the WG AEAD inside.
  - **Decoy-forwarding** (`wg-core::decoy`, Sprint 1B): the QUIC transport's `quic_mimic_with_decoy` proxies an unauthenticated first-contact Initial to a real backend (`DecoyForwarder`, per-source UDP upstream + reply pump through the listen socket) so the port answers like an ordinary QUIC server under active probing, instead of the silent drop. Config: `interface.decoy_backend`.
  - **Transport selection** (Sprint 2A): `common::TransportKind` (`plain|obfs|quic|mimic`) + `interface.transport`/`interface.daita`; daemons build the selected transport (`oxide-serverd::build_server_transport`, `client-core::build_client_transport`). Back-compat: `obfuscation_key` alone = `obfs`. Control-plane distribution of the choice is a follow-up (2A-2).
- **`obfs`** — **stealth mode** codec: wraps each datagram as `[nonce][ChaCha20(key,nonce) XOR ([len][payload][pad])]` so DPI can't fingerprint WireGuard (no fixed header). Padding rounds the datagram up to size **buckets** (256/512/…/1472) so handshakes/keepalives/small data collapse into indistinguishable sizes — traffic-analysis resistance (size dimension). Pure; unit-tested. Used by `wg-core`'s `Transport::Obfuscated`. (Timing-based cover traffic and protocol *mimicry* — WG-in-TLS/QUIC — are the next tiers.)
- **`daita`** — **traffic-analysis defense (DAITA v1)**: the pure cell codec + shaping decision. A **cell** is `[type:1][len:2][payload][random pad]` padded to a fixed `cell_size`, `type` = `REAL` (a WG datagram) or `COVER` (droppable filler). The `Shaper` is a bounded queue drained **one cell per slot** — a real datagram if queued, else a cover cell. Cells are the *plaintext* the obfs frame wraps, so a fixed cell size ⇒ one obfs bucket ⇒ one wire size, and recognizing/dropping cover needs the shared obfs key (so DAITA implies stealth). Wired into `wg-core` via `Engine::with_daita(Daita::{shaping,framing})` — the client shapes egress to a constant rate + cover; the server frames replies and drops inbound cover before boringtun. Honest cost: constant `cell_size*8/slot` bandwidth each way. Pure/unit-tested; capstone `tunnel_works_with_daita_shaping`.
- **`seccomp`** (`oxide-seccomp`) — **enforced no-logs (1D-1)**: builds + applies a seccomp-BPF filter that makes the process unable to create/write files (gates `openat`/`open` *flags* + FS-mutating syscalls; default-allow otherwise, so sockets/read-only opens/stdout work). `apply_no_disk_writes()`; serverd runs it under `[hardening] no_disk_writes`. Unprivileged (NO_NEW_PRIVS), fork-tested.
- **`attest`** (`oxide-attest`) — **verifiable build identity (1D-2/1D-3)**: Ed25519 signed `BuildManifest` (binary SHA-256 + git commit + version) verified against a **pinned** release key (`sign_manifest`/`verify_manifest`, `self_binary_sha256`), plus a hash-chained append-only `TransparencyLog` of deployed builds with a signed head (`verify_log`). Pure crypto; serverd exposes `attest-genkey`/`manifest`.
- **`oxide-serverd`** — server daemon: config → engine → net-linux; polls the control plane and reconciles peers live. Also: `genkey`/`pubkey`/`pq-genkey`/`attest-genkey`/`manifest` subcommands; `build.rs` bakes in git commit + build time.
- **`client-core`** — shared client tunnel logic: `resolve_connection` (control-plane server selection + PQ + registration → local config, unprivileged), `resolve_mesh` (join the account's private mesh → local config with one peer per device, unprivileged), and `run_tunnel` (bring up TUN + routing + kill switch + DNS + engine until a caller-supplied `stop`, with an `on_ready` callback exposing the `EngineHandle` for live stats).
- **`oxide-client`** — thin CLI over `client-core` (`up`/`connect`/`mesh`/`account`/`genkey`).
- **`oxide-agentd`** — privileged agent: runs as root, owns the tunnel (embedded via `client-core`), serves a Unix-socket control API (newline-JSON: Status/Connect/Disconnect) so the UI never needs root.
- **`oxide-tui`** — unprivileged terminal UI (ratatui): browse servers from the control plane, connect/disconnect via the agent socket, live status (uptime, tx/rx, peers, stealth/PQ flags).

Client UX architecture: **unprivileged TUI ⇄ Unix socket ⇄ privileged agent**. The agent does all root-requiring work; the TUI is a pure client of the control plane + agent socket.

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

- **2026-07-22 — Postgres backend (Sprint 2B).** The control plane now runs on **SQLite (default) or Postgres**, selected by the connection string (`postgres://…` → Postgres, else SQLite path). sqlx is compile-time DB-typed, so instead of a generic-over-`Database` rewrite we added a small **dialect layer** in `db.rs`: `Db{Sqlite(SqlitePool)|Postgres(PgPool)}` wraps the pool; `DbRow{Sqlite|Postgres}` exposes typed getters (`text`/`opt_text`/`int`/`opt_int`) that dispatch `try_get` (impl'd for both row types); `Val` is a bind param; the query methods rewrite `?`→`$n` for Postgres. **All SQL is written once** (SQLite `?` style); only the schema DDL branches (Postgres uses `BIGINT`/`BIGSERIAL` so `try_get::<i64>` decodes uniformly; SQLite keeps `INTEGER`/`AUTOINCREMENT` + its idempotent `ALTER` migrations). ~20 call sites converted to `pool.execute/fetch_optional/fetch_all/scalar_*`. Verified: existing SQLite tests unchanged (**no regression**) + a new `tests/postgres.rs` runs the full account/device/metrics flow against **live Postgres 18.4** (gated on `OXIDE_TEST_PG_URL`, skips cleanly in CI; unique server id per run). 95 tests.
  - Decision: **dialect enum over the sqlx `Any` driver** (user's call) — `Any` doesn't rewrite `?` placeholders and has type-mapping caveats; the enum keeps SQLite fully tested as one concrete branch and the Postgres branch is now proven against a real server, not guessed.
  - Decision: **`try_get` + `unwrap_or_default`/`.ok()` in `DbRow`** rather than panicking `row.get` — a schema/type mismatch degrades to a default/`None` in a request handler instead of a 500-with-panic. Postgres integer columns are all `BIGINT` so `i64` decode never type-mismatches.
  - Run Postgres: `oxide-control-plane --db 'postgres://user@host/oxide_cp' serve …`. The `reg_lock` still serializes IP allocation (correctness holds on either backend); a Postgres deployment can now run multiple API nodes once that lock becomes advisory/DB-side (future).
- **2026-07-22 — Verifiable no-logs (Sprint 1D-1/1D-2/1D-3).** Turns the no-logs posture from a promise into something enforced + provable. Two new pure crates + serverd wiring. Verified without root: 15 new tests (2 seccomp + 13 attest). 94 tests total, clippy + fmt clean.
  - **1D-1 enforced no-logs** (`oxide-seccomp`): a seccomp-BPF filter that makes the process **unable to create or write files**. `oxide-serverd` applies it (config `[hardening] no_disk_writes = true`) *after* setup, right before the packet loop, across all tokio threads (`apply_filter_all_threads`, inherited by children). **Key insight:** seccomp can't tell a file fd from a socket fd (no pointer deref), so we gate at `openat`/`open` **flags** (deny any write/create-intent open) + the FS-mutating syscalls (`creat`, `unlinkat`, `renameat2`, `truncate`, `openat2`, …) — *not* the `write` syscall, which sockets and stdout logging also use. Denials return `EPERM` (safe degrade; `KillProcess` is a one-liner for a stricter posture). Test forks a child, applies the filter, proves a file create is refused with `EPERM` while a socket + read-only open still work — **no root needed** (`PR_SET_NO_NEW_PRIVS`).
  - **1D-2 signed build manifest** (`oxide-attest`): an Ed25519 **release key** signs a `BuildManifest` (binary SHA-256 from `/proc/self/exe` + git commit + version + build time) → `SignedManifest`; a client pinning the release public key verifies it and can refuse unknown/tampered builds. Signature is over a fixed **canonical** encoding (not JSON). `oxide-serverd attest-genkey` (release keypair) + `oxide-serverd manifest --key <seed>` (emit the signed manifest for the running binary); a `build.rs` bakes in the git commit + `SOURCE_DATE_EPOCH`-aware build time. Verification is always against the **pinned** key, never the one embedded in the manifest — so an attacker who re-signs a tampered manifest with their own key still fails.
  - **1D-3 transparency log** (`oxide-attest`): an append-only, **hash-chained** log of deployed builds (`LogEntry{seq,binary_sha256,git_commit,prev_hash}`), with a signed head (`SignedHead` over `head_hash‖count`). `verify_log(entries, head, pinned_key)` checks chain integrity + head signature; editing any past entry breaks every later hash and the head. A client proves its server runs a build that was *publicly logged*, not one swapped in just for it.
  - **Decision: filter `openat` flags, not `write`** — the only enforceable way to say "no disk writes" in seccomp (it's fd-blind). Apply post-setup because the daemon legitimately opens `/dev/net/tun` `O_RDWR` at startup. Caveat: nft teardown (`disable_masquerade`) execs `nft` under the inherited filter — fine for `delete table` (netlink, no file writes); documented that `no_disk_writes` pairs best with a static config.
  - **Remaining (1D wiring):** distribute the signed manifest + transparency log via the control plane so the client verifies **at connect** (overlaps 2A-2 CP distribution); reproducible-build script; `1D-4` HW attestation (TPM/SGX) is out of scope (needs hardware — flagged to user).
- **2026-07-21 — Transport selector (Sprint 2A, local config).** Config now selects the wire transport instead of only obfs-on/off. New `common::TransportKind` (`plain|obfs|quic|mimic`) + `interface.transport` / `interface.daita` fields; `InterfaceConfig::transport_kind()` applies the **back-compat rule** (an `obfuscation_key` with no `transport` still means `obfs`). Both daemons build the selected transport from config: `oxide-serverd::build_server_transport` (binds/listens; `quic` uses `decoy_backend`; DAITA → `Daita::server()`) and `client-core::build_client_transport` (client role; `mimic` connects to the peer endpoint; DAITA → `Daita::client()`). `Config::validate` rejects `daita` without stealth and a stealth transport without a key. Verified without root: 3 config tests (back-compat/explicit parse, daita-needs-stealth, stealth-needs-key). 83 tests, clippy + fmt clean. **Scope:** local config only — control-plane distribution of the choice (like the obfs key) is the deferred 2A-2 follow-up.
  - Decision: **`transport` enum + orthogonal `daita` bool**, not a single 5-valued selector — DAITA isn't a transport, it *layers* on a stealth one (`Engine::with_daita`). Keeps the model correct.
  - Decision: **builders live in the daemons, not `wg-core`** — preserves the "wg-core knows nothing about config" invariant; the small role difference (server binds/decoy; client connects for mimic) is genuine, so minor duplication beats importing config types into the engine.
- **2026-07-21 — Undetectable server: decoy-forwarding (Sprint 1B).** New `wg-core::decoy::DecoyForwarder` + `Transport::quic_mimic_with_decoy`. On the QUIC-mimicry transport, an unauthenticated first-contact Initial (forged/stale/replayed — the active-probe vector) is no longer silently dropped: it's **spliced to a configured decoy backend** (a real TLS/QUIC endpoint), whose response is relayed back to the prober **through the server's own listen socket** — so the port answers like an ordinary QUIC/HTTP-3 server, not a dead port. A source classified as a prober stays spliced for the flow's lifetime (idle-reaped). Reuses the `relay` per-source-upstream pattern. New `interface.decoy_backend` config (`host:port`). Verified without root: 2 transport tests (forged probe answered by a stub backend from the server's port; genuine Initial still tunnels *concurrently* with a decoyed probe). 80 tests at 1B, clippy + fmt clean.
  - Decision: **trigger = failed QUIC Initial only**, not unknown short-header/garbage. Real QUIC servers also drop unassociated packets silently, so that's already realistic; and it preserves WireGuard endpoint **roaming** (a roaming client sends short-headers from a new address — those must still reach the tunnel, gated by the WG AEAD). The distinguishing active probe is a crafted Initial, which is exactly what we decoy.
  - Decision: **QUIC path only for v1.** TLS-mimic (TCP) decoy is a documented follow-up; serverd wiring of quic-with-decoy arrives via the transport selector (2A). Threat model: strongest when `decoy_backend` is a real service you host; our mimicry Initial isn't byte-perfect QUIC so a strict backend may send an error response (still *a* response); a global observer could compare authenticated vs decoyed timing.
- **2026-07-21 — DAITA v1: traffic-analysis defense (Sprint 1A).** New pure `daita` crate (cell codec + `Shaper`) + an engine-level queue in `wg-core` (`Engine::with_daita`, `crate::daita::Daita`). Finishes the traffic-analysis story obfs started (size buckets) by adding the **rate** and **cover** dimensions: the client drains outbound WG datagrams through a bounded queue at a fixed **slot** cadence, emitting exactly one fixed-size **cell** per slot — a `REAL` cell (a queued datagram) or a `COVER` cell (droppable filler) — so a passive/ML observer or our own multihop entry sees only steady, contentless, constant-size volume. A 1-byte REAL/COVER tag lives *inside* the obfs frame, so cover is recognized and dropped **before boringtun**; a fixed cell size means the obfs layer always picks the same size bucket (one wire size for every cell). v1 shapes **client→server egress, single peer**; the server runs `Daita::framing` (wraps replies as cells so the client can parse, drops inbound cover) but doesn't generate cover/constant-rate — server→client is size-normalized but reactive. Verified without root: 10 `daita` unit tests (roundtrip, one-size real==cover, cover-when-idle, FIFO drain, drop-oldest-when-full, malformed/oversize rejection) + capstone `tunnel_works_with_daita_shaping` (a real WG tunnel over obfs with DAITA on: a packet crosses **and** the steady cover stream never leaks to the server's tunnel). 78 tests, clippy + fmt clean.
  - Decision: **engine-level queue, not a `Transport` wrapper** (Part-4 fork #3) — keeps the `Transport` enum and the peer-generic engine clean; the shaper is a fourth detached task (`shaper_loop`) alongside outbound/inbound/timers, and all four client egress sites (`init_handshakes`, `outbound_loop`, `handle_incoming` replies, `timer_loop` keepalives) funnel through one `send_egress` helper so **every** client→server datagram is shaped → truly constant rate.
  - Decision: **framing is bidirectional, shaping is client-only** — the type byte changes the payload format, so both ends must speak the cell codec (the server strips the tag before decapsulate); only the client runs the constant-rate shaper + cover. Bidirectional/per-hop rate shaping is Sprint 4A.
  - Decision: **DAITA implies stealth** (fork #4) — cells ride inside the obfs frame (need the shared key to drop cover), so a stealth transport (obfs/QUIC/TLS-mimic) must be on. `with_daita` uses `Arc::get_mut` so it's additive (no `build` signature change) but must be called before `handle()`/`run()`.
  - Cost (documented, not hidden): constant `cell_size*8/slot` bandwidth floor **and** ceiling each way (default 1440 B / 5 ms ≈ 2.3 Mbit/s). Every wrapping layer cuts MTU — default `cell_size` (1440) fits a full stealth-MTU (~1380) datagram and lands in the top obfs bucket (1472). *Not yet wired:* a config/control-plane transport selector to turn DAITA on per-deployment (that's Wave 2A, alongside mimic/quic).
- **2026-07-21 — Active-probe-resistant QUIC mimicry (authenticated Initial).** The QUIC Initial is now **authenticated**: its token carries `timestamp(8) ‖ nonce(16) ‖ keyed-BLAKE2-MAC(16)`, the MAC binding QUIC version + both connection IDs + timestamp + nonce under the shared obfs key (`mimicry::quic::{initial_packet(payload,key,now), verify_initial(dg,key,now) -> (nonce,payload), parse_short}`; new `blake2` dep). The QuicMimic transport verifies every long-header datagram and **silently drops** any Initial that fails the MAC (a *forged* probe — the prober lacks the key), is outside `±120s` (a *stale* replay), or whose nonce is already in a pruned replay cache (a *replayed* probe) — so the port looks dead to an active prober, not just to a passive fingerprinter. Short-header packets are unauthenticated (their payload is still gated by the WireGuard AEAD after deobfuscation); first contact must be a valid Initial. Verified without root: 8 `quic` unit tests (forged/tampered/stale/replay-nonce) + 3 transport tests (authenticated-initial-then-short delivers; forged-key Initial ignored; replayed Initial dropped) + the existing QUIC-mimicry capstone tunnel still passes. 71 tests, clippy + fmt clean.
  - Threat model: defeats **active probing** (replay a captured first packet / send a crafted QUIC Initial and watch for a distinguishing response). The obfs layer already gave passive unlinkability but is an unauthenticated stream cipher, so a forged/replayed Initial could reach the WG layer; the keyed Initial gates it at the transport. Assumes client/server clocks within 120s (NTP). *Next tier:* decoy-forwarding (proxy unauthenticated first-contact traffic to a real backend, e.g. an actual TLS/QUIC server) so even the *absence* of a normal response can't be used as a signal.
  - Decision: **authenticate only the Initial, not every packet** — active probing is a first-contact attack; per-packet MACs would duplicate the WG AEAD and cost MTU. Timestamp+nonce+MAC in the token (a realistic ~40-byte QUIC address-validation token) keeps the packet indistinguishable from real QUIC.

- **2026-07-21 — Mesh hybrid ("Tailscale, but actually private").** A user's own devices form a private WireGuard P2P overlay coordinated by the control plane. New mesh DTOs (`common::api`), a `mesh_devices` table + `POST /v1/mesh/register` (idempotent by pubkey, allocates a stable `/32` in `100.64.0.0/16`, returns your mesh IP + the account's peer list) and `GET /v1/mesh` (control-plane). `control-client` gained `mesh_register`/`mesh_list`; `client-core::resolve_mesh` builds a `Resolved` where the interface holds the mesh `/16` and each other device is a peer pinned to its mesh `/32` (no default route → normal egress untouched); `oxide-client mesh --endpoint host:port`. Verified without root: `mesh_flow` capstone — two devices register, discover each other, and a packet flows directly between them over the mesh (no server, no exit). 60 tests, clippy + fmt clean.
  - Decision: **the mesh peer list is account-scoped** (devices only mesh with same-account devices), but mesh IPs are globally unique within `100.64.0.0/16`. This is the "actually private" property — no shared coordination server sees cross-account topology.
  - Decision: **v1 uses reported endpoints (direct reachability)** — the joining device tells the control plane where it's reachable (`--endpoint`). NAT traversal (STUN-style hole punching / a DERP-style relay fallback) is deferred; today it assumes devices can reach each other's endpoints (public IP + forwarded UDP port, or same LAN).
  - Hybrid: run `mesh` for private device-to-device traffic **and** `connect` for an anonymous exit — the mesh carries only its `/16`, so it composes with a full-tunnel exit.

- **2026-07-21 — QUIC mimicry (stealth tier 2, UDP-native).** New `mimicry::quic` module + `Transport::QuicMimic` — the flow looks like an HTTP/3 (QUIC) session: a long-header Initial (QUIC v1, connection IDs, embedded ClientHello w/ SNI, padded to 1200) then short-header 1-RTT packets. UDP-native, so it avoids the TCP-over-TCP penalty of the TLS mimicry and blends into HTTP/3 traffic. Reuses the datagram transport model (first packet per peer = Initial, rest short). Verified: codec tests (looks like QUIC, round-trips, rejects garbage) + a capstone real WireGuard tunnel over QUIC mimicry on loopback. 59 tests, clippy + fmt clean.
  - Decision: **QUIC mimicry is the preferred stealth transport** (UDP-native like WireGuard, no TCP penalty, huge cover traffic); TLS-over-TCP is the fallback for UDP-hostile networks.

- **2026-07-21 — Stealth tier 2: TLS protocol mimicry.** New `mimicry` crate (TLS 1.3 handshake + record framing) and `wg-core::MimicTransport` (`Transport::Mimic`) that carries the tunnel over TCP inside a flow that looks like HTTPS — a censor sees a ClientHello (SNI = `www.cloudflare.com`), a ServerHello, and application_data records. Composes over the ChaCha obfs so record contents are high-entropy like real TLS. Verified without root: codec tests, a "client's first bytes are a TLS ClientHello" transport test, and a capstone running a real WireGuard tunnel over TLS-mimicry on loopback. 54 tests, clippy + fmt clean.
  - Decision: **mimicry, not real TLS** — endpoints don't validate the handshake; it only has to fool a *passive* censor. Security is the WG AEAD (+ obfs) inside. Rides TCP (real TLS is TCP) — the accepted TCP-over-TCP trade-off for a censorship fallback. Enabled `tokio` `io-util`.
  - Follow-up: wire a config/control-plane transport selector (`udp`/`mimic`) so daemons pick it (like the obfs key); the capability + capstone are done.

- **2026-07-21 — Client UX: TUI + privileged agent.** New crates: `client-core` (shared tunnel logic extracted from the CLI, with a controllable `stop` + `on_ready` stats callback), `oxide-agentd` (root agent serving a Unix-socket control API), `oxide-tui` (unprivileged ratatui client). `EngineStats` gained tx/rx bytes; `common::agent` holds the UI⇄agent protocol. Verified without root: agent socket round-trips (Status→disconnected, bad input→error) and the TUI's app-state logic is unit-tested; rendering + the connect path need a TTY/root. 47 tests, clippy + fmt clean.
  - Decision: **unprivileged UI + privileged agent split** (the M5 plan) — the TUI is a pure client of the control plane + the agent socket, so it never needs root. The tunnel runs *embedded* in the agent (not a supervised child), so status shows real throughput.

- **2026-07-21 — Observability: `/metrics`.** The control plane exposes a Prometheus text endpoint (`GET /metrics`): `oxide_accounts_total`, `oxide_servers_total`, `oxide_devices_total`, and per-server `oxide_server_active_peers{server=…}` / `oxide_server_capacity{…}`. Rendering is a testable function (`render_metrics`). Unauthenticated aggregate counts (no secrets) — firewall/scrape internally in production. 42 tests, clippy + fmt clean.

- **2026-07-21 — Post-quantum handshake (signature feature, core).** New `pq` crate wrapping ML-KEM-768. The KEM shared secret becomes the WireGuard PSK, so the tunnel is protected by x25519 **and** ML-KEM — quantum-resistant, and strictly additive (hybrid). Verified: KEM round-trip tests + a capstone running a real WireGuard tunnel keyed by the PQ-derived PSK. 40 tests, clippy + fmt clean.
  - Decision: **hybrid via the PSK slot**, not replacing x25519 — matches Mullvad's approach and means the not-yet-audited ML-KEM impl can only add security, never subtract. ML-KEM-768 = NIST category 3. Private key stored/transported as its 64-byte seed.
  - **Control-plane distribution (done, single-hop + multihop):** `oxide-serverd pq-genkey` prints a seed + public key; put the seed in the server config (`pq_private_seed`) and register the public key (`add-server --pq-public-key`). The client fetches the server's (or exit's) PQ key, encapsulates, sends the ciphertext at registration; the server/exit decapsulates from its peer list — both derive the same PSK. For multihop it keys to the **exit** and the entry relays the (already-obfuscated-and/or-PQ) bytes untouched. Capstones: `pq_flow` (CP-negotiated single-hop) and `multihop_flow` (multihop + relay + PQ together).

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

# Oxide VPN — Development Plan & Runbook

> **What this file is.** The forward-looking execution plan: where the project is, how we
> work, and ~6 months of ambitious development laid out at an agent's pace (fast — think in
> *sprints of hours*, not weeks). It complements, and does not duplicate:
> - `README.md` — the pitch and status for humans.
> - `ROADMAP.md` — the high-level vision and signature bets.
> - `.claude/skills/oxide-vpn/SKILL.md` — the **operational** runbook (Run · Debug ·
>   Architecture · Gotchas · Changelog). Read that to *build/run/debug*; read this to know
>   *what to build next and why*.
>
> **How to resume after a context clear:** read this file top-to-bottom, then
> `SKILL.md`'s Architecture + Changelog, then open the current Wave and take the next
> unchecked sprint. Keep the checkboxes here in sync as you land work.

---

## Part 0 — Current state (2026-07-21)

A real WireGuard-based VPN platform built on **boringtun** (not hand-rolled crypto),
Linux-first, as a 17-crate Cargo workspace. ~108 tests, all green, verified **without root**
(mock TUN + loopback UDP + in-process control plane; seccomp fork-tested unprivileged; the
control plane runs on SQLite or Postgres — the Postgres flow test is gated on a live DB).
The live-kernel path is verified by the CI netns job.

**Done (M1–M4 + signature features):**
- **Data plane** (`wg-core`): boringtun engine, 3 tokio tasks, runtime-mutable peer table
  (`EngineHandle`), allowed-IPs router, `Transport` enum abstraction.
- **Control plane** (`control-plane`/`control-client`): anonymous account numbers, device
  registration + IP allocation, server list with location/capacity + heartbeat load,
  least-loaded selection, `/metrics` (Prometheus). axum + sqlx/SQLite.
- **Privacy**: kill switch + DNS leak protection (`net-linux`), audited no-logs/RAM-only
  data plane.
- **Multihop** (`relay`): WireGuard-native — entry relays exit-keyed ciphertext; no single
  server sees both ends.
- **Stealth** (`obfs` + `mimicry`): tier 1 ChaCha20 obfuscation + size-bucket padding; tier
  2 protocol mimicry — TLS-over-TCP (`Transport::Mimic`) and QUIC-over-UDP
  (`Transport::QuicMimic`); tier 3 **active-probe resistance** — the QUIC Initial is
  authenticated (timestamp + nonce + keyed BLAKE2 MAC), forged/stale/replayed Initials
  dropped in silence; tier 4 **decoy-forwarding** (`wg-core::decoy`) — those failed Initials
  are proxied to a real backend so the port answers like an ordinary web server. Daemons
  pick the transport via `interface.transport` (`plain|obfs|quic|mimic`).
- **Traffic-analysis defense** (`daita` + `wg-core` shaper): DAITA v1 — client egress
  shaped to a constant rate of fixed-size cells with cover traffic filling idle slots
  (`Engine::with_daita`); finishes the size/rate/cover story obfs began.
- **Verifiable no-logs** (`seccomp` + `attest`): enforced (a seccomp filter makes the
  server unable to write to disk, `[hardening] no_disk_writes`) + provable (Ed25519 signed
  build manifest verified against a pinned key + a hash-chained transparency log). 1D-1..3
  done; distributing the manifest/log via the control plane (verify at connect) remains.
- **Post-quantum** (`pq`): ML-KEM-768 → WireGuard PSK, hybrid, single-hop + multihop.
- **Mesh hybrid**: control-plane-coordinated private WireGuard P2P overlay of the account's
  own devices (`resolve_mesh`, `oxide-client mesh`); composes with a full-tunnel exit.
- **Client UX**: `client-core` (shared tunnel logic) → `oxide-agentd` (root agent, Unix
  socket API) → `oxide-tui` (unprivileged ratatui).
- **Hardening/CI**: RateLimiter DoS defense, per-IP auth limiting, rtnetlink, IPv6-in-tunnel,
  SIGTERM, MSS clamping; CI runs fmt + clippy `-D` + test + cargo-deny + a privileged netns
  job.

**Known gaps / debt (fold into the waves below):**
- **Transport selector done (2A + 2A-2)** — daemons build the configured transport
  (`plain|obfs|quic|mimic` + `daita`) and the control plane distributes the choice per-server
  (`add-server --transport/--daita`), so CP clients auto-pick. *Remaining stealth-CP wiring:*
  distribute the attest signed manifest/log for at-connect build verification.
- Peer demux is an O(peers) source-address fallback, not a receiver-index table.
- `nft`/`sysctl` still shell out; DNS backend isn't `systemd-resolved`-aware.
- WG **transport** is IPv4-only (IPv6 *inside* the tunnel works).
- Postgres backend done (2B) + concurrency-safe/multi-node allocation done (2C core); a fleet
  now needs only the remaining 2C lifecycle bits (token rotation, re-selection); no
  provisioning automation yet.
- No desktop/mobile/cross-platform clients yet.

---

## Part 1 — How we work (definition of done)

Every landed increment must, before commit:
1. **Build clean**, `cargo clippy --workspace --all-targets` with **zero** warnings.
2. **Tests green**, `cargo test --workspace`; new behavior gets new tests, verified
   **without root** (mock TUN + loopback + in-process control plane; pure builders
   unit-tested). Root-only paths get a netns/CI test, not a local run.
3. **`cargo fmt --all`** applied.
4. **Docs updated in the same change**: `SKILL.md` Changelog entry (newest first) +
   the relevant section; update `ROADMAP.md`/`README.md`/this `PLAN.md` checkboxes; update
   the auto-memory pointer when the architecture shifts.
5. **One cohesive commit** with a descriptive body. Push/PR **only when the user asks**.
   Commit trailer: `Co-Authored-By: Claude ...`.

Design discipline carried over and to keep: **vendor/read a crate's real API from source
before writing against it** (saved us on boringtun, rtnetlink, ml-kem, ratatui). **Build on
established crypto**, never invent primitives. **Silence is a feature** — undecodable/forged
traffic is dropped without response (probe resistance). **The data plane keeps nothing on
disk.**

---

## Part 2 — The 6-month plan

Four **waves**. Wave 1 is the agreed moonshots, in order. Later waves are ordered by
leverage but can be re-prioritized. Each sprint is a self-contained, committable increment.

### WAVE 1 — Signature moonshots (agreed order)

#### Sprint 1A — DAITA: traffic-analysis defense  ✅ **DONE (2026-07-21)**
> Landed as the `daita` crate + an engine-level queue in `wg-core` (`Engine::with_daita`,
> `Daita::{shaping,framing}`). Client egress → one fixed-size cell per slot (REAL or COVER);
> cover rides inside the obfs frame and is dropped before boringtun. Chose the **engine-level
> queue** over a `Transport` wrapper (fork #3); framing is bidirectional, shaping client-only;
> DAITA implies stealth (fork #4). 10 unit tests + `tunnel_works_with_daita_shaping` capstone.
> *Still open:* the transport selector (2A) to enable DAITA per-deployment; bidirectional/
> adaptive shaping (4A). See the SKILL Changelog for the full decision record.

**Goal.** A passive/ML observer (and even our own multihop entry) sees only shaped,
contentless volume — constant packet **rate**, constant **size**, with **cover traffic**
filling idle slots. Finishes the traffic-analysis story begun by obfs (which already did the
*size* dimension via buckets).

**Design.**
- New `shaper` module (in `wg-core`, or a small `daita` crate). **Pure** decision logic,
  unit-tested: given a slot tick and a queue of pending real datagrams, emit exactly one
  cell per slot — a real datagram if queued, else a **cover** cell — every cell padded to a
  fixed `cell_size`.
- **Cover cells** must be indistinguishable on the wire but droppable by the peer. Add a
  1-byte frame **type** to the stealth payload (`REAL` vs `COVER`) *inside* the obfs frame,
  so cover is recognized and dropped **before boringtun** ever sees it. Cover carries random
  padding to `cell_size`.
- **Integration.** The engine's outbound path gains an optional shaper: real encapsulated
  packets enqueue instead of sending immediately; a shaper task drains at the slot cadence.
  A `Transport`-level or engine-level hook — decide during implementation which keeps the
  peer-generic engine cleanest (client single-peer, fixed endpoint, is the v1 target).
- **Scope v1:** client→server egress shaping, one peer. Document server-side and
  bidirectional shaping, and adaptive/learned defenses (maybenot-style), as Sprint 4A.

**Acceptance.** Shaper unit tests (constant cadence; cover fills idle slots; all cells one
size). Transport test: cover cells dropped, real payloads still delivered. Capstone: a real
WireGuard tunnel with DAITA on, packet crosses, wire trace shows constant-size cells at a
steady rate. **Honesty in docs:** this is a padding+rate defense with a real
bandwidth/latency cost, not a learned framework; quantify overhead.

#### Sprint 1B — Undetectable server (decoy-forwarding)  ✅ **DONE (2026-07-21)**
> Landed as `wg-core::decoy::DecoyForwarder` + `Transport::quic_mimic_with_decoy`. A forged/
> stale/replayed QUIC Initial (the active-probe vector) is spliced to a real `decoy_backend`
> and its response relayed back through the server's listen socket, so the port answers like
> an ordinary QUIC server. **Trigger = failed Initial only** (preserves roaming; short-header
> junk stays silently dropped, which is QUIC-realistic). QUIC path only for v1 — TLS-mimic
> decoy is a follow-up. 2 transport tests (probe answered from server port; genuine tunnels
> concurrently). See the SKILL Changelog for the decision record + threat model.

**Goal.** The server is byte-for-byte indistinguishable from an ordinary web server. Today
unauthenticated first-contact is *silently dropped* (port looks dead). Instead, **proxy it
to a real TLS/QUIC backend** so the port looks alive and boring — even the *absence* of a
normal response can't be a probe signal. Completes censorship-resistance on top of the
authenticated Initial (Sprint tier 3).

**Design.**
- Server keeps per-source first-contact state. First datagram that **fails** Initial auth →
  don't drop; splice the flow to a configured `decoy_backend` (a real HTTP/3 or HTTPS
  endpoint — ideally a real site co-hosted on the box) and relay both directions
  transparently (reuse `relay`-crate patterns; UDP for QUIC, TCP for the TLS-mimic path).
- Authenticated flows tunnel as normal. Unauthenticated flows are proxied for their lifetime.
- Config: `decoy_backend = "host:port"`; docs on picking a plausible backend and, ideally,
  actually serving a real site there.

**Acceptance.** Test: a bogus/forged Initial is forwarded to a stub backend and the backend's
response returns to the prober; a genuine authenticated Initial still tunnels; both concurrently
(loopback backend, no root). Docs: threat model — strongest when the decoy is a real service
you host; note timing/behavioral caveats.

#### Sprint 1C — True onion multihop  ⏸ **PARKED (2026-07-23)**
> **Direction pivot (user):** "Let's get this classic VPN going first." Onion multihop and all
> onion-flavored work are paused until the *classic consumer VPN* is solid — reliability
> (auto-reconnect + re-selection on server death), DNS that holds on systemd-resolved/
> NetworkManager systems (2F), live end-to-end verification under root, desktop GUI (3A),
> provisioning (2D), WG-over-IPv6 (2G). Pull those forward; do not start 1C until re-opened.
> (The unresolved crypto fork — nested-WireGuard vs Tor-style onion cells — waits with it.)

**Goal.** Upgrade multihop from "entry blindly relays exit-keyed ciphertext" to **nested
per-hop encryption**: each relay peels exactly one layer and knows only its previous and next
hop — never both your IP and your destination, even if a single hop is compromised.

**Design fork (decide at implementation — see Part 4):**
- **(a) Nested WireGuard** ("WG-in-WG-in-WG"): the client runs a WG session to the entry,
  carrying inside it a WG session to the middle, carrying a WG session to the exit. Each hop
  terminates one tunnel and forwards the inner ciphertext. Reuses audited crypto; the engine
  is peer-generic so it's feasible; cost is 3× handshakes + per-hop tunnel state.
- **(b) Tor-style onion cells**: per-hop symmetric keys from ephemeral X25519 ECDH
  (distributed via the control plane), payload wrapped in nested ChaCha20-Poly1305 layers;
  each hop peels one. Lighter on the wire; uses **only established primitives** (no novel
  crypto), but it's a new protocol to get right (replay, key rotation, teardown).
- Control plane: path selection (entry/middle/exit, distinct operators), per-hop key
  material, circuit lifecycle.

**Acceptance.** A 3-hop circuit where a packet goes client→entry→middle→exit and back; a
capstone with 3 in-process hops on loopback asserts each hop sees only its neighbors (e.g.
the exit never learns the client's address; the entry never learns the destination). Likely
split into sub-sprints: 1C-1 circuit crypto + key agreement (pure, unit-tested); 1C-2
per-hop forwarding; 1C-3 control-plane path selection + client `--onion`.

#### Sprint 1D — Verifiable no-logs
**Goal.** Cryptographically **prove** the no-logs posture instead of asserting it. Layered;
ship the tractable layers, document hardware attestation as a stretch.
- **1D-1 seccomp-enforced no-logs**: run `oxide-serverd` under a public, auditable seccomp
  profile that **denies disk writes** on the data path — so the server *cannot* log even if
  compromised. A test proves a disk write is killed. This is the strongest concrete,
  verifiable deliverable — enforcement, not a promise.
- **1D-2 reproducible builds + signed build manifest**: pin toolchain, `--locked`,
  document/verify a byte-reproducible server binary; `oxide-serverd` exposes a
  release-key-**signed** manifest (binary hash + git commit + build time); the client
  verifies it at connect and can refuse unknown builds.
- **1D-3 transparency log**: publish an append-only signed log of deployed binary hashes +
  config digests; clients check the server they reached runs a logged, audited build.
- **1D-4 (stretch) remote attestation**: TPM/DICE or SGX binding the *running process* to the
  logged hash. Infra-heavy; scope later.

**Acceptance.** Seccomp profile + a test that a write() to disk is denied/killed; a
reproducible-build script emitting a stable hash; a signed-manifest endpoint + client-side
signature verification; a minimal transparency-log format + verifier. No root needed for the
crypto/format parts; seccomp test runs in CI.

> ✅ **1D-1 / 1D-2 / 1D-3 DONE (2026-07-22).** `oxide-seccomp` (no-disk-writes filter,
> unprivileged fork-test; serverd `[hardening] no_disk_writes`) + `oxide-attest` (Ed25519
> signed `BuildManifest` verified against a pinned key; hash-chained `TransparencyLog` with a
> signed head). serverd `attest-genkey`/`manifest` + `build.rs`. 15 tests. **Remaining:**
> distribute the manifest + log via the control plane so the client verifies **at connect**
> (overlaps 2A-2); a reproducible-build script; **1D-4 HW attestation (TPM/SGX)** stays out —
> needs hardware, flagged to the user. See SKILL Changelog for the decision record.

### WAVE 2 — Productization & scale (make it a real product)

- [x] **2A Transport selector** — *DONE (2A local 2026-07-21, 2A-2 CP distribution
  2026-07-22).* `common::TransportKind` + `interface.transport`/`daita`; daemons build the
  selected transport (back-compat: `obfuscation_key` alone = `obfs`). **2A-2:** `servers.transport`
  /`servers.daita` columns + `add-server --transport/--daita` + `RegisterDeviceResponse`
  fields + `client-core::resolve_registration` mapping — a CP client now auto-picks the
  server's transport (QUIC/DAITA/mimic), verified on SQLite + live PG. *Still open:* distribute
  the **attest** signed manifest/log so the client verifies the build at connect (1D wiring).
- [x] **2B Postgres backend** — *DONE 2026-07-22.* Control plane runs on SQLite (default) or
  Postgres, chosen by the connection string. Took the **`Db` dialect-enum** approach (user's
  call over sqlx `Any`): `db.rs` `Db`/`DbRow`/`Val` layer — SQL written once (`?`→`$n` for PG),
  only DDL branches (`BIGINT`/`BIGSERIAL`). ~20 call sites converted. Verified against **live
  Postgres 18.4** (`tests/postgres.rs`, gated on `OXIDE_TEST_PG_URL`) with **zero SQLite
  regression**. *Next for multi-node:* make `reg_lock` DB-side/advisory so multiple API nodes
  can share one Postgres (2C).
- [~] **2C HA & lifecycle** — *core DONE 2026-07-22 (multi-node ready).* Removed the
  in-process `reg_lock`; correctness is now DB-side (`CREATE UNIQUE INDEX IF NOT EXISTS` on
  `devices(server_id,tunnel_ip)` + `relays(entry_id,listen_port)`, lock-free insert-retry,
  portable `is_unique_violation`, SQLite WAL+busy_timeout). 10-way concurrent-registration
  test passes on **both** SQLite and live Postgres → multiple API nodes can share one PG.
  **Client re-selection on server death: DONE (2026-07-23, classic-VPN track)** — `client-core::
  reconnect` + `run_supervised` (always-on auto-reconnect + failover), wired into `oxide-client
  connect` and `oxide-agentd`. **Remaining:** server-token rotation (grace window), versioned
  zero-downtime API, concurrent schema-init hardening.
- [x] **2D Provisioning automation** — *DONE 2026-07-23.* `oxide-serverd provision` stands a
  server up in one command: generates WG/PQ/obfs keys, registers remotely via a new admin API
  (`POST /v1/admin/servers`, `serve --admin-token`), and writes a ready `server.toml` (then
  `sudo … up`). Config part needs no root. Pure config renderer + in-process admin-endpoint
  tests; verified live against a running control plane. *Follow-on:* IaC templates / cloud-init.
- [ ] **2E Receiver-index peer demux** — replace the O(peers) source-addr fallback for busy
  servers.
- [ ] **2F net-linux polish** — nftables via netlink lib (drop `nft` shell-out);
  `systemd-resolved`-aware DNS backend; idempotent teardown/crash recovery.
- [ ] **2G WG-over-IPv6 transport** + control-plane v6 IP allocation.
- [ ] **2H Observability** — dashboards/alerting on `/metrics`; PSK/DAITA/onion counters.

### WAVE 3 — Clients & reach

- [ ] **3A Desktop GUI** — a graphical client (e.g. Tauri) over the agent Unix socket; the
  agent is already the privileged helper. Server browser, connect toggle, live stats.
- [ ] **3B Cross-platform data plane** — `net-macos` / `net-windows` siblings to `net-linux`
  (the trait split was designed for this); `wg-core` is already OS-agnostic.
- [ ] **3C Mobile** — expose `wg-core` as a library via UniFFI; integrate with
  iOS NetworkExtension / Android VpnService.
- [ ] **3D Split tunnelling** — per-app / per-destination routing policy.
- [ ] **3E "New identity"** — one action for ephemeral keys + exit rotation (per-session
  unlinkability).

### WAVE 4 — Advanced privacy / research bets

- [ ] **4A Adaptive DAITA** — maybenot-style learned/state-machine defenses; bidirectional +
  per-hop cover; constant-rate across the fleet toward a mix-net.
- [ ] **4B Continuous rekey / PSK rotation** — forward secrecy beyond WG defaults; rotate the
  PQ-derived PSK on a schedule.
- [ ] **4C Decentralized / community exits** — bring-your-own-exit with reputation; a
  federated relay marketplace.
- [ ] **4D Developer SDK** — embeddable ephemeral tunnels (the data plane as a library others
  build on).
- [ ] **4E Target mimicry** — shape a flow to look like a *specific* app (Zoom/Netflix), the
  far end of DAITA.

---

## Part 3 — Rough 6-month mapping

At agent pace, a "sprint" is hours, but calendar-anchored so progress is legible. Order is
the contract; dates are a guide.

- **Month 1 — Wave 1 moonshots I:** 1A DAITA, 2A transport selector (pulled early, it's
  small and makes DAITA usable), 1B undetectable server. *Milestone: censorship-resistance
  and traffic-analysis stories both closed and selectable.*
- **Month 2 — Wave 1 moonshots II:** 1C onion multihop (1C-1…1C-3). *Milestone: Tor-grade
  hop unlinkability at VPN speed.*
- **Month 3 — Wave 1 close + trust:** 1D verifiable no-logs (1D-1…1D-3). *Milestone:
  enforced + provable no-logs.*
- **Month 4 — Wave 2 scale:** 2B Postgres, 2C HA, 2D provisioning, 2E demux. *Milestone:
  multi-node fleet you can actually operate.*
- **Month 5 — Wave 2 finish + Wave 3 start:** 2F/2G/2H; 3A desktop GUI, 3B cross-platform
  data plane. *Milestone: a real client on >1 OS.*
- **Month 6 — Wave 3/4:** 3C mobile, 3D split tunnelling, 3E new-identity; begin 4A adaptive
  DAITA / 4B rekey. *Milestone: shippable multi-platform product with a research edge.*

Re-baseline at each milestone: update this file's checkboxes, the SKILL Changelog, and the
memory pointer.

---

## Part 4 — Open design forks (decide when you reach them, flag to the user)

1. **Onion crypto (Sprint 1C):** nested-WireGuard (reuses audited crypto, heavier) vs
   Tor-style ChaCha20-Poly1305 onion cells (lighter, new protocol from established
   primitives). Leaning (b) for wire efficiency *if* the protocol is kept minimal and
   reviewed; (a) if we want zero new protocol surface. **Ask the user before building.**
2. **Verifiable no-logs depth (Sprint 1D):** how far into hardware attestation (TPM/SGX)?
   v1 = seccomp + signed manifest + transparency log (all in-repo, testable). HW attestation
   needs real hardware/infra — **confirm appetite before 1D-4.**
3. **DAITA layer placement (Sprint 1A):** shaper as a `Transport` wrapper vs an engine-level
   queue. Pick whichever keeps the peer-generic engine and the `Transport` enum cleanest;
   prototype both interfaces briefly.
4. **DAITA + stealth requirement:** cover cells ride the obfs frame (need the shared key), so
   DAITA v1 implies stealth is on. Fine, but note it in the selector (2A).

---

## Part 5 — Standing risks / invariants (don't regress)

- **boringtun contracts:** call `update_timers` on a ticker; loop `decapsulate(None,…)` until
  `Done`. Never hold the `Tunn` `std::sync::Mutex` across `.await`.
- **MTU:** every new wrapping layer (obfs, mimic, DAITA padding, onion) *reduces* effective
  MTU — keep MSS clamping honest and document the per-feature overhead.
- **No-logs invariant:** the data plane writes nothing to disk; secrets never logged (the
  `SecretKey` type refuses to print). Any persistence lives only in the control plane.
- **Load-bearing architecture:** nothing should force a breaking change to the `wg-core`
  public API — the runtime-mutable peer table + `net-linux` syscall isolation + `Transport`
  enum are what keep options open. Onion/DAITA should extend, not rewrite, them.
- **Verify-without-root** stays the default; root-only paths are CI/netns-tested.

---

*Keep this file honest. When a sprint lands, check its box, add the SKILL Changelog entry,
and note any new fork or debt discovered. This is the map we navigate by after every context
reset.*

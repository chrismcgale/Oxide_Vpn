# Handoff — next work: smaller Wave-2/3 items

> **Purpose.** Pick up 5 self-contained items after a context clear: **2E** receiver-index
> demux, **2F** nft-via-netlink, **2G** WG-over-IPv6, **3D** split tunnelling, **3E** "new
> identity". All are solo + verifiable without root (pure/loopback tests; live paths get a
> netns script). Written 2026-07-23 on branch `rearchitect-wireguard`.

> **Live status (2026-07-23):** 2E/3D/3E done **and live-verified under root** (netns).
> `netns-{classic,split,fulltunnel,reconnect,newidentity}-test.sh` all PASS. The live run
> caught a real bug (netlink errors were flattened to `ErrorKind::Other`, breaking 3D's
> tolerate-`AlreadyExists`) — fixed. Next: **2G (WG-over-IPv6)**, then 2F.

## Where things stand (read these first)
- **`PLAN.md`** — forward plan + checkboxes (source of truth for what's done/next).
- **`.claude/skills/oxide-vpn/SKILL.md`** — Run · Debug · Architecture · Gotchas · Changelog
  (newest first). Read the Architecture + the last ~15 Changelog entries.
- Auto-memory index: `~/.claude/projects/-home-archriso-github-Oxide-Vpn/memory/MEMORY.md`.
- **State:** 111 tests green, clippy `-D` + fmt clean, live Postgres green, live DNS (resolvectl)
  green. The **classic VPN is verified end-to-end** on a real kernel (netns harnesses:
  `scripts/netns-{classic,fulltunnel,reconnect}-test.sh`, `scripts/resolvectl-check.sh`).
  Wave-1 moonshots done (DAITA, decoy, PQ, mesh, verifiable no-logs); **1C onion is PARKED**
  (do not start it). 2A/2A-2/2B/2C/2D done.

## How to work (definition of done — every increment)
1. `cargo clippy --workspace --all-targets -- -D warnings` — **zero** warnings.
2. `cargo test --workspace` green; new behavior gets tests, verified **without root** (pure
   builders + loopback + in-process control plane). Root-only paths get a netns script.
3. `cargo fmt --all`.
4. Update docs in the **same** change: SKILL Changelog (newest first) + PLAN checkbox + this
   file's checklist; update the memory pointer when architecture shifts.
5. One cohesive commit per item; trailer `Co-Authored-By: Claude Opus 4.8 (1M context)
   <noreply@anthropic.com>`. Push only when the user asks.
- Toolchain: `. "$HOME/.cargo/env"` first. **No passwordless sudo here** — I can't run the
  netns/root scripts myself; write them carefully and have the user run them (that live pass
  caught 3 real bugs unit tests missed, so it's worth it).
- Live Postgres: `OXIDE_TEST_PG_URL='postgres:///oxide_cp?host=/run/postgresql' cargo test -p
  oxide-control-plane --test postgres`.
- **Invariants (don't regress):** never hold the boringtun `Tunn` `std::sync::Mutex` across
  `.await`; `Engine::run`'s spawned tasks must be registered with its `AbortGuard`;
  `outbound_loop` drops-and-continues on a send error (never propagate); `wg-core` knows
  nothing about config/control-plane; data plane writes nothing to disk; verify-without-root
  is the default. **Read a crate's real API from source before writing against it.**

---

## 2E — Receiver-index peer demux ✅ DONE (2026-07-23)
Implemented exactly as designed below: `parse_recv_index` (pure, type-4-only, length-guarded)
+ `Shared.recv_index_to_peer` cache, resolution order index→addr→scan, pruned on `remove_peer`.
Verified with parse unit tests + a 40-decoy integration test asserting ~1 probe/packet
(`decap_probes` counter / `EngineHandle::decap_probes`). 115 tests. See SKILL changelog.

**Goal.** Replace the O(peers) inbound demux with a direct index lookup so a busy server
doesn't try every peer per datagram.

**Where.** `crates/wg-core/src/engine.rs`:
- `Shared.addr_to_peer: Mutex<HashMap<SocketAddr, PeerId>>` (line ~85) — the current cache.
- `handle_incoming` (line ~426): looks up `addr_to_peer` for `src`, else falls back to
  `table.snapshot()` and tries **every** peer's `decapsulate` until one succeeds.

**Approach (no boringtun API needed).** A WireGuard **data** message (type 4) carries, at
bytes `[4..8)` (LE u32), the **receiver index** = the index *we* assigned to that peer's
session. We can **learn** `index -> PeerId` the first time a datagram from that index
decapsulates successfully (same pattern as the addr cache, but keyed by our index — and it
survives roaming, unlike the source address). Add `recv_index_to_peer: Mutex<HashMap<u32,
PeerId>>` to `Shared`; in `handle_incoming`, if the datagram's first byte is `4` (data),
read the receiver index and try that peer first; on any successful decapsulation cache
`index -> id`. Keep the addr cache + full fallback for handshake messages (types 1/2/3,
which don't carry our index) and cache misses. Prune the index map in `remove_peer`.

**Gotchas.** Only data messages carry our receiver index; handshakes still need the fallback.
Validate the datagram length before slicing. The index is LE. Don't change the peer table API.

**Acceptance.** Unit test (loopback, `test-util`): with N peers, a data packet from a known
index routes without scanning all peers (assert via a counter or by constructing a case the
addr cache can't resolve — e.g. a roamed source — that the index still resolves). The
existing `tunnel` capstones must stay green.

---

## 2F — nftables via netlink (drop the `nft` shell-out)
**Goal.** Build the NAT + kill-switch rulesets over netlink instead of shelling out to `nft`.

**Where.** `crates/net-linux/src/`:
- `cmd.rs::{run, apply_nft_ruleset}` — the shell-out helpers.
- `nat.rs` — `enable_masquerade`/`disable_masquerade` (builds a text ruleset, `apply_nft_ruleset`).
- `killswitch.rs` — `enable`/`disable`/`build_ruleset` (text ruleset). **Note:** `build_ruleset`
  is pure + unit-tested — keep an equivalent pure "describe the rules" layer so tests survive.

**Approach.** Add a netlink nftables crate — evaluate **`rustables`** (higher-level, safe) vs
**`nftnl`** (thin libnftnl bindings; needs the C lib). **Read its real API from source first.**
Reimplement `enable_masquerade` / kill-switch `enable` as netlink table/chain/rule builders;
keep `disable` idempotent. Preserve the dedicated tables (`oxide`, `oxide-ks`) so teardown
stays surgical and the host's rules are untouched.

**Gotchas.** The masquerade rule also does **MSS clamping** (`tcp flags syn … maxseg size set
rt mtu`) — don't drop that (it fixes the "ping works, curl hangs" PMTU black hole). Root-only
to apply; keep the rule *construction* pure and unit-tested. `nft`-via-netlink is a real dep +
API-learning task — flag to the user if it balloons.

**Acceptance.** Pure unit tests for rule construction (as today). Live: extend a netns script
(reuse `netns-fulltunnel-test.sh`'s NAT path) to confirm masquerade + kill switch still work
over netlink. Decision to flag: `rustables` vs `nftnl` (C dep).

---

## 2G — WG-over-IPv6 transport (+ control-plane v6)
**Goal.** Let the WireGuard transport bind/serve over IPv6 and clients dial v6 endpoints
(today the *underlay* transport is IPv4-only; IPv6 **inside** the tunnel already works).

**Where.**
- Server bind: `crates/oxide-serverd/src/main.rs::build_server_transport` (`UdpSocket::bind
  (("0.0.0.0", listen_port))`, line ~471). Client bind: `crates/client-core/src/lib.rs`
  (`bind(("0.0.0.0", bind_port))`, ~333).
- `Transport` (wg-core `transport.rs`) already takes a `UdpSocket`; `SocketAddr` already
  parses v6, so endpoints are fine — the **bind** is the change.

**Approach.** Bind dual-stack: bind `::` with `IPV6_V6ONLY=false` (via `socket2` — check if
it's already a dep; else add) so one socket serves v4+v6; or pick the family from config.
Simplest v1: server binds `[::]:port` dual-stack; client binds `[::]:0`. Control plane:
`ServerInfo.endpoint`/`add-server --endpoint` already strings — verify v6 `host:port` (bracketed)
round-trips through `host_of` and registration; add v6 tunnel-IP allocation only if you also
want v6 *assigned* addresses (optional — inside-tunnel v6 already works via static config).

**Gotchas.** `host_of` (control-plane lib.rs) splits on the last `:` and trims `[]` — verify it
handles `[2001:db8::1]:51820`. The `full_tunnel` route pin in `client-core::run_tunnel` uses
`set_default_v6_via_dev` already; the endpoint-pin path must handle a v6 endpoint (`default_route`
+ `add_host_route_via` for v6). Dual-stack sockets can be surprising in netns.

**Acceptance.** Loopback unit test: a tunnel handshake over a v6 UDP socket (mirror
`wg-core/tests/tunnel.rs`, bind `[::1]`). Live: a v6 variant of the netns test. Decision:
dual-stack single socket vs per-family — flag if config surface grows.

---

## 3D — Split tunnelling (per-destination) ✅ DONE (2026-07-23)
Implemented as designed below: `[interface] split_include`/`split_exclude`, a pure
`client-core::split::plan_routes` builder (per-family full/include/exclude), include CIDRs
routed via oxide0 (removes the manual `ip route add`), exclude CIDRs pinned via the original
gateway, KS refused with `split_exclude`, teardown tracks + removes every added route. Tests:
6 pure builder cases + config round-trip; live `scripts/netns-split-test.sh` (FIB assertions)
and `netns-classic-test.sh` now asserts the auto-include. 122 tests. See SKILL changelog.


**Goal.** Route only chosen CIDRs through the tunnel (include list) — or everything **except**
chosen CIDRs (exclude list) — instead of only full-tunnel or the interface subnet.

**Where.** `crates/client-core/src/lib.rs::run_tunnel` (routing block ~388–420). Today it only
handles the **full-tunnel** case (`0.0.0.0/0` peer → swing default via `set_default_v4_via_dev`).
Specific non-default `allowed_ips` CIDRs are **not** given OS routes (I had to `ip route add …
dev oxide0` by hand in `netns-classic-test.sh` — that manual step is exactly what 3D removes).

**Approach.** For a peer whose `allowed_ips` are specific CIDRs (not `0.0.0.0/0`), install a
route per CIDR via `oxide0` (`Netlink::add_route_dev` exists). For **exclude** (route *around*
the tunnel): full-tunnel + pin the excluded CIDRs via the original default gateway (like the
server-endpoint pin). Add config: `[interface] split_include = ["…"]` / `split_exclude = ["…"]`,
or derive include from the peer's non-default `allowed_ips`. Per-**app** split (cgroup/fwmark)
is a separate, bigger v2 — keep 3D to per-destination.

**Gotchas.** Kill switch assumes full-tunnel (`--kill-switch` requires a `0.0.0.0/0` peer) —
either disallow KS with split-include or adapt the KS permit set. Teardown must remove every
route it added (track them like the endpoint pin). Compose with the reconnect teardown.

**Acceptance.** Pure test for the route-plan builder (given allowed_ips/include/exclude → the
set of routes to add). Live: a netns test asserting an included CIDR goes via the tunnel and an
excluded one goes via the underlay.

---

## 3E — "New identity" (ephemeral keys + exit rotation) ✅ DONE (2026-07-23)
Implemented as designed below: `rotate_device_key` (atomic, 0600) + `rotate_identity`
(pure-ish, unit-tested), a new-identity generation `watch::<u64>` threaded into
`run_supervised` (teardown on stop OR new-identity, disambiguated after), `ConnEvent::NewIdentity`,
`AgentRequest::NewIdentity` (agent bumps the counter) → TUI `n` keybind, and CLI `connect`
rotates on **SIGUSR1**. Mesh keeps its key (scoped to exit connections). Live:
`scripts/netns-newidentity-test.sh`. 124 tests. See SKILL changelog.


**Goal.** One action → fresh device key + reconnect to a **different** exit, for per-session
unlinkability (Tor-style "new circuit").

**Where.** `crates/client-core/src/lib.rs` — `load_or_create_key` (device key file),
`resolve_connection` (registers `device_pub` on a server), `ConnectRequest.exclude` (already
used by reconnect to avoid a server), `run_supervised`. Agent: `oxide-agentd` `AgentRequest`
(`common::agent`) + `oxide-client`/`oxide-tui`.

**Approach.** A `new_identity` flow that: (1) generates a **fresh** device key (rotate the key
file — back up/replace), (2) re-resolves with the current server added to `exclude` (so it
picks a different exit) and a new device registration, (3) reconnects. In the always-on agent,
expose an `AgentRequest::NewIdentity` that swaps the running supervised connection to the new
identity (signal the current `run_supervised` to stop, start a fresh one with a new key +
exclude). CLI: `oxide-client new-identity` / TUI keybind.

**Gotchas.** The old device row lingers in the control plane (new key = new device) — fine
(no cross-linking is the point); optionally add a device-deregister endpoint later. Key file
rotation must be atomic (write new, then replace) and 0600. The mesh uses the same device key
— decide whether "new identity" also re-keys the mesh (probably scope to exit connections).

**Acceptance.** Pure test: `new_identity` produces a different device pubkey and an
`exclude`-set containing the prior server. Live: reuse the reconnect netns harness to show it
reconnects to a *different* ghost/exit after the action.

---

## Suggested order
~~2E (contained, wg-core-only)~~ **✅ done** → ~~3D~~ **✅ done** → ~~3E (builds on `exclude`/reconnect)~~ **✅ done** → **2G next** (dual-stack) → 2F (biggest: new dep + API learning)
(builds on `exclude`/reconnect) → 2G (dual-stack) → 2F (biggest: new dep + API learning; do
last or when the user okays the dependency). Reassess after each.

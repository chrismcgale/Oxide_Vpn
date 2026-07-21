# Oxide VPN — Roadmap

The strategic leverage: **we own the whole stack** — the data-plane engine (`wg-core`),
the control plane, and the relay layer. That lets us build things a commodity-WireGuard
service can't touch.

## Done

- **M1** — Real WireGuard tunnel (boringtun): TUN device, handshake, allowed-IPs routing, full-tunnel NAT. Interoperable with stock `wg`.
- **M2** — Control plane: anonymous account numbers (no PII), device registration + tunnel-IP allocation, live peer reconcile into a running server.
- **M3** — Multi-server selection + load balancing: servers advertise location/capacity and heartbeat live load; `best` endpoint + client auto-select.
- **M4** — Privacy / leak prevention: kill switch (nft output-drop), DNS leak protection, no-logs/RAM-only posture (audited).
- **Multihop** — WireGuard-native (entry relays ciphertext to exit); no single server sees both ends. Client engine unchanged.

---

## Signature bets (cool & unique)

Ranked by differentiation × real-world impact. All leverage owning the stack.

1. **Stealth mode / censorship resistance.** — *tier 1 DONE:* `obfs` (ChaCha20 keystream)
   + `Transport::Obfuscated`, distributed via the control plane. *tier 2 DONE:* `mimicry`
   crate — **TLS-over-TCP** (`Transport::Mimic`, looks like HTTPS) and **QUIC-over-UDP**
   (`Transport::QuicMimic`, looks like HTTP/3, UDP-native — the preferred mode). *Next:*
   config/CP transport selector so daemons choose the stealth transport; mimicry in the
   `relay`; a full QUIC state-machine emulator to beat *active* probing.
2. **Traffic-analysis defense (DAITA-style).** — *size dimension DONE:* obfs pads every
   datagram up to size buckets, so packet sizes normalize into an anonymity set. *Next:*
   constant-rate cover traffic + timing normalization in `wg-core`, so even the multihop
   entry sees only shaped volume.
3. **Post-quantum handshake.** — *DONE:* `pq` crate (ML-KEM-768); the KEM shared secret
   feeds the WireGuard PSK (hybrid X25519 + ML-KEM), negotiated through the control plane
   for both single-hop and **multihop** (keyed to the exit). Three capstone tunnels prove
   it (single, CP-negotiated, multihop+relay+PQ). *Next:* PSK rotation.
4. **Personal-mesh + privacy hybrid.** — *DONE:* control-plane-coordinated WireGuard P2P
   overlay of the account's own devices — `mesh_devices` + `POST /v1/mesh/register` (stable
   `/32` in `100.64.0.0/16`, account-scoped peer list), `client-core::resolve_mesh`,
   `oxide-client mesh`; capstone `mesh_flow` proves two devices talk directly (no server).
   The mesh carries only its `/16`, so it composes with a full-tunnel `connect` for
   anonymous egress: Tailscale-style device overlay *plus* anonymous exits — "Tailscale
   that's actually private." *Next:* NAT traversal (STUN-style hole punching + a DERP-style
   relay fallback) so devices behind NAT mesh without a forwarded port.

**Secondary:** verifiable no-logs (remote attestation / reproducible builds / transparency
log); policy split-tunneling (per-app/per-destination routing); developer API/SDK
(embeddable ephemeral tunnels); "new identity" button (per-session ephemeral keys + exit
rotation).

---

## Productization (make it an actual product)

### Core correctness/robustness
- Verify the **live-kernel path** on real hardware across distros (CI can run `scripts/netns-test.sh` as root).
- **IPv6** end-to-end; **MSS clamping / PMTU** handling.
- Proper **receiver-index peer demux** (replace the O(peers) fallback) for busy servers.
- Migrate **`net-linux` off shell-outs** to real netlink (rtnetlink) + nftables libraries.
- Graceful shutdown, crash recovery, idempotent teardown.

### Scale & ops
- **Postgres** for the control plane (already designed for). Server **provisioning
  automation**. **Observability** — *`/metrics` DONE* (Prometheus text: account/server/
  device totals + per-server load); dashboards/alerting next. **HA** (control-plane
  redundancy, DB replication, client re-selection on server death). Token rotation;
  zero-downtime, versioned-API deploys.

### Security hardening
- **Auth rate-limiting** (account number = bearer with no brute-force protection today).
- **DoS protection**: wire boringtun's `RateLimiter` (currently `None`).
- Privilege-drop the data plane to `CAP_NET_ADMIN` + GUI/helper split.
- Request size/timeout limits; `cargo-audit`/`cargo-deny`/SBOM; crypto-integration review;
  anti-abuse on device registration (subnet exhaustion).

### Product surface
- *DONE:* **terminal UI** (`oxide-tui`) + **privileged agent** (`oxide-agentd`) with a
  Unix-socket control API — the unprivileged-UI/privileged-helper split.
- **Cross-platform clients** (macOS/Windows, iOS/Android network extensions) — the payoff
  of `wg-core` being OS-agnostic. Desktop tray/GUI (Tauri) over the same agent socket,
  auto-connect, trusted networks. Anonymous payment (cash/crypto).

### Quality / CI
- **CI pipeline** (build + test + clippy + fmt + audit) — biggest credibility jump.
- Interop matrix vs stock WireGuard; **fuzz the packet parser**; soak/load tests.

---

## Current focus

**Hardening pass** (a cool feature on a fragile base isn't a product):

- [x] CI pipeline (fmt/clippy/test + cargo-deny + privileged netns live-path job)
- [x] Auth rate-limiting (per-IP) + request body/timeout limits
- [x] DoS defense (boringtun `RateLimiter` on the server engine)
- [x] Migrate `net-linux` link/addr/route to real **netlink** (rtnetlink). (nftables still
      shells out to `nft`; the one default-route *read* still uses `ip route show`.)
- [x] **IPv6 inside the tunnel**: dual-stack addresses (`address6`) + `::/0` routing.
      Remaining: WG-over-IPv6 *transport*, control-plane v6 IP allocation.
- [x] MSS clamping (NAT forward chain) + graceful `SIGTERM` shutdown.

Then the first signature bet: **stealth mode** (censorship resistance in the relay).

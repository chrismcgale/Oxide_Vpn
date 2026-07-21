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

1. **Stealth mode / censorship resistance.** Make WG traffic look like HTTPS/QUIC so DPI
   (China/Iran/Russia) can't detect-and-block it. Lives in the `relay` layer: the entry
   speaks an obfuscated transport (Shadowsocks-style / obfs4 / WG-in-QUIC). Biggest
   real-world impact.
2. **Traffic-analysis defense (DAITA-style).** Padding, constant-rate cover traffic, and
   timing normalization in `wg-core` to defeat ML traffic fingerprinting — so even the
   multihop entry sees only shaped volume. Cutting-edge.
3. **Post-quantum handshake.** Hybrid X25519 + ML-KEM (Kyber); control plane distributes
   rotating PQ-derived PSKs. Forward-looking; we already own key distribution.
4. **Personal-mesh + privacy hybrid.** Tailscale-style device overlay *plus* anonymous
   exits. The positioning nobody owns: "Tailscale that's actually private."

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
  automation**. **Observability** (Prometheus metrics, dashboards, alerting). **HA**
  (control-plane redundancy, DB replication, client re-selection on server death).
  Token rotation; zero-downtime, versioned-API deploys.

### Security hardening
- **Auth rate-limiting** (account number = bearer with no brute-force protection today).
- **DoS protection**: wire boringtun's `RateLimiter` (currently `None`).
- Privilege-drop the data plane to `CAP_NET_ADMIN` + GUI/helper split.
- Request size/timeout limits; `cargo-audit`/`cargo-deny`/SBOM; crypto-integration review;
  anti-abuse on device registration (subnet exhaustion).

### Product surface
- **Cross-platform clients** (macOS/Windows, iOS/Android network extensions) — the payoff
  of `wg-core` being OS-agnostic. GUI/tray, auto-connect, trusted networks. Anonymous
  payment (cash/crypto).

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
      Remaining: WG-over-IPv6 *transport*, control-plane v6 IP allocation, MSS clamping.

Then the first signature bet: **stealth mode** (censorship resistance in the relay).

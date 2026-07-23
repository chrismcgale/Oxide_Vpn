#!/usr/bin/env bash
# Classic-VPN live verification, part 2: FULL TUNNEL + KILL SWITCH.
#
# Proves the two properties a real VPN must have:
#   1. Full tunnel — the client swings its DEFAULT route into the tunnel, so *all* traffic
#      exits via the server (source IP masqueraded → the internet sees the server, not you).
#   2. Kill switch — while connected, non-tunnel egress is BLOCKED, so nothing can leak out
#      the underlay if the tunnel drops.
#
# Topology (three namespaces). The server carries TWO underlay IPs so the client's default
# gateway (10.50.0.1) differs from the WireGuard endpoint (10.50.0.3) — exactly like a real
# LAN router vs a remote server, which is what full-tunnel route-pinning expects:
#
#   oxide-cli --10.50.0.0/24-- oxide-srv --10.60.0.0/24-- oxide-net
#     .2         gw .1 / wg .3   (NAT out veth-sn)          .2  "the internet"
#
# Requires root.  Run:  sudo bash scripts/netns-fulltunnel-test.sh
set -euo pipefail

CLI=oxide-cli
SRV=oxide-srv
NET=oxide-net
DIR=$(mktemp -d)
BIN=target/debug
SRV_EGRESS=10.60.0.1

cleanup() {
    set +e
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
    [ -n "${CLI_PID:-}" ] && kill "$CLI_PID" 2>/dev/null
    [ -n "${ECHO_PID:-}" ] && kill "$ECHO_PID" 2>/dev/null
    ip netns del "$CLI" 2>/dev/null
    ip netns del "$SRV" 2>/dev/null
    ip netns del "$NET" 2>/dev/null
    rm -rf "$DIR"
}
trap cleanup EXIT

if [ -z "${OXIDE_SKIP_BUILD:-}" ]; then
    echo "== building =="
    ( . "$HOME/.cargo/env" 2>/dev/null; cargo build -p oxide-serverd -p oxide-client )
fi
SERVERD="$PWD/$BIN/oxide-serverd"
CLIENT="$PWD/$BIN/oxide-client"

echo "== keys =="
SPRIV=$("$SERVERD" genkey); SPUB=$(echo "$SPRIV" | "$SERVERD" pubkey)
CPRIV=$("$CLIENT"  genkey); CPUB=$(echo "$CPRIV" | "$CLIENT"  pubkey)

cat > "$DIR/server.toml" <<EOF
[interface]
private_key = "$SPRIV"
address = "10.8.0.1/24"
listen_port = 51820
[nat]
egress = "veth-sn"
[[peer]]
public_key = "$CPUB"
allowed_ips = ["10.8.0.2/32"]
EOF

# Full tunnel: 0.0.0.0/0. No dns field (a namespace shares the host's /etc/resolv.conf, so we
# deliberately don't touch DNS here — the DNS backend is covered separately).
cat > "$DIR/client.toml" <<EOF
[interface]
private_key = "$CPRIV"
address = "10.8.0.2/24"
[[peer]]
public_key = "$SPUB"
endpoint = "10.50.0.3:51820"
allowed_ips = ["0.0.0.0/0"]
persistent_keepalive = 25
EOF

echo "== namespaces + veths =="
for ns in "$CLI" "$SRV" "$NET"; do ip netns del "$ns" 2>/dev/null || true; done
ip netns add "$CLI"; ip netns add "$SRV"; ip netns add "$NET"
ip link add veth-cs netns "$CLI" type veth peer name veth-sc netns "$SRV"
ip -n "$CLI" addr add 10.50.0.2/24 dev veth-cs
# Add the WireGuard endpoint FIRST so it's the interface's *primary* address — the server
# then replies to the client from .3 (its endpoint), so WireGuard endpoint-learning stays
# consistent with the configured endpoint and the kill switch. .1 is a secondary address
# acting as the client's "LAN router" (default gateway), distinct from the endpoint.
ip -n "$SRV" addr add 10.50.0.3/24 dev veth-sc   # WireGuard endpoint (primary)
ip -n "$SRV" addr add 10.50.0.1/24 dev veth-sc   # client's default gateway (secondary)
ip link add veth-sn netns "$SRV" type veth peer name veth-ns netns "$NET"
ip -n "$SRV" addr add 10.60.0.1/24 dev veth-sn
ip -n "$NET" addr add 10.60.0.2/24 dev veth-ns
for ns in "$CLI" "$SRV" "$NET"; do ip -n "$ns" link set lo up; done
ip -n "$CLI" link set veth-cs up
ip -n "$SRV" link set veth-sc up
ip -n "$SRV" link set veth-sn up
ip -n "$NET" link set veth-ns up
# The client needs a default route to pin the endpoint against (like a real host's LAN gw).
ip -n "$CLI" route add default via 10.50.0.1

echo "== 'internet' host echoing the caller's source IP =="
ip netns exec "$NET" python3 -c '
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
        self.wfile.write(self.client_address[0].encode())
    def log_message(self, *a): pass
socketserver.TCPServer(("0.0.0.0", 9000), H).serve_forever()
' >"$DIR/echo.log" 2>&1 &
ECHO_PID=$!

echo "== start server, then client with --kill-switch (full tunnel) =="
ip netns exec "$SRV" env RUST_LOG=info "$SERVERD" up --config "$DIR/server.toml" >"$DIR/srv.log" 2>&1 &
SRV_PID=$!
sleep 1
ip netns exec "$CLI" env RUST_LOG=info "$CLIENT" up --config "$DIR/client.toml" --kill-switch >"$DIR/cli.log" 2>&1 &
CLI_PID=$!

echo "== wait for handshake + route swing =="
sleep 4

RC=0
echo "== the client's routes now send everything into the tunnel =="
# Full tunnel is the wg-quick way: 0.0.0.0/1 + 128.0.0.0/1 via the tunnel override the
# default (0.0.0.0/0) without deleting it, so the pinned server endpoint stays reachable.
ROUTES=$(ip netns exec "$CLI" ip route)
echo "$ROUTES" | grep -E "oxide0|default" | sed 's/^/  /'
if echo "$ROUTES" | grep -q "0.0.0.0/1 dev oxide0"; then
    echo "  full tunnel: PASS ✓  (0.0.0.0/1 + 128.0.0.0/1 override the default via oxide0)"
else
    echo "  full tunnel: FAIL ✗"
    RC=1
fi

echo "== exit IP: curl the internet through the (default) tunnel =="
SEEN=""
for _ in 1 2 3; do
    SEEN=$(ip netns exec "$CLI" curl -s --max-time 4 http://10.60.0.2:9000 || true)
    [ -n "$SEEN" ] && break; sleep 1
done
echo "  internet saw source IP: '${SEEN:-<none>}'   (expected the server's egress $SRV_EGRESS)"
if [ "$SEEN" = "$SRV_EGRESS" ]; then echo "  exit IP hidden: PASS ✓"; else echo "  exit IP hidden: FAIL ✗"; RC=1; fi

echo "== kill switch: non-tunnel egress must be BLOCKED (no leak) =="
# Pinging the underlay gateway directly (not via the tunnel, not the WG endpoint port) must
# be dropped by the kill switch. Without it, this directly-connected ping would succeed.
if ip netns exec "$CLI" ping -c 1 -W 2 10.50.0.1 >/dev/null 2>&1; then
    echo "  underlay ping SUCCEEDED — kill switch is NOT blocking: FAIL ✗"
    RC=1
else
    echo "  underlay ping blocked: PASS ✓  (nothing leaks outside the tunnel)"
fi
echo "  kill-switch nft table:"
ip netns exec "$CLI" nft list table inet oxide-ks 2>/dev/null | grep -E "chain|policy|drop|accept" | sed 's/^/    /' || echo "    (table not found)"

if [ $RC -ne 0 ]; then
    echo "== server log =="; cat "$DIR/srv.log"
    echo "== client log =="; cat "$DIR/cli.log"
    echo "== cli routes =="; ip netns exec "$CLI" ip route
fi

echo
if [ $RC -eq 0 ]; then
    echo "RESULT: PASS ✓  full tunnel routes everything via the server, and the kill switch blocks leaks."
else
    echo "RESULT: FAIL ✗  (see logs above)"
fi
exit $RC

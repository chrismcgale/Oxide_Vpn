#!/usr/bin/env bash
# Classic-VPN live verification: prove the exit IP is hidden (NAT masquerade), end to end.
#
# Topology — three network namespaces on one host:
#
#   oxide-cli --10.50.0.0/24-- oxide-srv --10.60.0.0/24-- oxide-net
#      .2                       .1    .1                    .2
#   client tunnel 10.8.0.2      server tunnel 10.8.0.1              "the internet"
#                               + NAT masquerade out veth-sn
#
# The client sends traffic to oxide-net THROUGH the tunnel; the server NATs it, so oxide-net
# sees the *server's* egress IP (10.60.0.1), not the client's. That is the classic VPN
# property: your real address is replaced by the exit server's.
#
# Requires root (CAP_NET_ADMIN).  Run:  sudo bash scripts/netns-classic-test.sh
set -euo pipefail

CLI=oxide-cli
SRV=oxide-srv
NET=oxide-net
DIR=$(mktemp -d)
BIN=target/debug
SRV_EGRESS=10.60.0.1 # what oxide-net should see as the source (server's veth-sn IP)

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

# Server: terminates the tunnel and NATs tunnel traffic out toward "the internet" (veth-sn).
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

# Client: routes the tunnel subnet AND the "internet" subnet through the tunnel.
cat > "$DIR/client.toml" <<EOF
[interface]
private_key = "$CPRIV"
address = "10.8.0.2/24"
[[peer]]
public_key = "$SPUB"
endpoint = "10.50.0.1:51820"
allowed_ips = ["10.8.0.0/24", "10.60.0.0/24"]
persistent_keepalive = 25
EOF

echo "== namespaces + veths =="
# Clean up any leftovers from a previous aborted run.
for ns in "$CLI" "$SRV" "$NET"; do ip netns del "$ns" 2>/dev/null || true; done
ip netns add "$CLI"; ip netns add "$SRV"; ip netns add "$NET"
# client <-> server underlay
ip link add veth-cs netns "$CLI" type veth peer name veth-sc netns "$SRV"
ip -n "$CLI" addr add 10.50.0.2/24 dev veth-cs
ip -n "$SRV" addr add 10.50.0.1/24 dev veth-sc
# server <-> "internet"
ip link add veth-sn netns "$SRV" type veth peer name veth-ns netns "$NET"
ip -n "$SRV" addr add 10.60.0.1/24 dev veth-sn
ip -n "$NET" addr add 10.60.0.2/24 dev veth-ns
for ns in "$CLI" "$SRV" "$NET"; do ip -n "$ns" link set lo up; done
ip -n "$CLI" link set veth-cs up
ip -n "$SRV" link set veth-sc up
ip -n "$SRV" link set veth-sn up
ip -n "$NET" link set veth-ns up

echo "== 'internet' host on oxide-net: an HTTP server that echoes the caller's source IP =="
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

echo "== start daemons =="
ip netns exec "$SRV" env RUST_LOG=info "$SERVERD" up --config "$DIR/server.toml" >"$DIR/srv.log" 2>&1 &
SRV_PID=$!
ip netns exec "$CLI" env RUST_LOG=info "$CLIENT" up --config "$DIR/client.toml" >"$DIR/cli.log" 2>&1 &
CLI_PID=$!

echo "== wait for handshake, then route the 'internet' subnet into the tunnel =="
sleep 4
# client-core auto-routes only the full-tunnel (0.0.0.0/0) case; add the test subnet route
# so the client sends 10.60.0.0/24 into oxide0 (the engine cryptokey-routes it to the server).
ip netns exec "$CLI" ip route add 10.60.0.0/24 dev oxide0 2>/dev/null || true
sleep 1

RC=0
echo "== baseline: ping the server's tunnel IP through the tunnel =="
if ip netns exec "$CLI" ping -c 2 -W 2 10.8.0.1 >/dev/null 2>&1; then
    echo "  tunnel: PASS ✓"
else
    echo "  tunnel: FAIL ✗"
    RC=1
fi

echo "== exit IP: curl the internet host THROUGH the tunnel =="
SEEN=""
for _ in 1 2 3; do
    SEEN=$(ip netns exec "$CLI" curl -s --max-time 4 http://10.60.0.2:9000 || true)
    [ -n "$SEEN" ] && break
    sleep 1
done
echo "  oxide-net saw source IP: '${SEEN:-<none>}'   (expected the server's egress $SRV_EGRESS)"
if [ "$SEEN" = "$SRV_EGRESS" ]; then
    echo "  exit IP hidden: PASS ✓  (client's real address replaced by the exit server's)"
else
    echo "  exit IP hidden: FAIL ✗"
    RC=1
fi

if [ $RC -ne 0 ]; then
    echo "== server log =="; cat "$DIR/srv.log"
    echo "== client log =="; cat "$DIR/cli.log"
    echo "== srv namespace routes/nft =="
    ip netns exec "$SRV" ip route; ip netns exec "$SRV" nft list ruleset 2>/dev/null | head -30
fi

echo
if [ $RC -eq 0 ]; then
    echo "RESULT: PASS ✓  classic full-exit path works — traffic exits via the server, source IP masqueraded."
else
    echo "RESULT: FAIL ✗  (see logs above)"
fi
exit $RC

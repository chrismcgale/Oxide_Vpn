#!/usr/bin/env bash
# 2G WG-over-IPv6 live verification: the WireGuard underlay runs over an IPv6 endpoint.
#
# Topology — two namespaces joined by ONE veth carrying only IPv6:
#
#   oxide-cli --fd00:50::/64-- oxide-srv
#      ::2                       ::1   (UDP :51820, dual-stack [::] bind)
#   client tunnel 10.8.0.2      server tunnel 10.8.0.1
#
# The client dials the server at a **v6 endpoint** ([fd00:50::1]:51820); the tunnel comes up
# and carries an inner **IPv4** ping (10.8.0.2 -> 10.8.0.1), proving the transport is agnostic
# to the underlay's address family and that the dual-stack bind serves v6 peers.
#
# Requires root.  Run:  sudo bash scripts/netns-ipv6-test.sh
set -euo pipefail

CLI=oxide-cli
SRV=oxide-srv
DIR=$(mktemp -d)
BIN=target/debug

cleanup() {
    set +e
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
    [ -n "${CLI_PID:-}" ] && kill "$CLI_PID" 2>/dev/null
    ip netns del "$CLI" 2>/dev/null
    ip netns del "$SRV" 2>/dev/null
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
[[peer]]
public_key = "$CPUB"
allowed_ips = ["10.8.0.2/32"]
EOF

# Client dials the server at its IPv6 endpoint.
cat > "$DIR/client.toml" <<EOF
[interface]
private_key = "$CPRIV"
address = "10.8.0.2/24"
[[peer]]
public_key = "$SPUB"
endpoint = "[fd00:50::1]:51820"
allowed_ips = ["10.8.0.0/24"]
persistent_keepalive = 25
EOF

echo "== namespaces + v6-only veth =="
for ns in "$CLI" "$SRV"; do ip netns del "$ns" 2>/dev/null || true; done
ip netns add "$CLI"; ip netns add "$SRV"
ip link add veth-cs netns "$CLI" type veth peer name veth-sc netns "$SRV"
for ns in "$CLI" "$SRV"; do ip -n "$ns" link set lo up; done
# Ensure IPv6 is enabled on the veths, then address them.
ip netns exec "$CLI" sysctl -qw net.ipv6.conf.veth-cs.disable_ipv6=0
ip netns exec "$SRV" sysctl -qw net.ipv6.conf.veth-sc.disable_ipv6=0
ip -n "$CLI" addr add fd00:50::2/64 dev veth-cs
ip -n "$SRV" addr add fd00:50::1/64 dev veth-sc
ip -n "$CLI" link set veth-cs up
ip -n "$SRV" link set veth-sc up
# Wait out IPv6 DAD so the addresses leave "tentative" before we bind/dial.
sleep 2

echo "== underlay reachability (v6) =="
if ip netns exec "$CLI" ping6 -c 2 -W 2 fd00:50::1 >/dev/null 2>&1; then
    echo "  v6 underlay: PASS ✓"
else
    echo "  v6 underlay: FAIL ✗ (veth/DAD problem, not the VPN)"; exit 1
fi

echo "== start daemons =="
ip netns exec "$SRV" env RUST_LOG=info "$SERVERD" up --config "$DIR/server.toml" >"$DIR/srv.log" 2>&1 &
SRV_PID=$!
ip netns exec "$CLI" env RUST_LOG=info "$CLIENT" up --config "$DIR/client.toml" >"$DIR/cli.log" 2>&1 &
CLI_PID=$!

echo "== wait for handshake over the v6 underlay =="
sleep 4

RC=0
echo "== inner IPv4 ping through the v6-underlay tunnel =="
if ip netns exec "$CLI" ping -c 3 -W 2 10.8.0.1 >/dev/null 2>&1; then
    echo "  tunnel over IPv6: PASS ✓  (inner v4 traffic rides a v6 WireGuard underlay)"
else
    echo "  tunnel over IPv6: FAIL ✗"
    RC=1
fi

if [ $RC -ne 0 ]; then
    echo "== server log =="; cat "$DIR/srv.log"
    echo "== client log =="; cat "$DIR/cli.log"
fi

echo
if [ $RC -eq 0 ]; then
    echo "RESULT: PASS ✓  WireGuard runs over an IPv6 endpoint (dual-stack bind + v6 endpoint dial)."
else
    echo "RESULT: FAIL ✗  (see logs above)"
fi
exit $RC

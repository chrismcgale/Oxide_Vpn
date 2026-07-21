#!/usr/bin/env bash
# End-to-end Milestone 1 test on a single host using two network namespaces.
#
# Topology:
#   ns "oxide-srv"  10.99.0.1/24  <--veth-->  10.99.0.2/24  ns "oxide-cli"
#   server tunnel 10.8.0.1/24 (udp :51820)     client tunnel 10.8.0.2/24
#
# Proves: real WireGuard handshake via boringtun, TUN devices, and bidirectional
# traffic across the encrypted tunnel (ping 10.8.0.1 from the client namespace).
#
# Requires root (CAP_NET_ADMIN). Run:  sudo bash scripts/netns-test.sh
set -euo pipefail

SRV=oxide-srv
CLI=oxide-cli
DIR=$(mktemp -d)
BIN_DIR="target/debug"

cleanup() {
    set +e
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
    [ -n "${CLI_PID:-}" ] && kill "$CLI_PID" 2>/dev/null
    ip netns del "$SRV" 2>/dev/null
    ip netns del "$CLI" 2>/dev/null
    rm -rf "$DIR"
}
trap cleanup EXIT

if [ -z "${OXIDE_SKIP_BUILD:-}" ]; then
    echo "== building =="
    ( . "$HOME/.cargo/env" 2>/dev/null; cargo build -p oxide-serverd -p oxide-client )
fi
SERVERD="$PWD/$BIN_DIR/oxide-serverd"
CLIENT="$PWD/$BIN_DIR/oxide-client"

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

cat > "$DIR/client.toml" <<EOF
[interface]
private_key = "$CPRIV"
address = "10.8.0.2/24"
[[peer]]
public_key = "$SPUB"
endpoint = "10.99.0.1:51820"
allowed_ips = ["10.8.0.0/24"]
persistent_keepalive = 25
EOF

echo "== namespaces + veth =="
ip netns add "$SRV"
ip netns add "$CLI"
ip link add veth-s netns "$SRV" type veth peer name veth-c netns "$CLI"
ip -n "$SRV" addr add 10.99.0.1/24 dev veth-s
ip -n "$CLI" addr add 10.99.0.2/24 dev veth-c
ip -n "$SRV" link set veth-s up
ip -n "$CLI" link set veth-c up
ip -n "$SRV" link set lo up
ip -n "$CLI" link set lo up

echo "== start daemons =="
ip netns exec "$SRV" env RUST_LOG=info "$SERVERD" up --config "$DIR/server.toml" >"$DIR/srv.log" 2>&1 &
SRV_PID=$!
ip netns exec "$CLI" env RUST_LOG=info "$CLIENT" up --config "$DIR/client.toml" >"$DIR/cli.log" 2>&1 &
CLI_PID=$!

echo "== waiting for handshake =="
sleep 3

echo "== ping across the tunnel (client -> server) =="
if ip netns exec "$CLI" ping -c 3 -W 2 10.8.0.1; then
    echo
    echo "RESULT: PASS ✓  tunnel carries traffic end-to-end"
    RC=0
else
    echo
    echo "RESULT: FAIL ✗  (see logs below)"
    RC=1
fi

echo "== server log =="; cat "$DIR/srv.log"
echo "== client log =="; cat "$DIR/cli.log"
exit $RC
